/*
 * Gatekeeper - DoS protection system.
 * Copyright (C) 2016 Digirati LTDA.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include <rte_ip.h>
#include <rte_log.h>
#include <rte_hash.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_memcpy.h>
#include <rte_cycles.h>
#include <rte_malloc.h>

#include "gatekeeper_gk.h"
#include "gatekeeper_main.h"
#include "gatekeeper_config.h"
#include "gatekeeper_launch.h"
#include "gatekeeper_lls.h"

#define	START_PRIORITY		 (38)
/* Set @START_ALLOWANCE as the double size of a large DNS reply. */
#define	START_ALLOWANCE		 (8)

/*
 * Priority used for DSCP field of encapsulated packets:
 *  0 for legacy packets; 1 for granted packets; 
 *  2 for capability renew; 3-63 for request packets.
 */
#define PRIORITY_GRANTED	 (1)
#define PRIORITY_RENEW_CAP	 (2)
#define PRIORITY_MAX		 (63)

/* XXX Sample parameters, need to be tested for better performance. */
#define GK_CMD_BURST_SIZE        (32)

/* Store information about a packet. */
struct ipacket {
	/* Flow identifier for this packet. */
	struct ip_flow  flow;
	/* Pointer to the packet itself. */
	struct rte_mbuf *pkt;
};

struct flow_entry {
	/* IP flow information. */
	struct ip_flow flow;

	/* The state of the entry. */
	enum gk_flow_state state;

	/*
	 * The fib entry that instructs where
	 * to send the packets for this flow entry.
	 */
	struct gk_fib *grantor_fib;

	union {
		struct {
			/* The time the last packet of the entry was seen. */
			uint64_t last_packet_seen_at;
			/* 
			 * The priority associated to
			 * the last packet of the entry.
			 */
			uint8_t last_priority;
			/* 
			 * The number of packets that the entry is allowed
			 * to send with @last_priority without waiting
			 * the amount of time necessary to be granted
			 * @last_priority.
			 */
			uint8_t allowance;
		} request;

		struct {
			/* When the granted capability expires. */
			uint64_t cap_expire_at;
			/* When @budget_byte is reset. */
			uint64_t budget_renew_at;
			/* 
			 * When @budget_byte is reset, reset it to
			 * @tx_rate_kb_cycle * 1024 bytes.
			 */
			int tx_rate_kb_cycle;
			/* How many bytes @src can still send in current cycle. */
			int budget_byte;
			/*
			 * When GK should send the next renewal to
			 * the corresponding grantor.
			 */
			uint64_t send_next_renewal_at;
			/*
			 * How many cycles (unit) GK must wait before
			 * sending the next capability renewal request.
			 */
			uint64_t renewal_step_cycle;
		} granted;

		struct {
			/*
			 * When the punishment (i.e. the declined capability)
			 * expires.
			 */
			uint64_t expire_at;
		} declined;
	} u;
};

/* We should avoid calling integer_log_base_2() with zero. */
static inline uint8_t
integer_log_base_2(uint64_t delta_time)
{
#if __WORDSIZE == 64
    return (8 * sizeof(uint64_t) - 1) - __builtin_clzl(delta_time);
#else
    return (8 * sizeof(uint64_t) - 1) - __builtin_clzll(delta_time);
#endif
}

/* 
 * It converts the difference of time between the current packet and 
 * the last seen packet into a given priority. 
 */
static uint8_t 
priority_from_delta_time(uint64_t present, uint64_t past)
{
	uint64_t delta_time;

	if (unlikely(present < past)) {
		/*
		 * This should never happen, but we handle it gracefully here 
		 * in order to keep going.
		 */
		RTE_LOG(ERR, GATEKEEPER,
			"gk: the present time smaller than the past time!\n");

		return 0;
	}

	delta_time = (present - past) * picosec_per_cycle;
	if (unlikely(delta_time < 1))
		return 0;
	
	return integer_log_base_2(delta_time);
}

static struct gk_fib *
look_up_fib(struct gk_lpm *ltbl, struct ip_flow *flow)
{
	int fib_id;

	if (flow->proto == ETHER_TYPE_IPv4) {
		fib_id = lpm_lookup_ipv4(ltbl->lpm, flow->f.v4.dst);
		if (fib_id < 0)
			return NULL;
		return &ltbl->fib_tbl[fib_id];
	}

	if (likely(flow->proto == ETHER_TYPE_IPv6)) {
		fib_id = lpm_lookup_ipv6(ltbl->lpm6, flow->f.v6.dst);
		if (fib_id < 0)
			return NULL;
		return &ltbl->fib_tbl6[fib_id];
	}

	rte_panic("Unexpected condition at %s: unknown flow type %hu\n",
		__func__, flow->proto);

	return NULL; /* Unreachable. */
}

static int
extract_packet_info(struct rte_mbuf *pkt, struct ipacket *packet)
{
	int ret = 0;
	uint16_t ether_type;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip4_hdr;
	struct ipv6_hdr *ip6_hdr;
	uint16_t pkt_len = rte_pktmbuf_data_len(pkt);

	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

	switch (ether_type) {
	case ETHER_TYPE_IPv4:
		if (pkt_len < sizeof(*eth_hdr) + sizeof(*ip4_hdr)) {
			packet->flow.proto = 0;
			RTE_LOG(NOTICE, GATEKEEPER,
				"gk: packet is too short to be IPv4 (%" PRIu16 ")!\n",
				pkt_len);
			ret = -1;
			goto out;
		}

		ip4_hdr = rte_pktmbuf_mtod_offset(pkt,
					struct ipv4_hdr *,
					sizeof(struct ether_hdr));
		packet->flow.proto = ETHER_TYPE_IPv4;
		packet->flow.f.v4.src = ip4_hdr->src_addr;
		packet->flow.f.v4.dst = ip4_hdr->dst_addr;
		break;

	case ETHER_TYPE_IPv6:
		if (pkt_len < sizeof(*eth_hdr) + sizeof(*ip6_hdr)) {
			packet->flow.proto = 0;
			RTE_LOG(NOTICE, GATEKEEPER,
				"gk: packet is too short to be IPv6 (%" PRIu16 ")!\n",
				pkt_len);
			ret = -1;
			goto out;
		}

		ip6_hdr = rte_pktmbuf_mtod_offset(pkt,
					struct ipv6_hdr *,
					sizeof(struct ether_hdr));
		packet->flow.proto = ETHER_TYPE_IPv6;
		rte_memcpy(packet->flow.f.v6.src, ip6_hdr->src_addr,
			sizeof(packet->flow.f.v6.src));
		rte_memcpy(packet->flow.f.v6.dst, ip6_hdr->dst_addr,
			sizeof(packet->flow.f.v6.dst));
		break;

	default:
		packet->flow.proto = 0;
		RTE_LOG(NOTICE, GATEKEEPER,
			"gk: unknown network layer protocol %" PRIu16 "!\n",
			ether_type);
		ret = -1;
		break;
	}
out:
	packet->pkt = pkt;
	return ret;
}

static inline void
initialize_flow_entry(struct flow_entry *fe,
	struct ip_flow *flow, struct gk_fib *grantor_fib)
{
	rte_memcpy(&fe->flow, flow, sizeof(*flow));

	fe->state = GK_REQUEST;
	fe->u.request.last_packet_seen_at = rte_rdtsc();
	fe->u.request.last_priority = START_PRIORITY;
	fe->u.request.allowance = START_ALLOWANCE - 1;

	/*
	 * TODO Flow entries should maintain the reference counter of
	 * the grantor FIB entry to avoid the entry to go away before the flow.
	 *
	 * Notice that all GK blocks are calling this function, so a solution
	 * needs to deal with concurrency.
	 *
	 * Moreover, the chose solution must be very efficient due to
	 * the impact on the throughout of the GK blocks. For example,
	 * a simple atomic counter will slow down all GK blocks;
	 * especially if there is only one grantor FIB entry.
	 *
	 * Ideas for solution: trade the need to maintain the reference counter
	 * of the grantor FIB entry for some expensive operation that is only
	 * needed while editing the FIB table.
	 */
	fe->grantor_fib = grantor_fib;
	grantor_fib->ref_cnt++;
}

static inline void
reinitialize_flow_entry(struct flow_entry *fe, uint64_t now)
{
	fe->state = GK_REQUEST;
	fe->u.request.last_packet_seen_at = now;
	fe->u.request.last_priority = START_PRIORITY;
	fe->u.request.allowance = START_ALLOWANCE - 1;
}

static inline int
drop_packet(struct rte_mbuf *pkt)
{
	rte_pktmbuf_free(pkt);
	return 0;
}

/* 
 * When a flow entry is at request state, all the GK block processing
 * that entry does is to:
 * (1) compute the priority of the packet.
 * (2) encapsulate the packet as a request.
 * (3) put this encapsulated packet in the request queue.
 */
static int
gk_process_request(struct flow_entry *fe, struct ipacket *packet)
{
	int ret;
	uint64_t now = rte_rdtsc();
	uint8_t priority = priority_from_delta_time(now,
			fe->u.request.last_packet_seen_at);
	struct gk_fib *fib = fe->grantor_fib;

	fe->u.request.last_packet_seen_at = now;

	/*
	 * The reason for using "<" instead of "<=" is that the equal case 
	 * means that the source has waited enough time to have the same 
	 * last priority, so it should be awarded with the allowance.
	 */
	if (priority < fe->u.request.last_priority &&
			fe->u.request.allowance > 0) {
		fe->u.request.allowance--;
		priority = fe->u.request.last_priority;
	} else {
		fe->u.request.last_priority = priority;
		fe->u.request.allowance = START_ALLOWANCE - 1;
	}

	/*
	 * TODO If the nexthop MAC address is stale, then drop the packet.
	 */

	/*
	 * Adjust @priority for the DSCP field.
	 * DSCP 0 for legacy packets; 1 for granted packets; 
	 * 2 for capability renew; 3-63 for requests.
	 */
	priority += 3;
	if (unlikely(priority > PRIORITY_MAX))
		priority = PRIORITY_MAX;

	/* The assigned priority is @priority. */

	/* Encapsulate the packet as a request. */
	ret = encapsulate(packet->pkt, priority, &fib->u.grantor.flow);
	if (ret < 0)
		return ret;

	/* TODO Fill up the Ethernet header of the packet. */

	/* TODO Put this encapsulated packet in the request queue. */

	return 0;
}

static inline uint64_t
cycle_from_second(uint64_t time)
{
	return (cycles_per_sec * time);
}

static int
gk_process_granted(struct flow_entry *fe, struct ipacket *packet)
{
	int ret;
	bool renew_cap;
	uint8_t priority = PRIORITY_GRANTED;
	uint64_t now = rte_rdtsc();
	struct rte_mbuf *pkt = packet->pkt;
	struct gk_fib *fib = fe->grantor_fib;

	if (now >= fe->u.granted.cap_expire_at) {
		reinitialize_flow_entry(fe, now);
		return gk_process_request(fe, packet);
	}

	if (now >= fe->u.granted.budget_renew_at) {
		fe->u.granted.budget_renew_at = now + cycle_from_second(1);
		fe->u.granted.budget_byte = fe->u.granted.tx_rate_kb_cycle * 1024;
	}

	if (pkt->data_len > fe->u.granted.budget_byte)
		return drop_packet(pkt);

	fe->u.granted.budget_byte -= pkt->data_len;
	renew_cap = now >= fe->u.granted.send_next_renewal_at;
	if (renew_cap) {
		fe->u.granted.send_next_renewal_at = now +
			fe->u.granted.renewal_step_cycle;
		priority = PRIORITY_RENEW_CAP;
	}

	/*
	 * TODO If the nexthop MAC address is stale, then drop the packet.
	 */

	/*
	 * Encapsulate packet as a granted packet,
	 * mark it as a capability renewal request if @renew_cap is true,
	 * enter destination according to @fe->grantor_fib.
	 */
	ret = encapsulate(packet->pkt, priority, &fib->u.grantor.flow);
	if (ret < 0)
		return ret;

	/* TODO Fill up the Ethernet header of the packet. */

	/* TODO Put the encapsulated packet in the granted queue. */

	return 0;
}

static int
gk_process_declined(struct flow_entry *fe, struct ipacket *packet)
{
	uint64_t now = rte_rdtsc();

	if (unlikely(now >= fe->u.declined.expire_at)) {
		reinitialize_flow_entry(fe, now);
		return gk_process_request(fe, packet);
	}

	return drop_packet(packet->pkt);
}

static int
get_block_idx(struct gk_config *gk_conf, unsigned int lcore_id)
{
	int i;
	for (i = 0; i < gk_conf->num_lcores; i++)
		if (gk_conf->lcores[i] == lcore_id)
			return i;
	rte_panic("Unexpected condition: lcore %u is not running a gk block\n",
		lcore_id);
	return 0;
}

static int
setup_gk_instance(unsigned int lcore_id, struct gk_config *gk_conf)
{
	int  ret;
	char ht_name[64];
	unsigned int block_idx = get_block_idx(gk_conf, lcore_id);
	unsigned int socket_id = rte_lcore_to_socket_id(lcore_id);

	struct gk_instance *instance = &gk_conf->instances[block_idx];
	struct rte_hash_parameters ip_flow_hash_params = {
		.entries = gk_conf->flow_ht_size,
		.key_len = sizeof(struct ip_flow),
		.hash_func = rss_ip_flow_hf,
		.hash_func_init_val = 0,
	};

	ret = snprintf(ht_name, sizeof(ht_name), "ip_flow_hash_%u", block_idx);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(ht_name));

	/* Setup the flow hash table for GK block @block_idx. */
	ip_flow_hash_params.name = ht_name;
	ip_flow_hash_params.socket_id = socket_id;
	instance->ip_flow_hash_table = rte_hash_create(&ip_flow_hash_params);
	if (instance->ip_flow_hash_table == NULL) {
		RTE_LOG(ERR, HASH,
			"The GK block cannot create hash table at lcore %u!\n",
			lcore_id);

		ret = -1;
		goto out;
	}
	/* Set a new hash compare function other than the default one. */
	rte_hash_set_cmp_func(instance->ip_flow_hash_table, ip_flow_cmp_eq);

	/* Setup the flow entry table for GK block @block_idx. */
	instance->ip_flow_entry_table = (struct flow_entry *)rte_calloc(NULL,
		gk_conf->flow_ht_size, sizeof(struct flow_entry), 0);
	if (instance->ip_flow_entry_table == NULL) {
		RTE_LOG(ERR, MALLOC,
			"The GK block can't create flow entry table at lcore %u!\n",
			lcore_id);

		ret = -1;
		goto flow_hash;
	}

	ret = init_mailbox("gk", MAILBOX_MAX_ENTRIES,
		sizeof(struct gk_cmd_entry), lcore_id, &instance->mb);
    	if (ret < 0)
        	goto flow_entry;

	ret = 0;
	goto out;

flow_entry:
    	rte_free(instance->ip_flow_entry_table);
    	instance->ip_flow_entry_table = NULL;
flow_hash:
	rte_hash_free(instance->ip_flow_hash_table);
	instance->ip_flow_hash_table = NULL;
out:
	return ret;
}

static void
print_flow_err_msg(struct ip_flow *flow, const char *err_msg)
{
	char src[128];
	char dst[128];

	if (flow->proto == ETHER_TYPE_IPv4) {
		if (inet_ntop(AF_INET, &flow->f.v4.src,
				src, sizeof(struct in_addr)) == NULL) {
			RTE_LOG(ERR, GATEKEEPER, "gk: %s: failed to convert a number to an IPv4 address (%s)\n",
				__func__, strerror(errno));
			return;
		}

		if (inet_ntop(AF_INET, &flow->f.v4.dst,
				dst, sizeof(struct in_addr)) == NULL) {
			RTE_LOG(ERR, GATEKEEPER, "gk: %s: failed to convert a number to an IPv4 address (%s)\n",
				__func__, strerror(errno));
			return;
		}
	} else if (likely(flow->proto == ETHER_TYPE_IPv6)) {
		if (inet_ntop(AF_INET6, flow->f.v6.src,
				src, sizeof(struct in6_addr)) == NULL) {
			RTE_LOG(ERR, GATEKEEPER, "gk: %s: failed to convert a number to an IPv6 address (%s)\n",
				__func__, strerror(errno));
			return;
		}

		if (inet_ntop(AF_INET6, flow->f.v6.dst,
				dst, sizeof(struct in6_addr)) == NULL) {
			RTE_LOG(ERR, GATEKEEPER, "gk: %s: failed to convert a number to an IPv6 address (%s)\n",
				__func__, strerror(errno));
			return;
		}
	} else
		rte_panic("Unexpected condition at %s: unknown flow type %hu!\n",
			__func__, flow->proto);

	RTE_LOG(ERR, GATEKEEPER,
		"%s for the flow with IP source address %s, and destination address %s!\n",
		err_msg, src, dst);
}

/*
 * This function is only called when a policy from GGU block
 * tries to add a new flow entry in the flow table.
 *
 * Notice, the function doesn't fully initialize the new flow entry,
 * instead it only initializes the @flow and @grantor_fib fields.
 */
static struct flow_entry *
add_new_flow_from_policy(
	struct ggu_policy *policy, struct gk_instance *instance,
	struct gk_lpm *ltbl, uint32_t rss_hash_val)
{
	int ret;
	struct gk_fib *fib;
	struct flow_entry *fe;

	fib = look_up_fib(ltbl, &policy->flow);
	if (fib == NULL || fib->action != GK_FWD_GRANTOR) {
		/*
		 * Drop this solicitation to add
		 * a policy decision.
		 */
		char err_msg[128];
		ret = snprintf(err_msg, sizeof(err_msg),
			"gk: at %s initialize flow entry error", __func__);
		RTE_VERIFY(ret > 0 && ret < (int)sizeof(err_msg));
		print_flow_err_msg(&policy->flow, err_msg);
		return NULL;
	}

	/* Create a new flow entry. */
	ret = rte_hash_add_key_with_hash(
		instance->ip_flow_hash_table,
 		&policy->flow, rss_hash_val);
	if (ret < 0) {
		RTE_LOG(ERR, HASH,
			"The GK block failed to add new key to hash table in %s!\n",
			__func__);
		return NULL;
	}

	fe = &instance->ip_flow_entry_table[ret];
	rte_memcpy(&fe->flow, &policy->flow, sizeof(fe->flow));

	fe->grantor_fib = fib;
	fib->ref_cnt++;

	return fe;
}

static void
add_ggu_policy(struct ggu_policy *policy,
	struct gk_instance *instance, struct gk_lpm *ltbl)
{
	int ret;
	uint64_t now = rte_rdtsc();
	struct flow_entry *fe;
	uint32_t rss_hash_val = rss_ip_flow_hf(&policy->flow, 0, 0);

	/*
	 * When the flow entry already exists,
	 * the grantor ID should be already known.
	 * Otherwise, Grantor ID comes from LPM lookup.
	 */
	ret = rte_hash_lookup_with_hash(instance->ip_flow_hash_table,
		&policy->flow, rss_hash_val);
	if (ret < 0) {
		/*
	 	 * The function add_ggu_policy() only fills up
		 * GK_GRANTED and GK_DECLINED states. So, it doesn't
		 * need to call initialize_flow_entry().
		 */
		fe = add_new_flow_from_policy(
			policy, instance, ltbl, rss_hash_val);
		if (fe == NULL)
			return;
	} else
		fe = &instance->ip_flow_entry_table[ret];

	switch (policy->state) {
	case GK_GRANTED:
		fe->state = GK_GRANTED;
		fe->u.granted.cap_expire_at = now +
			policy->params.u.granted.cap_expire_sec *
			cycles_per_sec;
		fe->u.granted.tx_rate_kb_cycle =
			policy->params.u.granted.tx_rate_kb_sec;
		fe->u.granted.send_next_renewal_at = now +
			policy->params.u.granted.next_renewal_ms *
			cycles_per_ms;
		fe->u.granted.renewal_step_cycle =
			policy->params.u.granted.renewal_step_ms *
			cycles_per_ms;
		fe->u.granted.budget_renew_at =
			now + cycle_from_second(1);
		fe->u.granted.budget_byte =
			fe->u.granted.tx_rate_kb_cycle * 1024;
		break;

	case GK_DECLINED:
		fe->state = GK_DECLINED;
		fe->u.declined.expire_at = now +
			policy->params.u.declined.expire_sec * cycles_per_sec;
		break;

	default:
		RTE_LOG(ERR, GATEKEEPER,
			"gk: unknown flow state %u!\n", policy->state);
		break;
	}
}

static void
process_gk_cmd(struct gk_cmd_entry *entry,
	struct gk_instance *instance, struct gk_lpm *ltbl)
{
	switch (entry->op) {
	case GGU_POLICY_ADD:
		add_ggu_policy(&entry->u.ggu, instance, ltbl);
		break;

	default:
		RTE_LOG(ERR, GATEKEEPER,
			"gk: unknown command operation %u\n", entry->op);
		break;
	}
}

static int
gk_setup_rss(struct gk_config *gk_conf)
{
	int i, ret = 0;
	uint8_t port_front = gk_conf->net->front.id;
	uint16_t gk_queues_front[gk_conf->num_lcores];
	uint8_t port_back = gk_conf->net->back.id;
	uint16_t gk_queues_back[gk_conf->num_lcores];

	for (i = 0; i < gk_conf->num_lcores; i++) {
		gk_queues_front[i] = gk_conf->instances[i].rx_queue_front;
		gk_queues_back[i] = gk_conf->instances[i].rx_queue_back;
	}

	ret = gatekeeper_setup_rss(
		port_front, gk_queues_front, gk_conf->num_lcores);
	if (ret < 0)
		goto out;

	ret = gatekeeper_get_rss_config(
		port_front, &gk_conf->rss_conf_front);
	if (ret < 0)
		goto out;

	ret = gatekeeper_setup_rss(
		port_back, gk_queues_back, gk_conf->num_lcores);
	if (ret < 0)
		goto out;

	ret = gatekeeper_get_rss_config(
		port_back, &gk_conf->rss_conf_back);
	if (ret < 0)
		goto out;

	ret = 0;

out:
	return ret;
}

/* TODO Customize the hash function for IPv4. */

static inline struct ether_cache *
lookup_ether_cache(struct neighbor_hash_table *neigh_tbl, void *key)
{
	int ret = rte_hash_lookup(neigh_tbl->hash_table, key);

	if (ret < 0)
		return NULL;

	return &neigh_tbl->cache_tbl[ret];
}

/* Process the packets on the front interface. */
static void
process_pkts_front(uint8_t port_front, uint8_t port_back,
	uint16_t rx_queue_front, uint16_t tx_queue_back,
	unsigned int lcore, struct gk_instance *instance,
	struct gk_config *gk_conf)
{
	/* Get burst of RX packets, from first port of pair. */
	int i;
	int ret;
	uint16_t num_rx;
	uint16_t num_tx = 0;
	uint16_t num_tx_succ;
	struct rte_mbuf *rx_bufs[GATEKEEPER_MAX_PKT_BURST];
	struct rte_mbuf *tx_bufs[GATEKEEPER_MAX_PKT_BURST];
	IPV6_ACL_SEARCH_DEF(acl);

	/* Load a set of packets from the front NIC. */
	num_rx = rte_eth_rx_burst(port_front, rx_queue_front, rx_bufs,
		GATEKEEPER_MAX_PKT_BURST);

	if (unlikely(num_rx == 0))
		return;

	for (i = 0; i < num_rx; i++) {
		struct ipacket packet;
		/*
		 * Pointer to the flow entry in request state 
		 * under evaluation.
		 */
		struct flow_entry *fe;
		struct rte_mbuf *pkt = rx_bufs[i];

		ret = extract_packet_info(pkt, &packet);
		if (ret < 0) {
			/* Drop non-IP packets. */
			drop_packet(pkt);
			continue;
		}

		/* 
		 * Find the flow entry for the IP pair.
		 *
		 * If the pair of source and destination addresses 
		 * is in the flow table, proceed as the entry instructs,
		 * and go to the next packet.
		 */
		ret = rte_hash_lookup_with_hash(instance->ip_flow_hash_table,
			&packet.flow, pkt->hash.rss);
		if (ret >= 0)
			fe = &instance->ip_flow_entry_table[ret];
		else {
			/*
			 * Otherwise, look up the destination address
		 	 * in the global LPM table.
			 */
			struct gk_fib *fib = look_up_fib(
				&gk_conf->lpm_tbl, &packet.flow);
			struct ether_cache *eth_cache;
			struct ether_hdr *eth_hdr;

		 	/* No entry for the destination, drop the packet. */
			if (fib == NULL) {
				if (packet.flow.proto == ETHER_TYPE_IPv6)
					add_pkt_ipv6_acl(&acl, pkt);
				else {
					print_flow_err_msg(&packet.flow,
						"gk: failed to get the fib entry");
					drop_packet(pkt);
				}
				continue;
			}

			switch (fib->action) {
			case GK_FWD_GRANTOR:
				/*
				 * The entry instructs to enforce
				 * policies over its packets,
			 	 * initialize an entry in the
				 * flow table, proceed as the
				 * brand-new entry instructs, and
			 	 * go to the next packet.
			 	 */
				ret = rte_hash_add_key_with_hash(
					instance->ip_flow_hash_table,
 					&packet.flow, pkt->hash.rss);
				if (ret < 0) {
					RTE_LOG(ERR, HASH,
						"The GK block failed to add new key to hash table!\n");
					drop_packet(pkt);
					continue;
				}

				fe = &instance->ip_flow_entry_table[ret];
				initialize_flow_entry(fe, &packet.flow, fib);
				break;

			case GK_FWD_GATEWAY_BACK_NET: {
			 	/*
				 * The entry instructs to forward
				 * its packets to the gateway in
				 * the back network, forward accordingly.
				 *
				 * BP block bypasses from the front to the
				 * back interface are expected to bypass
				 * ranges of IP addresses that should not
				 * go through Gatekeeper.
				 *
				 * Notice that one needs to update
				 * the Ethernet header.
				 *
				 * TODO Add sequential lock to deal with the
				 * concurrency between GK and LLS on the cached
				 * Ethernet header.
				 */
				eth_cache = fib->u.gateway.eth_cache;
				if (eth_cache == NULL || eth_cache->stale) {
					drop_packet(pkt);
					continue;
				}

				eth_hdr = rte_pktmbuf_mtod(
					pkt, struct ether_hdr *);
				rte_memcpy(eth_hdr,
					&eth_cache->eth_hdr, sizeof(*eth_hdr));
				tx_bufs[num_tx++] = pkt;
				continue;
			}

			case GK_FWD_NEIGHBOR_BACK_NET: {
				/*
				 * The entry instructs to forward
				 * its packets to the neighbor in
				 * the back network, forward accordingly.
				 */
				if (packet.flow.proto == ETHER_TYPE_IPv4) {
					eth_cache = lookup_ether_cache(
						&fib->u.neigh,
						&packet.flow.f.v4.dst);
				} else {
					eth_cache = lookup_ether_cache(
						&fib->u.neigh6,
						packet.flow.f.v6.dst);
				}

				if (eth_cache == NULL || eth_cache->stale) {
					drop_packet(pkt);
					continue;
				}

				eth_hdr = rte_pktmbuf_mtod(
					pkt, struct ether_hdr *);
				rte_memcpy(eth_hdr,
					&eth_cache->eth_hdr, sizeof(*eth_hdr));
				tx_bufs[num_tx++] = pkt;
				continue;
			}

			case GK_DROP:
				/* FALLTHROUGH */
			default:
				drop_packet(pkt);
				continue;
			}
		}

		switch (fe->state) {
		case GK_REQUEST:
			ret = gk_process_request(fe, &packet);
			break;

		case GK_GRANTED:
			ret = gk_process_granted(fe, &packet);
			break;

		case GK_DECLINED:
			ret = gk_process_declined(fe, &packet);
			break;

		default:
			ret = -1;
			/* XXX Incorrect state, log warning. */
			RTE_LOG(ERR, GATEKEEPER,
				"gk: unknown flow state!\n");
			break;
		}

		if (ret < 0)
			rte_pktmbuf_free(pkt);
		else
			tx_bufs[num_tx++] = pkt;
	}

	/* Send burst of TX packets, to second port of pair. */
	num_tx_succ = rte_eth_tx_burst(port_back, tx_queue_back,
		tx_bufs, num_tx);

	/* XXX Do something better here! For now, free any unsent packets. */
	if (unlikely(num_tx_succ < num_tx)) {
		for (i = num_tx_succ; i < num_tx; i++)
			rte_pktmbuf_free(tx_bufs[i]);
	}

	process_pkts_ipv6_acl(&gk_conf->net->front, lcore, &acl);
}

/* Process the packets on the back interface. */
static void
process_pkts_back(uint8_t port_back, uint8_t port_front,
	uint16_t rx_queue_back, uint16_t tx_queue_front,
	unsigned int lcore, struct gk_config *gk_conf)
{
	/* Get burst of RX packets, from first port of pair. */
	int i;
	int ret;
	uint16_t num_rx;
	uint16_t num_tx = 0;
	uint16_t num_tx_succ;
	struct rte_mbuf *rx_bufs[GATEKEEPER_MAX_PKT_BURST];
	struct rte_mbuf *tx_bufs[GATEKEEPER_MAX_PKT_BURST];
	IPV6_ACL_SEARCH_DEF(acl);

	/* Load a set of packets from the back NIC. */
	num_rx = rte_eth_rx_burst(port_back, rx_queue_back, rx_bufs,
		GATEKEEPER_MAX_PKT_BURST);

	if (unlikely(num_rx == 0))
		return;

	for (i = 0; i < num_rx; i++) {
		struct ipacket packet;
		struct gk_fib *fib;
		struct rte_mbuf *pkt = rx_bufs[i];
		struct ether_cache *eth_cache;
		struct ether_hdr *eth_hdr;

		ret = extract_packet_info(pkt, &packet);
		if (ret < 0) {
			/* Drop non-IP packets. */
			drop_packet(pkt);
			continue;
		}

		fib = look_up_fib(&gk_conf->lpm_tbl, &packet.flow);

		 /* No entry for the destination, drop the packet. */
		if (fib == NULL) {
			if (packet.flow.proto == ETHER_TYPE_IPv6)
				add_pkt_ipv6_acl(&acl, pkt);
			else {
				print_flow_err_msg(&packet.flow,
					"gk: failed to get the fib entry");
				drop_packet(pkt);
			}
			continue;
		}

		switch (fib->action) {
		case GK_FWD_GATEWAY_FRONT_NET: {
			/*
			 * The entry instructs to forward
			 * its packets to the gateway in
			 * the front network, forward accordingly.
			 *
			 * BP bypasses from the back to the front interface
			 * are expected to bypass the outgoing traffic
			 * from the AS to its peers.
			 *
			 * Notice that one needs to update
			 * the Ethernet header.
			 *
			 * TODO Add sequential lock to deal with the
			 * concurrency between GK and LLS on the cached
			 * Ethernet header.
			 */
			eth_cache = fib->u.gateway.eth_cache;
			if (eth_cache == NULL || eth_cache->stale) {
				drop_packet(pkt);
				continue;
			}

			eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
			rte_memcpy(eth_hdr,
				&eth_cache->eth_hdr, sizeof(*eth_hdr));
			tx_bufs[num_tx++] = pkt;
			continue;
		}

		case GK_FWD_NEIGHBOR_FRONT_NET: {
			/*
		 	 * The entry instructs to forward
			 * its packets to the neighbor in
			 * the front network, forward accordingly.
			 */
			if (packet.flow.proto == ETHER_TYPE_IPv4) {
				eth_cache = lookup_ether_cache(
					&fib->u.neigh,
					&packet.flow.f.v4.dst);
			} else {
				eth_cache = lookup_ether_cache(
					&fib->u.neigh6,
					packet.flow.f.v6.dst);
			}

			if (eth_cache == NULL || eth_cache->stale) {
				drop_packet(pkt);
				continue;
			}

			eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
			rte_memcpy(eth_hdr,
				&eth_cache->eth_hdr, sizeof(*eth_hdr));
			tx_bufs[num_tx++] = pkt;
			continue;
		}

		default:
			/* All other actions should log a warning. */
			RTE_LOG(WARNING, GATEKEEPER,
				"gk: the fib entry has an unexpected action %u at %s!\n",
				fib->action, __func__);
			drop_packet(pkt);
			continue;
		}
	}

	/* Send burst of TX packets, to second port of pair. */
	num_tx_succ = rte_eth_tx_burst(port_front, tx_queue_front,
		tx_bufs, num_tx);

	/* XXX Do something better here! For now, free any unsent packets. */
	if (unlikely(num_tx_succ < num_tx)) {
		for (i = num_tx_succ; i < num_tx; i++)
			rte_pktmbuf_free(tx_bufs[i]);
	}

	process_pkts_ipv6_acl(&gk_conf->net->back, lcore, &acl);
}

static void
process_cmds_from_mailbox(
	struct gk_instance *instance, struct gk_config *gk_conf)
{
	int i;
	int num_cmd;
	struct gk_cmd_entry *gk_cmds[GK_CMD_BURST_SIZE];

	/* Load a set of commands from its mailbox ring. */
        num_cmd = mb_dequeue_burst(&instance->mb,
               	(void **)gk_cmds, GK_CMD_BURST_SIZE);

        for (i = 0; i < num_cmd; i++) {
		process_gk_cmd(gk_cmds[i], instance, &gk_conf->lpm_tbl);
		mb_free_entry(&instance->mb, gk_cmds[i]);
        }
}

static int
gk_proc(void *arg)
{
	unsigned int lcore = rte_lcore_id();
	struct gk_config *gk_conf = (struct gk_config *)arg;
	unsigned int block_idx = get_block_idx(gk_conf, lcore);
	struct gk_instance *instance = &gk_conf->instances[block_idx];

	uint8_t port_front = get_net_conf()->front.id;
	uint8_t port_back = get_net_conf()->back.id;
	uint16_t rx_queue_front = instance->rx_queue_front;
	uint16_t tx_queue_front = instance->tx_queue_front;
	uint16_t rx_queue_back = instance->rx_queue_back;
	uint16_t tx_queue_back = instance->tx_queue_back;

	RTE_LOG(NOTICE, GATEKEEPER,
		"gk: the GK block is running at lcore = %u\n", lcore);

	gk_conf_hold(gk_conf);

	while (likely(!exiting)) {
		process_pkts_front(port_front, port_back,
			rx_queue_front, tx_queue_back,
			lcore, instance, gk_conf);

		process_pkts_back(port_back, port_front,
			rx_queue_back, tx_queue_front,
			lcore, gk_conf);

		process_cmds_from_mailbox(instance, gk_conf);
	}

	RTE_LOG(NOTICE, GATEKEEPER,
		"gk: the GK block at lcore = %u is exiting\n", lcore);

	return gk_conf_put(gk_conf);
}

struct gk_config *
alloc_gk_conf(void)
{
	return rte_calloc("gk_config", 1, sizeof(struct gk_config), 0);
}

static void
destroy_gk_lpm(struct gk_lpm *ltbl)
{
	destroy_ipv4_lpm(ltbl->lpm);
	destroy_ipv6_lpm(ltbl->lpm6);
}

static int
cleanup_gk(struct gk_config *gk_conf)
{
	int i;

	for (i = 0; i < gk_conf->num_lcores; i++) {
		if (gk_conf->instances[i].ip_flow_hash_table != NULL)
			rte_hash_free(gk_conf->instances[i].
				ip_flow_hash_table);

		if (gk_conf->instances[i].ip_flow_entry_table != NULL)
			rte_free(gk_conf->instances[i].
				ip_flow_entry_table);

                destroy_mailbox(&gk_conf->instances[i].mb);
	}

	for (i = 0; i < 2; i++) {
		if (gk_conf->lpm_tbl.fib_tbl[i].u.neigh.cache_tbl != NULL)
			rte_free(gk_conf->lpm_tbl.fib_tbl[i].
				u.neigh.cache_tbl);

		if (gk_conf->lpm_tbl.fib_tbl[i].u.neigh.hash_table != NULL)
			rte_hash_free(gk_conf->lpm_tbl.fib_tbl[i].
				u.neigh.hash_table);

		if (gk_conf->lpm_tbl.fib_tbl6[i].u.neigh.cache_tbl != NULL)
			rte_free(gk_conf->lpm_tbl.fib_tbl6[i].
				u.neigh.cache_tbl);

		if (gk_conf->lpm_tbl.fib_tbl6[i].u.neigh.hash_table != NULL)
			rte_hash_free(gk_conf->lpm_tbl.fib_tbl6[i].
				u.neigh.hash_table);
	}

	destroy_gk_lpm(&gk_conf->lpm_tbl);

	rte_free(gk_conf->instances);
	rte_free(gk_conf->lcores);
	rte_free(gk_conf);

	return 0;
}

int
gk_conf_put(struct gk_config *gk_conf)
{
	/*
	 * Atomically decrements the atomic counter (v) by one and returns true 
	 * if the result is 0, or false in all other cases.
	 */
	if (rte_atomic32_dec_and_test(&gk_conf->ref_cnt))
		return cleanup_gk(gk_conf);

	return 0;
}

static int
parse_ip_prefix(const char *ip_prefix, struct ipaddr *res)
{
	/* Need to make copy to tokenize. */
	size_t ip_prefix_len = strlen(ip_prefix);
	char ip_prefix_copy[ip_prefix_len + 1];
	char *ip_addr;

	char *saveptr;
	char *prefix_len_str;
	char *end;
	long prefix_len;
	int ip_type;

	strncpy(ip_prefix_copy, ip_prefix, ip_prefix_len + 1);

	ip_addr = strtok_r(ip_prefix_copy, "/", &saveptr);
	if (ip_addr == NULL)
		return -1;

	ip_type = get_ip_type(ip_addr);

	prefix_len_str = strtok_r(NULL, "\0", &saveptr);
	if (prefix_len_str == NULL)
		return -1;

	prefix_len = strtol(prefix_len_str, &end, 10);
	if (prefix_len_str == end || !*prefix_len_str || *end) {
		RTE_LOG(ERR, GATEKEEPER,
			"gk: prefix length \"%s\" is not a number\n",
			prefix_len_str);
		return -1;
	}

	if ((prefix_len == LONG_MAX || prefix_len == LONG_MIN) &&
			errno == ERANGE) {
		RTE_LOG(ERR, GATEKEEPER,
			"gk: prefix length \"%s\" caused underflow or overflow\n",
			prefix_len_str);
		return -1;
	}

	if (prefix_len < 0 || prefix_len > max_prefix_len(ip_type)) {
		RTE_LOG(ERR, GATEKEEPER,
			"gk: prefix length \"%s\" is out of range\n",
			prefix_len_str);
		return -1;
	}

	if (convert_str_to_ip(ip_addr, res) < 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"gk: failed to convert ip prefix %s to a number!\n",
			ip_prefix);
		return -1;
	}

	return prefix_len;
}

static int
init_fib_tbl(struct gk_config *gk_conf)
{
	unsigned int i;
	struct gk_lpm *ltbl = &gk_conf->lpm_tbl;

	/* TODO Set up the neighbor hash tables. */

	/*
	 * We use the first fib entry with
	 * action GK_FWD_NEIGHBOR_FRONT_NET.
	 */
	ltbl->fib_tbl[0].action = GK_FWD_NEIGHBOR_FRONT_NET;
	ltbl->fib_tbl6[0].action = GK_FWD_NEIGHBOR_FRONT_NET;

	/*
	 * We use the second fib entry with
	 * action GK_FWD_NEIGHBOR_BACK_NET.
	 */
	ltbl->fib_tbl[1].action = GK_FWD_NEIGHBOR_BACK_NET;
	ltbl->fib_tbl6[1].action = GK_FWD_NEIGHBOR_BACK_NET;

	for (i = 2; i < GK_MAX_NUM_FIB_ENTRIES; i++) {
		ltbl->fib_tbl[i].action = GK_FIB_MAX;
		ltbl->fib_tbl6[i].action = GK_FIB_MAX;
	}

	return 0;
}

/*
 * XXX Only instantiate the LPM tables needed, for example,
 * there's no need for an IPv6 LPM table in an IPv4-only deployment.
 */
static int
setup_gk_lpm(struct gk_config *gk_conf, unsigned int socket_id)
{
	int ret;
	struct rte_lpm_config ipv4_lpm_config;
	struct rte_lpm6_config ipv6_lpm_config;
	struct gk_lpm *ltbl = &gk_conf->lpm_tbl;

	ipv4_lpm_config.max_rules = gk_conf->max_num_ipv4_rules;
	ipv4_lpm_config.number_tbl8s = gk_conf->num_ipv4_tbl8s;
	ipv6_lpm_config.max_rules = gk_conf->max_num_ipv6_rules;
	ipv6_lpm_config.number_tbl8s = gk_conf->num_ipv6_tbl8s;

	/*
	 * The GK blocks only need to create one single IPv4 LPM table
	 * on the @socket_id, so the @lcore and @identifier are set to 0.
	 */
	ltbl->lpm = init_ipv4_lpm("gk", &ipv4_lpm_config, socket_id, 0, 0);
	if (ltbl->lpm == NULL) {
		ret = -1;
		goto out;
	}

	/*
	 * The GK blocks only need to create one single IPv6 LPM table
	 * on the @socket_id, so the @lcore and @identifier are set to 0.
	 */
	ltbl->lpm6 = init_ipv6_lpm("gk", &ipv6_lpm_config, socket_id, 0, 0);
	if (ltbl->lpm6 == NULL) {
		ret = -1;
		goto free_lpm;
	}

	ret = init_fib_tbl(gk_conf);
	if (ret < 0)
		goto free_lpm6;

	ret = 0;
	goto out;

free_lpm6:
	destroy_ipv6_lpm(ltbl->lpm6);

free_lpm:
	destroy_ipv4_lpm(ltbl->lpm);

out:
	return ret;
}

static int
gk_lpm_add_ipv4_routes(
	struct rte_lpm *lpm, struct ipv4_lpm_route *routes,
	unsigned int num_routes, struct gk_lpm *ltbl)
{
	int ret = 0;
	unsigned int i;
	for (i = 0; i < num_routes; i++) {
		ret = rte_lpm_add(lpm, routes[i].ip,
			routes[i].depth, routes[i].nexthop);
		if (ret < 0)
			goto out;
		ltbl->fib_tbl[routes[i].nexthop].ref_cnt++;
	}

out:
	return ret;
}

static int
gk_lpm_add_ipv6_routes(
	struct rte_lpm6 *lpm, struct ipv6_lpm_route *routes,
	unsigned int num_routes, struct gk_lpm *ltbl)
{
	int ret = 0;
	unsigned int i;
	for (i = 0; i < num_routes; i++) {
		ret = rte_lpm6_add(lpm, routes[i].ip,
			routes[i].depth, routes[i].nexthop);
		if (ret < 0)
			goto out;
		ltbl->fib_tbl6[routes[i].nexthop].ref_cnt++;
	}

out:
	return ret;
}

static int
get_empty_fib_id(struct gk_fib *fib_tbl)
{
	int i;
	for (i = 0; i < GK_MAX_NUM_FIB_ENTRIES; i++) {
		if (fib_tbl[i].action == GK_FIB_MAX)
			return i; 
	}

	RTE_LOG(WARNING, GATEKEEPER,
		"gk: cannot find an empty fib entry in the LPM fib_tbl!\n");

	return -1;
}

static struct gk_fib *
add_prefix_fib(struct ipaddr *ip_addr,
	int prefix_len, struct gk_config *gk_conf)
{
	int ret;
	int fib_id = -1;
	struct ipv4_lpm_route ipv4_route;
	struct ipv6_lpm_route ipv6_route;
	struct gk_fib *new_fib = NULL;
	struct gk_lpm *ltbl = &gk_conf->lpm_tbl;

	/* Find an empty fib entry for the IP address. */
	if (ip_addr->proto == ETHER_TYPE_IPv4) {
		if (!ipv4_if_configured(&gk_conf->net->back))
			goto out;

		fib_id = get_empty_fib_id(ltbl->fib_tbl);
		if (fib_id < 0)
			goto out;

		new_fib = &ltbl->fib_tbl[fib_id];

		/*
		 * Add the fib entry for the IPv4 address
		 * to the IPv4 LPM table.
		 */
		ipv4_route.ip = ip_addr->ip.v4.s_addr;
		ipv4_route.depth = prefix_len;
		ipv4_route.nexthop = fib_id;
		ret = gk_lpm_add_ipv4_routes(
			ltbl->lpm, &ipv4_route, 1, ltbl);
		if (ret < 0)
			goto out;
	} else if (ip_addr->proto == ETHER_TYPE_IPv6) {
		if (!ipv6_if_configured(&gk_conf->net->back))
			goto out;

		fib_id = get_empty_fib_id(ltbl->fib_tbl6);
		if (fib_id < 0)
			goto out;

		new_fib = &ltbl->fib_tbl6[fib_id];

		/*
		 * Add the fib entry for the IPv6 address 
		 * to the IPv6 LPM table.
		 */
		rte_memcpy(ipv6_route.ip,
			ip_addr->ip.v6.s6_addr, sizeof(ipv6_route.ip));
		ipv6_route.depth = prefix_len;
		ipv6_route.nexthop = fib_id;
		ret = gk_lpm_add_ipv6_routes(
			ltbl->lpm6, &ipv6_route, 1, ltbl);
		if (ret < 0)
			goto out;
	} else
		goto out;

out:
	return new_fib;
}

static struct gk_fib *
init_gateway_fib(struct ipaddr *gw_addr, struct ipaddr *ip_prefix_addr,
	int ip_prefix_len, enum gk_fib_action action, struct gk_config *gk_conf)
{
	int fib_id = -1;
	struct ether_cache *eth_cache;
	struct gk_fib *gw_fib = NULL;
	struct gk_fib *gt_fib = NULL;
	struct gk_lpm *ltbl = &gk_conf->lpm_tbl;

	if (gw_addr->proto != ip_prefix_addr->proto) {
		RTE_LOG(ERR, GATEKEEPER,
			"gk: failed to initialize a fib entry for gateway, since the gateway and its responsible grantors have different IP versions.\n");
		goto out;
	}

	if (action != GK_FWD_GATEWAY_FRONT_NET
			&& action != GK_FWD_GATEWAY_BACK_NET) {
		RTE_LOG(ERR, GATEKEEPER,
			"gk: failed to initialize a fib entry for gateway, since it has invalid action %d.\n",
			action);
		goto out;
	}

	/* Find the fib entry for the gateway IP address. */
	if (gw_addr->proto == ETHER_TYPE_IPv4) {
		fib_id = lpm_lookup_ipv4(ltbl->lpm, gw_addr->ip.v4.s_addr);
		if (fib_id < 0) {
			gw_fib = add_prefix_fib(gw_addr,
				(sizeof(struct in_addr) * 8), gk_conf);
		} else
			gw_fib = &ltbl->fib_tbl[fib_id];
	} else if (gw_addr->proto == ETHER_TYPE_IPv6) {
		fib_id = lpm_lookup_ipv6(ltbl->lpm6, gw_addr->ip.v6.s6_addr);
		if (fib_id < 0) {
			gw_fib = add_prefix_fib(gw_addr,
				(sizeof(struct in6_addr) * 8), gk_conf);
		} else
			gw_fib = &ltbl->fib_tbl6[fib_id];
	} else
		rte_panic("Unexpected condiction: unknown IP type %hu at %s!\n",
			gw_addr->proto, __func__);

	if (gw_fib == NULL)
		goto out;

	/* Fill up the fib entry for the gateway. */
	gw_fib->action = action;

	rte_memcpy(&gw_fib->u.gateway.ip_addr,
		gw_addr, sizeof(gw_fib->u.gateway.ip_addr));

	eth_cache = gw_fib->u.gateway.eth_cache;
	eth_cache->stale = true;
	eth_cache->eth_hdr.ether_type = gw_addr->proto;
	eth_cache->ref_cnt++;

	/*
	 * Add a fib entry for the Grantor IP prefix,
	 * for which the gateway is responsible.
	 *
	 * Notice, for this fib, it doesn't need to initialize the
	 * fields @flow and @eth_cache, since it's only used to help
	 * lookup the fib entry for the gateway.
	 */
	gt_fib = add_prefix_fib(ip_prefix_addr, ip_prefix_len, gk_conf);
	if (gt_fib != NULL) {
		gt_fib->action = GK_FWD_GRANTOR;
		gt_fib->u.grantor.next_fib = gw_fib;
		gt_fib->u.grantor.is_grantor_prefix_fib = true;
		gw_fib->ref_cnt++;
	}

out:
	return gw_fib;
}

static struct gk_fib *
init_grantor_fib(struct ipaddr *gt_addr, struct gk_config *gk_conf)
{
	int fib_id = -1;
	int prefix_len;
	struct ip_flow *flow;
	struct gk_fib *gt_fib = NULL;
	struct gk_fib *gt_prefix_fib = NULL;
	struct gk_lpm *ltbl = &gk_conf->lpm_tbl;

	/* Find the fib entry for the Grantor IP prefix. */
	if (gt_addr->proto == ETHER_TYPE_IPv4) {
		fib_id = lpm_lookup_ipv4(ltbl->lpm, gt_addr->ip.v4.s_addr);
		if (fib_id >= 0)
			gt_prefix_fib = &ltbl->fib_tbl[fib_id];

		prefix_len = sizeof(struct in_addr) * 8;
	} else if (gt_addr->proto == ETHER_TYPE_IPv6) {
		fib_id = lpm_lookup_ipv6(ltbl->lpm6, gt_addr->ip.v6.s6_addr);
		if (fib_id >= 0)
			gt_prefix_fib = &ltbl->fib_tbl6[fib_id];

		prefix_len = sizeof(struct in6_addr) * 8;
	} else
		rte_panic("Unexpected condiction: unknown IP type %hu at %s!\n",
			gt_addr->proto, __func__);

	/* It's the fib entry for the Grantor. */
	if (gt_prefix_fib && !gt_prefix_fib->u.grantor.is_grantor_prefix_fib)
		return gt_prefix_fib;

	gt_fib = add_prefix_fib(gt_addr, prefix_len, gk_conf);
	if (gt_fib == NULL)
		goto out;

	gt_fib->action = GK_FWD_GRANTOR;
	flow = &gt_fib->u.grantor.flow;

	if (gt_addr->proto == ETHER_TYPE_IPv4) {
		flow->proto = ETHER_TYPE_IPv4;
		flow->f.v4.src = gk_conf->net->back.ip4_addr.s_addr;
		flow->f.v4.dst = gt_addr->ip.v4.s_addr;
	} else {
		flow->proto = ETHER_TYPE_IPv6;
		rte_memcpy(flow->f.v6.src,
			gk_conf->net->back.ip6_addr.s6_addr,
			sizeof(flow->f.v6.src));
		rte_memcpy(flow->f.v6.dst,
			gt_addr->ip.v6.s6_addr, sizeof(flow->f.v6.dst));
	}

	/* Fill up the @next_fib field in the @gt_fib. */

	/* The Grantor server is an neighbor. */
	if (gt_prefix_fib == NULL) {
		gt_fib->u.grantor.eth_cache->stale = true;
		gt_fib->u.grantor.eth_cache->eth_hdr.ether_type =
			gt_addr->proto;
		gt_fib->u.grantor.eth_cache->ref_cnt++;
		gt_fib->u.grantor.next_fib =
			gt_addr->proto == ETHER_TYPE_IPv4 ?
			ltbl->fib_tbl : ltbl->fib_tbl6;
		gt_fib->u.grantor.next_fib->ref_cnt++;
	} else {
		gt_fib->u.grantor.next_fib =
			gt_prefix_fib->u.grantor.next_fib;
		gt_fib->u.grantor.next_fib->ref_cnt++;
	}

out:
	return gt_fib;
}

int
add_fib_entry(struct lua_gk_fib *gk_fib, struct gk_config *gk_conf)
{
	int ret;

	struct ipaddr gw_addr;
	struct gk_fib *gw_fib = NULL;

	struct ipaddr gt_addr;
	struct gk_fib *gt_fib = NULL;

	struct ipaddr ip_prefix_addr;
	int ip_prefix_len;
	struct gk_fib *ip_prefix_fib = NULL;

	switch (gk_fib->action) {
	case GK_FWD_GRANTOR: {

		/* Initialize the fib entry for the Grantor. */
		ret = convert_str_to_ip(gk_fib->grantor, &gt_addr);
		if (ret < 0)
			goto out;

		gt_fib = init_grantor_fib(&gt_addr, gk_conf);
		if (gt_fib == NULL) {
			ret = -1;
			goto out;
		}

		/* Initialize the fib entry for the IP prefix. */
 		ip_prefix_len = parse_ip_prefix(
			gk_fib->ip_prefix, &ip_prefix_addr);
		if (ip_prefix_len < 0) {
			ret = -1;
			goto out;
		}

		ip_prefix_fib = add_prefix_fib(
			&ip_prefix_addr, ip_prefix_len, gk_conf);
		if (ip_prefix_fib == NULL) {
			ret = -1;
			goto out;
		}

		rte_memcpy(ip_prefix_fib, gt_fib, sizeof(*ip_prefix_fib));
		gt_fib->u.grantor.next_fib->ref_cnt++;

		/*
	 	 * XXX The nexthop MAC address should be
	 	 * initialized only after NICs start.
	 	 */
		break;
	}

	case GK_FWD_GATEWAY_FRONT_NET:
	case GK_FWD_GATEWAY_BACK_NET:
		/* Initialize the fib entry for the gateway. */
		ret = convert_str_to_ip(gk_fib->gateway, &gw_addr);
		if (ret < 0)
			goto out;

		ip_prefix_len = parse_ip_prefix(
			gk_fib->ip_prefix, &ip_prefix_addr);
		if (ip_prefix_len < 0) {
			ret = -1;
			goto out;
		}

		gw_fib = init_gateway_fib(
			&gw_addr, &ip_prefix_addr,
			ip_prefix_len, gk_fib->action, gk_conf);
		if (gw_fib == NULL) {
			ret = -1;
			goto out;
		}

		break;

	case GK_FWD_NEIGHBOR_FRONT_NET:
	case GK_FWD_NEIGHBOR_BACK_NET:
		/* FALLTHROUGH */
	case GK_DROP:
		/* Initialize the fib entry for the IP prefix. */
 		ip_prefix_len = parse_ip_prefix(
			gk_fib->ip_prefix, &ip_prefix_addr);
		if (ip_prefix_len < 0) {
			ret = -1;
			goto out;
		}

		ip_prefix_fib = add_prefix_fib(
			&ip_prefix_addr, ip_prefix_len, gk_conf);
		if (ip_prefix_fib == NULL) {
			ret = -1;
			goto out;
		}

		ip_prefix_fib->action = gk_fib->action;

		break;

	default:
		RTE_LOG(ERR, GATEKEEPER,
			"Unknown fib action %u\n",
			gk_fib->action);
		ret = -1;
		goto out;
	}

	RTE_LOG(NOTICE, GATEKEEPER,
		"gk: add a fib entry [ip prefix = %s, action = %u, grantor = %s, gateway = %s]\n",
		gk_fib->ip_prefix, gk_fib->action,
		gk_fib->grantor, gk_fib->gateway);

	ret = 0;
out:
	return ret;
}

static int
gk_stage1(void *arg)
{
	struct gk_config *gk_conf = arg;
	int ret, i;

	gk_conf->instances = rte_calloc(__func__, gk_conf->num_lcores,
		sizeof(struct gk_instance), 0);
	if (gk_conf->instances == NULL)
		goto cleanup;

	/*
	 * Set up the GK LPM table. We assume that
	 * all the GK instances are running on the same socket.
	 */
	ret = setup_gk_lpm(gk_conf,
		rte_lcore_to_socket_id(gk_conf->lcores[0]));
	if (ret < 0) {
		cleanup_gk(gk_conf);
		return -1;
	}

	for (i = 0; i < gk_conf->num_lcores; i++) {
		unsigned int lcore = gk_conf->lcores[i];
		struct gk_instance *inst_ptr = &gk_conf->instances[i];

		/* Set up queue identifiers for RSS. */

		ret = get_queue_id(&gk_conf->net->front, QUEUE_TYPE_RX, lcore);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER, "gk: cannot assign an RX queue for the front interface for lcore %u\n",
				lcore);
			goto cleanup;
		}
		inst_ptr->rx_queue_front = ret;

		ret = get_queue_id(&gk_conf->net->front, QUEUE_TYPE_TX, lcore);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER, "gk: cannot assign a TX queue for the front interface for lcore %u\n",
				lcore);
			return -1;
		}
		inst_ptr->tx_queue_front = ret;

		ret = get_queue_id(&gk_conf->net->back, QUEUE_TYPE_RX, lcore);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER, "gk: cannot assign an RX queue for the back interface for lcore %u\n",
				lcore);
			return -1;
		}
		inst_ptr->rx_queue_back = ret;

		ret = get_queue_id(&gk_conf->net->back, QUEUE_TYPE_TX, lcore);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER, "gk: cannot assign a TX queue for the back interface for lcore %u\n",
				lcore);
			goto cleanup;
		}
		inst_ptr->tx_queue_back = ret;

		/* Setup the GK instance at @lcore. */
		ret = setup_gk_instance(lcore, gk_conf);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER,
				"gk: failed to setup gk instances for GK block at lcore %u\n",
				lcore);
			goto cleanup;
		}
	}

	return 0;

cleanup:
	cleanup_gk(gk_conf);
	return -1;
}

static int
gk_stage2(void *arg)
{
	struct gk_config *gk_conf = arg;

	int ret = gk_setup_rss(gk_conf);
	if (ret < 0)
		goto cleanup;

	return 0;

cleanup:
	cleanup_gk(gk_conf);
	return ret;
}

/*
 * TODO Implement the addition of FIB entries in the dynamic configuration.
 */
int
run_gk(const char *front_net_prefix, const char *front_net_prefix6,
	const char *back_net_prefix, const char *back_net_prefix6,
	struct net_config *net_conf, struct gk_config *gk_conf)
{
	int ret, i;

	if (front_net_prefix == NULL || front_net_prefix6 == NULL ||
			back_net_prefix == NULL || back_net_prefix6 == NULL ||
			net_conf == NULL || gk_conf == NULL) {
		ret = -1;
		goto out;
	}

	if (!net_conf->back_iface_enabled) {
		RTE_LOG(ERR, GATEKEEPER, "gk: back interface is required\n");
		ret = -1;
		goto out;
	}

	gk_conf->net = net_conf;

	if (gk_conf->num_lcores <= 0)
		goto success;

	gk_conf->front_net_prefix = rte_malloc(
		"ipv4_front_network_prefix", strlen(front_net_prefix) + 1, 0);
	if (gk_conf->front_net_prefix == NULL) {
		RTE_LOG(ERR, MALLOC, "%s: Out of memory for IPv4 front network prefix\n",
			__func__);
		ret = -1;
		goto out;
	}
	strcpy(gk_conf->front_net_prefix, front_net_prefix);

	gk_conf->front_net_prefix6 = rte_malloc(
		"ipv6_front_network_prefix", strlen(front_net_prefix6) + 1, 0);
	if (gk_conf->front_net_prefix6 == NULL) {
		RTE_LOG(ERR, MALLOC, "%s: Out of memory for IPv6 front network prefix\n",
			__func__);
		ret = -1;
		goto out;
	}
	strcpy(gk_conf->front_net_prefix6, front_net_prefix6);

	gk_conf->back_net_prefix = rte_malloc(
		"ipv4_back_network_prefix", strlen(back_net_prefix) + 1, 0);
	if (gk_conf->back_net_prefix == NULL) {
		RTE_LOG(ERR, MALLOC, "%s: Out of memory for IPv4 back network prefix\n",
			__func__);
		ret = -1;
		goto out;
	}
	strcpy(gk_conf->back_net_prefix, back_net_prefix);

	gk_conf->back_net_prefix6 = rte_malloc(
		"ipv6_back_network_prefix", strlen(back_net_prefix6) + 1, 0);
	if (gk_conf->back_net_prefix6 == NULL) {
		RTE_LOG(ERR, MALLOC, "%s: Out of memory for IPv6 back network prefix\n",
			__func__);
		ret = -1;
		goto out;
	}
	strcpy(gk_conf->back_net_prefix6, back_net_prefix6);

	ret = net_launch_at_stage1(
		net_conf, gk_conf->num_lcores, gk_conf->num_lcores,
		gk_conf->num_lcores, gk_conf->num_lcores, gk_stage1, gk_conf);
	if (ret < 0)
		goto out;

	ret = launch_at_stage2(gk_stage2, gk_conf);
	if (ret < 0)
		goto stage1;

	for (i = 0; i < gk_conf->num_lcores; i++) {
		unsigned int lcore = gk_conf->lcores[i];
		ret = launch_at_stage3("gk", gk_proc, gk_conf, lcore);
		if (ret < 0) {
			pop_n_at_stage3(i);
			goto stage2;
		}
	}

	goto success;

stage2:
	pop_n_at_stage2(1);
stage1:
	pop_n_at_stage1(1);
out:
	return ret;

success:
	rte_atomic32_init(&gk_conf->ref_cnt);
	return 0;
}

struct mailbox *
get_responsible_gk_mailbox(const struct ip_flow *flow,
	const struct gk_config *gk_conf)
{
	/*
	 * Calculate the RSS hash value for the
	 * pair <Src, Dst> in the decision.
	 */
	uint32_t rss_hash_val = rss_ip_flow_hf(flow, 0, 0);
	uint32_t idx;
	uint32_t shift;
	uint16_t queue_id;
	int i, block_idx = -1;

	/*
	 * XXX Change the mapping rss hash value to rss reta entry
	 * if the reta size is not 128.
	 */
	RTE_VERIFY(gk_conf->rss_conf_front.reta_size == 128);
	rss_hash_val = (rss_hash_val & 127);

	/*
	 * Identify which GK block is responsible for the
	 * pair <Src, Dst> in the decision.
	 */
	idx = rss_hash_val / RTE_RETA_GROUP_SIZE;
	shift = rss_hash_val % RTE_RETA_GROUP_SIZE;
	queue_id = gk_conf->rss_conf_front.reta_conf[idx].reta[shift];

	/* XXX Change mapping queue id to the GK instance id efficiently. */
	for (i = 0; i < gk_conf->num_lcores; i++)
		if (gk_conf->instances[i].rx_queue_front == queue_id) {
			block_idx = i;
			break;
		}

	if (block_idx == -1)
		RTE_LOG(ERR, GATEKEEPER,
			"gk: wrong RSS configuration for GK blocks!\n");

	return &gk_conf->instances[block_idx].mb;
}
