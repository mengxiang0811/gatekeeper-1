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

#include <arpa/inet.h>
#include <lualib.h>
#include <lauxlib.h>

#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_log.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include "gatekeeper_ggu.h"
#include "gatekeeper_ipip.h"
#include "gatekeeper_gk.h"
#include "gatekeeper_gt.h"
#include "gatekeeper_main.h"
#include "gatekeeper_net.h"
#include "gatekeeper_launch.h"

/* TODO Get the install-path via Makefile. */
#define LUA_POLICY_BASE_DIR "./lua"
#define GRANTOR_CONFIG_FILE "policy.lua"

static int
get_block_idx(struct gt_config *gt_conf, unsigned int lcore_id)
{
	int i;
	for (i = 0; i < gt_conf->num_lcores; i++)
		if (gt_conf->lcores[i] == lcore_id)
			return i;
	rte_panic("Unexpected condition: lcore %u is not running a gt block\n",
		lcore_id);
	return 0;
}

static int
gt_setup_rss(struct gt_config *gt_conf)
{
	int i;
	uint8_t port_in = gt_conf->net->front.id;
	uint16_t gt_queues[gt_conf->num_lcores];

	for (i = 0; i < gt_conf->num_lcores; i++)
		gt_queues[i] = gt_conf->instances[i].rx_queue;

	return gatekeeper_setup_rss(port_in, gt_queues, gt_conf->num_lcores);
}

static void *
get_ip_hdr(struct rte_mbuf *m, uint8_t *ip_version)
{
	struct ipv4_hdr *ip4_hdr = rte_pktmbuf_mtod(m, struct ipv4_hdr *);

	*ip_version = (ip4_hdr->version_ihl & 0xF0) >> 4;
	if (*ip_version != 4 && *ip_version != 6)
		return NULL;

	return ip4_hdr;
}

static int
lookup_policy_decision(void *ip_hdr, uint8_t ip_version,
	struct ggu_policy *policy, struct gt_instance *instance)
{
	struct gt_match_fields mf;

	if (ip_version == 4) {
		struct ipv4_hdr *ip4_hdr = (struct ipv4_hdr *)ip_hdr;

		mf.proto = ETHER_TYPE_IPv4;
		mf.ip.v4 = ip4_hdr->dst_addr;

		if (ip4_hdr->next_proto_id == IPPROTO_TCP)
			mf.dest_port = rte_be_to_cpu_16(
				((struct tcp_hdr *)&ip4_hdr[1])->dst_port);
		else if (ip4_hdr->next_proto_id == IPPROTO_UDP)
			mf.dest_port = rte_be_to_cpu_16(
				((struct udp_hdr *)&ip4_hdr[1])->dst_port);
		else
			return -1;

		policy->flow.proto = ETHER_TYPE_IPv4;
		policy->flow.f.v4.src = ip4_hdr->src_addr;
		policy->flow.f.v4.dst = ip4_hdr->dst_addr;
	} else {
		struct ipv6_hdr *ip6_hdr = (struct ipv6_hdr *)ip_hdr;

		mf.proto = ETHER_TYPE_IPv6;
		rte_memcpy(mf.ip.v6, ip6_hdr->dst_addr, sizeof(mf.ip.v6));

		if (ip6_hdr->proto == IPPROTO_TCP)
			mf.dest_port = rte_be_to_cpu_16(
				((struct tcp_hdr *)&ip6_hdr[1])->dst_port);
		else if (ip6_hdr->proto == IPPROTO_UDP)
			mf.dest_port = rte_be_to_cpu_16(
				((struct udp_hdr *)&ip6_hdr[1])->dst_port);
		else
			return -1;

		policy->flow.proto = ETHER_TYPE_IPv6;
		rte_memcpy(policy->flow.f.v6.src, ip6_hdr->src_addr,
			sizeof(policy->flow.f.v6.src));
		rte_memcpy(policy->flow.f.v6.dst, ip6_hdr->dst_addr,
			sizeof(policy->flow.f.v6.dst));
	}

	lua_getglobal(instance->lua_state, "lookup_policy");
	lua_pushlightuserdata(instance->lua_state, &mf);
	lua_pushlightuserdata(instance->lua_state, policy);

	if (lua_pcall(instance->lua_state, 2, 0, 0) != 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"gt: error running function `lookup_policy': %s",
			lua_tostring(instance->lua_state, -1));
		return -1;
	}

	return 0;
}

static int
gt_proc(void *arg)
{
	unsigned int lcore = rte_lcore_id();
	struct gt_config *gt_conf = (struct gt_config *)arg;
	unsigned int block_idx = get_block_idx(gt_conf, lcore);
	struct gt_instance *instance = &gt_conf->instances[block_idx];

	uint8_t port = get_net_conf()->front.id;
	uint16_t rx_queue = instance->rx_queue;
	uint16_t tx_queue = instance->tx_queue;

	RTE_LOG(NOTICE, GATEKEEPER,
		"gt: the GT block is running at lcore = %u\n", lcore);

	gt_conf_hold(gt_conf);

	while (likely(!exiting)) {
		int i;
		uint16_t num_rx;
		uint16_t num_tx = 0;
		uint16_t num_tx_succ;
		struct rte_mbuf *rx_bufs[GATEKEEPER_MAX_PKT_BURST];
		struct rte_mbuf *tx_bufs[GATEKEEPER_MAX_PKT_BURST];

		/* Load a set of packets from the front NIC. */
		num_rx = rte_eth_rx_burst(port, rx_queue, rx_bufs,
			GATEKEEPER_MAX_PKT_BURST);

		if (unlikely(num_rx == 0))
			continue;

		for (i = 0; i < num_rx; i++) {
			int ret;
			uint8_t inner_ip_ver = 4;
			struct rte_mbuf *m = rx_bufs[i];
			void *ip_hdr;
			struct ggu_policy policy;
			struct ether_hdr *new_eth;

			/*
			 * TODO Decapsulate the packets.
			 *
			 * Only request packets and priority packets
			 * with capabilities about to expire go through a
			 * policy decision.
			 *
			 * Other packets will be fowarded directly.
			 */
			rte_pktmbuf_adj(m, sizeof(struct ether_hdr));

			ip_hdr = get_ip_hdr(m, &inner_ip_ver);
			if (ip_hdr == NULL) {
				rte_pktmbuf_free(m);
				continue;
			}

			/*
	 		 * Fill up the Ethernet header, and forward
			 * the original packet to the destination.
	 		 */
			new_eth = (struct ether_hdr *)
				rte_pktmbuf_prepend(
				m, sizeof(struct ether_hdr));
			ether_addr_copy(&gt_conf->net->front.eth_addr,
				&new_eth->s_addr);
	 		/*
			 * TODO The destination MAC address
			 * comes from LLS block.
			 */

			if (inner_ip_ver == 4)
				new_eth->ether_type =
					rte_cpu_to_be_16(ETHER_TYPE_IPv4);
			else
				new_eth->ether_type =
					rte_cpu_to_be_16(ETHER_TYPE_IPv6);

			/*
			 * Lookup the policy decision.
			 *
			 * The policy, which is defined by a Lua script,
			 * decides which capabilities to grant or decline,
			 * the maximum receiving rate of the granted
			 * capabilities, and when each decision expires.
			 *
			 * Notice that, the packet now only contains L3
			 * and above information.
			 */
			ret = lookup_policy_decision(ip_hdr,
				inner_ip_ver, &policy, instance);
			if (ret < 0) {
				rte_pktmbuf_free(m);
				continue;
			}

			if (policy.state == GK_GRANTED)
				tx_bufs[num_tx++] = m;
			else
				rte_pktmbuf_free(m);

			/* TODO Reply the policy decision to GK-GT unit. */
		}

		/* Send burst of TX packets, to second port of pair. */
		num_tx_succ = rte_eth_tx_burst(port, tx_queue,
			tx_bufs, num_tx);

		/*
		 * XXX Do something better here!
		 * For now, free any unsent packets.
		 */
		if (unlikely(num_tx_succ < num_tx)) {
			for (i = num_tx_succ; i < num_tx; i++)
				rte_pktmbuf_free(tx_bufs[i]);
		}
	}

	RTE_LOG(NOTICE, GATEKEEPER,
		"gt: the GT block at lcore = %u is exiting\n", lcore);

	return gt_conf_put(gt_conf);
}

struct gt_config *
alloc_gt_conf(void)
{
	return rte_calloc("gt_config", 1, sizeof(struct gt_config), 0);
}

static int
cleanup_gt(struct gt_config *gt_conf)
{
	rte_free(gt_conf->instances);
	rte_free(gt_conf->lcores);
	rte_free(gt_conf);

	return 0;
}

int
gt_conf_put(struct gt_config *gt_conf)
{
	/*
	 * Atomically decrements the atomic counter (v) by one and returns true 
	 * if the result is 0, or false in all other cases.
	 */
	if (rte_atomic32_dec_and_test(&gt_conf->ref_cnt))
		return cleanup_gt(gt_conf);

	return 0;
}

static int
config_gt_instance(struct gt_config *gt_conf, unsigned int lcore_id)
{
	int ret;
	char lua_entry_path[128];
	unsigned int block_idx = get_block_idx(gt_conf, lcore_id);
	struct gt_instance *instance = &gt_conf->instances[block_idx];

	ret = snprintf(lua_entry_path, sizeof(lua_entry_path), \
			"%s/%s", LUA_POLICY_BASE_DIR, GRANTOR_CONFIG_FILE);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(lua_entry_path));

	instance->lua_state = luaL_newstate();
	if (instance->lua_state == NULL) {
		RTE_LOG(ERR, GATEKEEPER,
			"gt: failed to create new Lua state at lcore %u!\n",
			lcore_id);
		ret = -1;
		goto out;
	}

	luaL_openlibs(instance->lua_state);
	set_lua_path(instance->lua_state, LUA_POLICY_BASE_DIR);
	ret = luaL_loadfile(instance->lua_state, lua_entry_path);
	if (ret != 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"gt: %s!\n", lua_tostring(instance->lua_state, -1));
		ret = -1;
		goto out;
	}

	/* Call functions to initialize the policy table. */
	ret = lua_pcall(instance->lua_state, 0, 0, 0);
	if (ret != 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"gt: %s!\n", lua_tostring(instance->lua_state, -1));
		ret = -1;
		goto out;
	}

	/* Push functions. */
	lua_getglobal(instance->lua_state, "setup_policy");
	lua_pushinteger(instance->lua_state, rte_lcore_to_socket_id(lcore_id));
	lua_pushinteger(instance->lua_state, lcore_id);

	if (lua_pcall(instance->lua_state, 2, 0, 0) != 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"gt: error running function `setup_policy', %s",
			lua_tostring(instance->lua_state, -1));
		ret = -1;
		goto out;
	}

	ret = 0;

out:
	return ret;
}

static int
init_gt_instances(struct gt_config *gt_conf)
{
	int i;
	int ret;
	int num_succ_instances = 0;
	struct gt_instance *inst_ptr;

	/* Set up queue identifiers now for RSS, before instances start. */
	for (i = 0; i < gt_conf->num_lcores; i++) {
		unsigned int lcore = gt_conf->lcores[i];
		inst_ptr = &gt_conf->instances[i];

		ret = get_queue_id(&gt_conf->net->front, QUEUE_TYPE_RX, lcore);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER, "gt: cannot assign an RX queue for the front interface for lcore %u\n",
				lcore);
			goto out;
		}
		inst_ptr->rx_queue = ret;

		ret = get_queue_id(&gt_conf->net->front, QUEUE_TYPE_TX, lcore);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER, "gt: cannot assign a TX queue for the front interface for lcore %u\n",
				lcore);
			goto out;
		}
		inst_ptr->tx_queue = ret;

		/*
		 * Set up the lua state for each instance,
		 * and initialize the policy tables.
		 */
		ret = config_gt_instance(gt_conf, lcore);
		if (ret < 0)
			goto free_lua_state;

		num_succ_instances++;
	}

	ret = 0;
	goto out;

free_lua_state:
	lua_close(inst_ptr->lua_state);
	inst_ptr->lua_state = NULL;
	for (i = 0; i < num_succ_instances; i++)
		lua_close(gt_conf->instances[i].lua_state);

out:
	return ret;
}

static int
gt_stage1(void *arg)
{
	int ret;
	struct gt_config *gt_conf = arg;

	gt_conf->instances = rte_calloc(__func__, gt_conf->num_lcores,
		sizeof(struct gt_instance), 0);
	if (gt_conf->instances == NULL) {
		ret = -1;
		goto out;
	}

	ret = init_gt_instances(gt_conf);
	if (ret < 0)
		goto  instance;

	goto out;

instance:
	rte_free(gt_conf->instances);
	gt_conf->instances = NULL;
	rte_free(gt_conf->lcores);
	gt_conf->lcores = NULL;
out:
	return ret;
}

static int
gt_stage2(void *arg)
{
	struct gt_config *gt_conf = arg;
	return gt_setup_rss(gt_conf);
}

int
run_gt(struct net_config *net_conf, struct gt_config *gt_conf)
{
	int ret, i;

	if (net_conf == NULL || gt_conf == NULL) {
		ret = -1;
		goto out;
	}

	gt_conf->net = net_conf;

	if (gt_conf->num_lcores <= 0)
		goto success;

	ret = net_launch_at_stage1(net_conf, gt_conf->num_lcores,
		gt_conf->num_lcores, 0, 0, gt_stage1, gt_conf);
	if (ret < 0)
		goto out;

	ret = launch_at_stage2(gt_stage2, gt_conf);
	if (ret < 0)
		goto stage1;

	for (i = 0; i < gt_conf->num_lcores; i++) {
		unsigned int lcore = gt_conf->lcores[i];
		ret = launch_at_stage3("gt", gt_proc, gt_conf, lcore);
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
	rte_atomic32_init(&gt_conf->ref_cnt);
	return 0;
}

int
lua_update_ipv4_lpm(struct rte_lpm *lpm,
	struct lua_ip_routes *routes, unsigned int num_routes)
{
	/* TODO Support Add/Delete routing entries. */

	int ret;
	unsigned int i;
	int num_ipv4_routes = 0;
	struct ipv4_lpm_route *ipv4_routes;

	ipv4_routes = rte_calloc(NULL, num_routes, sizeof(*ipv4_routes), 0);
	if (ipv4_routes == NULL) {
		ret = -1;
		goto out;
	}

	/* Parse all the routes. */
	for (i = 0; i < num_routes; i++) {
		struct in_addr ipv4_addr;
		int ip_type = get_ip_type(routes[i].ip_addr);
		if (ip_type == AF_INET) {
			if (inet_pton(AF_INET,
					routes[i].ip_addr, &ipv4_addr) != 1) {
				ret = -1;
				goto free_ipv4_routes;
			}

			ipv4_routes[num_ipv4_routes].ip =
				ipv4_addr.s_addr;
			ipv4_routes[num_ipv4_routes].depth =
				routes[i].prefix_len;
			ipv4_routes[num_ipv4_routes].policy_id =
				routes[i].policy_id;
			num_ipv4_routes++;
		} else {
			ret = -1;
			goto free_ipv4_routes;
		}
	}

	/* Update the IPv4 routes. */
	ret = lpm_add_ipv4_routes(lpm, ipv4_routes, num_ipv4_routes);
	if (ret < 0)
		goto free_ipv4_routes;

	ret = 0;

free_ipv4_routes:
	rte_free(ipv4_routes);

out:
	return ret;
}

int
lua_update_ipv6_lpm(struct rte_lpm6 *lpm,
	struct lua_ip_routes *routes, unsigned int num_routes)
{
	int ret;
	unsigned int i;
	int num_ipv6_routes = 0;
	struct ipv6_lpm_route *ipv6_routes;

	ipv6_routes = rte_calloc(NULL, num_routes, sizeof(*ipv6_routes), 0);
	if (ipv6_routes == NULL) {
		ret = -1;
		goto out;
	}

	/* Parse all the routes. */
	for (i = 0; i < num_routes; i++) {
		struct in6_addr ipv6_addr;
		int ip_type = get_ip_type(routes[i].ip_addr);
		if (ip_type == AF_INET6) {
			if (inet_pton(AF_INET6,
					routes[i].ip_addr, &ipv6_addr) != 1) {
				ret = -1;
				goto free_ipv6_routes;
			}

			rte_memcpy(ipv6_routes[num_ipv6_routes].ip,
				ipv6_addr.s6_addr,
				sizeof(ipv6_routes[num_ipv6_routes].ip));
			ipv6_routes[num_ipv6_routes].depth =
				routes[i].prefix_len;
			ipv6_routes[num_ipv6_routes].policy_id =
				routes[i].policy_id;
			num_ipv6_routes++;
		} else {
			ret = -1;
			goto free_ipv6_routes;
		}
	}

	ret = lpm_add_ipv6_routes(lpm, ipv6_routes, num_ipv6_routes);
	if (ret < 0)
		goto free_ipv6_routes;

	ret = 0;

free_ipv6_routes:
	rte_free(ipv6_routes);

out:
	return ret;
}
