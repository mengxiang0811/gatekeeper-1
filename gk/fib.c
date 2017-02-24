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

#include "gatekeeper_fib.h"
#include "gatekeeper_gk.h"
#include "gatekeeper_lls.h"
#include "gatekeeper_main.h"

void
destroy_neigh_hash_table(struct neighbor_hash_table *neigh)
{
	if (neigh->cache_tbl != NULL) {
		rte_free(neigh->cache_tbl);
		neigh->cache_tbl = NULL;
	}

	if (neigh->hash_table != NULL) {
		rte_hash_free(neigh->hash_table);
		neigh->hash_table = NULL;
	}
}

static int
gk_lpm_add_ipv4_route(uint32_t ip,
	uint8_t depth, uint32_t nexthop, struct gk_lpm *ltbl)
{
	int ret = rte_lpm_add(ltbl->lpm, ntohl(ip), depth, nexthop);
	if (ret < 0)
		return -1;

	ltbl->fib_tbl[nexthop].ref_cnt++;

	return 0;
}

static int
gk_lpm_add_ipv6_route(uint8_t *ip,
	uint8_t depth, uint32_t nexthop, struct gk_lpm *ltbl)
{
	int ret = rte_lpm6_add(ltbl->lpm6, ip, depth, nexthop);
	if (ret < 0)
		return -1;

	ltbl->fib_tbl6[nexthop].ref_cnt++;

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
	if (ip_addr == NULL) {
		RTE_LOG(ERR, GATEKEEPER,
			"gk: failed to parse IP address in IP prefix %s at %s\n",
			ip_prefix, __func__);
		return -1;
	}

	ip_type = get_ip_type(ip_addr);
	if (ip_type != AF_INET && ip_type != AF_INET6)
		return -1;

	prefix_len_str = strtok_r(NULL, "\0", &saveptr);
	if (prefix_len_str == NULL) {
		RTE_LOG(ERR, GATEKEEPER,
			"gk: failed to parse prefix length in IP prefix %s at %s\n",
			ip_prefix, __func__);
		return -1;
	}

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

	RTE_VERIFY((ip_type == AF_INET && res->proto == ETHER_TYPE_IPv4) ||
		(ip_type == AF_INET6 && res->proto == ETHER_TYPE_IPv6));

	return prefix_len;
}

/*
 * This function will return an empty FIB entry.
 */
static int
get_empty_fib_id(struct gk_fib *fib_tbl, struct gk_config *gk_conf)
{
	int i;

	RTE_VERIFY(fib_tbl == gk_conf->lpm_tbl.fib_tbl ||
		fib_tbl == gk_conf->lpm_tbl.fib_tbl6);

	for (i = 0; i < gk_conf->gk_max_num_fib_entries; i++) {
		if (fib_tbl[i].action == GK_FIB_MAX) {
			fib_tbl[i].ref_cnt = 0;
			return i; 
		}
	}

	if (fib_tbl == gk_conf->lpm_tbl.fib_tbl) {
		RTE_LOG(WARNING, GATEKEEPER,
			"gk: cannot find an empty fib entry in the IPv4 FIB table!\n");
	} else {
		RTE_LOG(WARNING, GATEKEEPER,
			"gk: cannot find an empty fib entry in the IPv6 FIB table!\n");
	}

	return -1;
}

/*
 * Add a prefix into the LPM table.
 * It returns the FIB entry for the prefix.
 */
static struct gk_fib *
add_prefix_fib(struct ipaddr *ip_addr,
	int prefix_len, struct gk_config *gk_conf)
{
	int ret;
	int fib_id = -1;
	struct gk_fib *new_fib = NULL;
	struct gk_lpm *ltbl = &gk_conf->lpm_tbl;

	/* Find an empty fib entry for the IP address. */
	if (ip_addr->proto == ETHER_TYPE_IPv4) {
		fib_id = get_empty_fib_id(ltbl->fib_tbl, gk_conf);
		if (fib_id < 0)
			return NULL;

		new_fib = &ltbl->fib_tbl[fib_id];

		/*
		 * Add the fib entry for the IPv4 address
		 * to the IPv4 LPM table.
		 */
		ret = gk_lpm_add_ipv4_route(
			ip_addr->ip.v4.s_addr, prefix_len, fib_id, ltbl);
		if (ret < 0)
			return NULL;
	} else if (likely(ip_addr->proto == ETHER_TYPE_IPv6)) {
		fib_id = get_empty_fib_id(ltbl->fib_tbl6, gk_conf);
		if (fib_id < 0)
			return NULL;

		new_fib = &ltbl->fib_tbl6[fib_id];

		/*
		 * Add the fib entry for the IPv6 address 
		 * to the IPv6 LPM table.
		 */
		ret = gk_lpm_add_ipv6_route(
			ip_addr->ip.v6.s6_addr, prefix_len, fib_id, ltbl);
		if (ret < 0)
			return NULL;
	}

	return new_fib;
}

static int
setup_neighbor_tbl(unsigned int socket_id, int identifier,
	int ip_ver, int ht_size, struct neighbor_hash_table *neigh)
{
	int  i, ret;
	char ht_name[64];
	int key_len = ip_ver == ETHER_TYPE_IPv4 ?
		sizeof(struct in_addr) : sizeof(struct in6_addr);

	struct rte_hash_parameters neigh_hash_params = {
		.entries = ht_size,
		.key_len = key_len,
		.hash_func = DEFAULT_HASH_FUNC,
		.hash_func_init_val = 0,
	};

	ret = snprintf(ht_name, sizeof(ht_name),
		"neighbor_hash_%u", identifier);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(ht_name));

	/* Setup the neighbor hash table. */
	neigh_hash_params.name = ht_name;
	neigh_hash_params.socket_id = socket_id;
	neigh->hash_table = rte_hash_create(&neigh_hash_params);
	if (neigh->hash_table == NULL) {
		RTE_LOG(ERR, HASH,
			"The GK block cannot create hash table for neighbor FIB!\n");

		ret = -1;
		goto out;
	}

	/* Setup the Ethernet header cache table. */
	neigh->cache_tbl = rte_calloc(NULL,
		ht_size, sizeof(struct ether_cache), 0);
	if (neigh->cache_tbl == NULL) {
		RTE_LOG(ERR, MALLOC,
			"The GK block cannot create Ethernet header cache table\n");

		ret = -1;
		goto neigh_hash;
	}

	/* Initialize the sequential lock for each Ethernet cache entry. */
	for (i = 0; i < ht_size; i++)
		seqlock_init(&neigh->cache_tbl[i].lock);

	ret = 0;
	goto out;

neigh_hash:
	rte_hash_free(neigh->hash_table);
	neigh->hash_table = NULL;
out:
	return ret;
}

/*
 * Setup the FIB entries for the network prefixes, for which @iface
 * is responsible.
 * These prefixes are configured when the Gatekeeper server starts.
 */
static int
setup_net_prefix_fib(int identifier,
	struct gatekeeper_if *iface, struct gk_config *gk_conf)
{
	int ret;
	int ip4_prefix_len, ip6_prefix_len;
	struct ipaddr addr4, addr6;
	unsigned int socket_id = rte_lcore_to_socket_id(gk_conf->lcores[0]);
	struct net_config *net_conf = gk_conf->net;
	struct gk_fib *fib[2] = { NULL, NULL };

	/* Set up the FIB entry for the IPv4 network prefix. */
	if (ipv4_if_configured(iface)) {
		addr4.proto = ETHER_TYPE_IPv4;
		rte_memcpy(&addr4.ip.v4,
			&iface->ip4_addr, sizeof(addr4.ip.v4));
		ip4_prefix_len = iface->ip4_addr_plen;

		fib[0] = add_prefix_fib(&addr4, ip4_prefix_len, gk_conf);
		if (fib[0] == NULL)
			return -1;

		if (iface == &net_conf->front) {
			fib[0]->action = GK_FWD_NEIGHBOR_FRONT_NET;
			gk_conf->neigh_fib_front = fib[0];
		} else if (likely(iface == &net_conf->back)) {
			fib[0]->action = GK_FWD_NEIGHBOR_BACK_NET;
			gk_conf->neigh_fib_back = fib[0];
		} else
			rte_panic("Unexpected condiction: invalid interface %s at %s!\n",
				iface->name, __func__);

		ret = setup_neighbor_tbl(socket_id, (identifier * 2),
			ETHER_TYPE_IPv4, (1 << (32 - ip4_prefix_len)),
			&fib[0]->u.neigh);
		if (ret < 0) {
			rte_lpm_delete(gk_conf->lpm_tbl.lpm,
				ntohl(addr4.ip.v4.s_addr), ip4_prefix_len);
			return -1;
		}
	}

	/* Set up the FIB entry for the IPv6 network prefix. */
	if (ipv6_if_configured(iface)) {
		addr6.proto = ETHER_TYPE_IPv6;
		rte_memcpy(&addr6.ip.v6,
			&iface->ip6_addr, sizeof(addr6.ip.v6));
		ip6_prefix_len = iface->ip6_addr_plen;

		fib[1] = add_prefix_fib(&addr6, ip6_prefix_len, gk_conf);
		if (fib[1] == NULL) {
			ret = -1;
			goto free_fib0;
		}

		if (iface == &net_conf->front) {
			fib[1]->action = GK_FWD_NEIGHBOR_FRONT_NET;
			gk_conf->neigh6_fib_front = fib[1];
		} else if (likely(iface == &net_conf->back)) {
			fib[1]->action = GK_FWD_NEIGHBOR_BACK_NET;
			gk_conf->neigh6_fib_back = fib[1];
		} else
			rte_panic("Unexpected condiction: invalid interface %s at %s!\n",
				iface->name, __func__);

		ret = setup_neighbor_tbl(socket_id, (identifier * 2 + 1),
			ETHER_TYPE_IPv6, gk_conf->max_num_ipv6_neighbors,
			&fib[1]->u.neigh6);
		if (ret < 0) {
			rte_lpm6_delete(gk_conf->lpm_tbl.lpm6,
				addr6.ip.v6.s6_addr, ip6_prefix_len);
			goto free_fib0;
		}
	}

	return 0;

free_fib0:
	if (fib[0] != NULL) {
		rte_lpm_delete(gk_conf->lpm_tbl.lpm,
			ntohl(addr4.ip.v4.s_addr), ip4_prefix_len);
		destroy_neigh_hash_table(&fib[0]->u.neigh);
	}

	return -1;
}

static int
init_fib_tbl(struct gk_config *gk_conf)
{
	int i;
	int ret;
	struct gk_lpm *ltbl = &gk_conf->lpm_tbl;

	rte_spinlock_init(&ltbl->lock);

	for (i = 0; i < gk_conf->gk_max_num_fib_entries; i++) {
		ltbl->fib_tbl[i].action = GK_FIB_MAX;
		rte_atomic16_init(&ltbl->fib_tbl[i].num_updated_instances);

		ltbl->fib_tbl6[i].action = GK_FIB_MAX;
		rte_atomic16_init(&ltbl->fib_tbl6[i].num_updated_instances);
	}

	/* Set up the FIB entry for the front network prefixes. */
	ret = setup_net_prefix_fib(0, &gk_conf->net->front, gk_conf);
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"gk: failed to setup the FIB entry for the front network prefixes at %s\n",
			__func__);
		goto out;
	}

	/* Set up the FIB entry for the back network prefixes. */
	if (gk_conf->net->back_iface_enabled) {
		ret = setup_net_prefix_fib(1, &gk_conf->net->back, gk_conf);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER,
				"gk: failed to setup the FIB entry for the back network prefixes at %s\n",
				__func__);
			goto free_front_fibs;
		}
	}

	ret = 0;
	goto out;

free_front_fibs:
	if (gk_conf->neigh_fib_front != NULL)
		destroy_neigh_hash_table(&gk_conf->neigh_fib_front->u.neigh);
	if (gk_conf->neigh6_fib_front != NULL)
		destroy_neigh_hash_table(&gk_conf->neigh6_fib_front->u.neigh6);

out:
	return ret;
}

/*
 * XXX Only instantiate the LPM tables needed, for example,
 * there's no need for an IPv6 LPM table in an IPv4-only deployment.
 */
int
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
		RTE_LOG(ERR, GATEKEEPER,
			"gk: failed to initialize the IPv4 LPM table at %s\n",
			__func__);
		ret = -1;
		goto out;
	}

	ltbl->fib_tbl = rte_calloc(NULL, gk_conf->gk_max_num_fib_entries,
		sizeof(struct gk_fib), 0);
	if (ltbl->fib_tbl == NULL) {
		RTE_LOG(ERR, MALLOC,
			"gk: failed to allocate the IPv4 FIB table at %s\n",
			__func__);
		ret = -1;
		goto free_lpm;
	}

	/*
	 * The GK blocks only need to create one single IPv6 LPM table
	 * on the @socket_id, so the @lcore and @identifier are set to 0.
	 */
	ltbl->lpm6 = init_ipv6_lpm("gk", &ipv6_lpm_config, socket_id, 0, 0);
	if (ltbl->lpm6 == NULL) {
		RTE_LOG(ERR, GATEKEEPER,
			"gk: failed to initialize the IPv6 LPM table at %s\n",
			__func__);
		ret = -1;
		goto free_lpm_tbl;
	}

	ltbl->fib_tbl6 = rte_calloc(NULL, gk_conf->gk_max_num_fib_entries,
		sizeof(struct gk_fib), 0);
	if (ltbl->fib_tbl6 == NULL) {
		RTE_LOG(ERR, MALLOC,
			"gk: failed to allocate the IPv6 FIB table at %s\n",
			__func__);
		ret = -1;
		goto free_lpm6;
	}

	ret = init_fib_tbl(gk_conf);
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"gk: failed to initialize the FIB table at %s\n",
			__func__);
		goto free_lpm_tbl6;
	}

	ret = 0;
	goto out;

free_lpm_tbl6:
	rte_free(ltbl->fib_tbl6);
	ltbl->fib_tbl6 = NULL;

free_lpm6:
	destroy_ipv6_lpm(ltbl->lpm6);

free_lpm_tbl:
	rte_free(ltbl->fib_tbl);
	ltbl->fib_tbl = NULL;

free_lpm:
	destroy_ipv4_lpm(ltbl->lpm);

out:
	return ret;
}

static void
notify_flow_flush(struct gk_fib *fib, struct gk_instance *instance)
{
	int ret;
	struct mailbox *mb = &instance->mb;
	struct gk_cmd_entry *entry = mb_alloc_entry(mb);
	if (entry == NULL) {
		RTE_LOG(ERR, GATEKEEPER,
			"gk: failed to allocate a `struct gk_cmd_entry` entry at %s\n",
			__func__);
		return;
	}

	entry->op = GK_FLUSH_FLOW_TABLE;
	entry->u.fib = fib;

	ret = mb_send_entry(mb, entry);
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"gk: failed to send a `struct gk_cmd_entry` entry at %s\n",
			__func__);
	}
}

/*
 * For removing FIB entries, once the field @ref_cnt
 * of a FIB entry becomes 0, then it needs to notify the GK instances
 * to flush the flows that have a reference to it. This can be
 * implemented by mailbox ring.
 */
static int
del_fib_entry_locked(const char *ip_prefix, struct gk_config *gk_conf)
{
	int i, ret = 0;
	int ip_prefix_present;
	int ip_prefix_len;
	struct ipaddr ip_prefix_addr;
	struct gk_fib *ip_prefix_fib;
	struct gk_lpm *ltbl = &gk_conf->lpm_tbl;

	if (ip_prefix == NULL)
		return -1;

 	ip_prefix_len = parse_ip_prefix(ip_prefix, &ip_prefix_addr);
	if (ip_prefix_len < 0)
		return -1;

	if (ip_prefix_addr.proto == ETHER_TYPE_IPv4) {
		uint32_t fib_id;

		ip_prefix_present = rte_lpm_is_rule_present(
			ltbl->lpm, ntohl(ip_prefix_addr.ip.v4.s_addr),
			ip_prefix_len, &fib_id);
		if (!ip_prefix_present) {
			RTE_LOG(WARNING, GATEKEEPER,
				"gk: delete an invalid IP prefix (%s)\n",
				ip_prefix);
			return -1;
		}

		ip_prefix_fib = &ltbl->fib_tbl[fib_id];
	} else if (ip_prefix_addr.proto == ETHER_TYPE_IPv6) {
		uint8_t fib_id;

		ip_prefix_present = rte_lpm6_is_rule_present(
			ltbl->lpm6, ip_prefix_addr.ip.v6.s6_addr,
			ip_prefix_len, &fib_id);
		if (!ip_prefix_present) {
			RTE_LOG(WARNING, GATEKEEPER,
				"gk: delete an invalid IP prefix (%s)\n",
				ip_prefix);
			return -1;
		}

		ip_prefix_fib = &ltbl->fib_tbl6[fib_id];
	} else {
		RTE_LOG(WARNING, GATEKEEPER,
			"gk: delete an invalid IP prefix (%s)\n",
			ip_prefix);
		return -1;
	}

	if (ip_prefix_fib->ref_cnt != 1) {
		RTE_LOG(ERR, GATEKEEPER,
			"gk: delete a fib entry [ip prefix = %s] with ref_cnt = %d, and action = %d\n",
			ip_prefix, ip_prefix_fib->ref_cnt,
			ip_prefix_fib->action);
		return -1;
	}

	if (ip_prefix_addr.proto == ETHER_TYPE_IPv4) {
		ret = rte_lpm_delete(ltbl->lpm,
			ntohl(ip_prefix_addr.ip.v4.s_addr), ip_prefix_len);
		if (ret < 0)
			return -1;
	} else {
		ret = rte_lpm6_delete(ltbl->lpm6,
			ip_prefix_addr.ip.v6.s6_addr, ip_prefix_len);
		if (ret < 0)
			return -1;
	}

	switch (ip_prefix_fib->action) {
	case GK_FWD_GRANTOR: {
		struct ip_flow *flow = &ip_prefix_fib->u.grantor.flow;
		struct ether_cache *eth_cache =
			ip_prefix_fib->u.grantor.eth_cache;

		/* Decrement the @ref_cnt of the @next_fib entry. */
		ip_prefix_fib->u.grantor.next_fib->ref_cnt--;

		write_seqlock(&eth_cache->lock);
		eth_cache->ref_cnt--;
		write_sequnlock(&eth_cache->lock);

		/*
		 * The Grantor is a neighbor, and the prefix
		 * is the Grantor. So, we need to release the @eth_cache
		 * Ethernet header entry from the neighbor hash table.
		 */
		if (ip_prefix_fib->u.grantor.next_fib->action ==
				GK_FWD_NEIGHBOR_BACK_NET) {
			/* Find the FIB entry for the Grantor. */
			struct gk_fib *neigh_fib;
			struct neighbor_hash_table *neigh_ht;

			if (flow->proto == ETHER_TYPE_IPv4 && flow->f.v4.dst ==
					ip_prefix_addr.ip.v4.s_addr) {
				/*
				 * The Ethernet header cache entry is still
				 * referenced by another prefix, so we cannot
				 * release this FIB entry.
				 */
				write_seqlock(&eth_cache->lock);
				if (eth_cache->ref_cnt != 0) {
					RTE_LOG(ERR, GATEKEEPER,
						"gk: delete a grantor neighbor fib entry [ip prefix = %s], however, its cached Ethernet header is referenced by other entries\n",
						ip_prefix);
					write_sequnlock(&eth_cache->lock);
					return -1;
				}
				write_sequnlock(&eth_cache->lock);

				/*
				 * Find the neighbor FIB entry
				 * that contains its @eth_cache.
				 */
				neigh_fib = ip_prefix_fib->u.grantor.next_fib;

				neigh_ht = &neigh_fib->u.neigh;
				ret = rte_hash_del_key(neigh_ht->hash_table,
					&flow->f.v4.dst);
				if (ret < 0) {
					RTE_LOG(ERR, GATEKEEPER,
						"gk: failed to delete the Ethernet cached header of the Grantor FIB entry for the IP prefix %s at %s\n",
						ip_prefix, __func__);
					return -1;
				}

				put_arp((struct in_addr *)&flow->f.v4.dst,
					gk_conf->lcores[0]);

				/*
				 * Add concurrency control to
				 * reset the Ethernet cache entry.
				 */
				write_seqlock(&eth_cache->lock);
				eth_cache->stale = false;
				memset(&eth_cache->eth_hdr, 0,
					sizeof(eth_cache->eth_hdr));
				eth_cache->ref_cnt = 0;
				write_sequnlock(&eth_cache->lock);
			} else if (flow->proto == ETHER_TYPE_IPv6 &&
					memcmp(flow->f.v6.dst,
					ip_prefix_addr.ip.v6.s6_addr,
					sizeof(ip_prefix_addr.ip.v6) == 0)) {
				/*
				 * The Ethernet header cache entry is still
				 * referenced by another prefix, so we cannot
				 * release this FIB entry.
				 */
				write_seqlock(&eth_cache->lock);
				if (eth_cache->ref_cnt != 0) {
					RTE_LOG(ERR, GATEKEEPER,
						"gk: delete a grantor neighbor fib entry [ip prefix = %s], however, its cached Ethernet header is referenced by other entries\n",
						ip_prefix);
					write_sequnlock(&eth_cache->lock);
					return -1;
				}
				write_sequnlock(&eth_cache->lock);

				/*
				 * Find the neighbor FIB entry
				 * that contains its @eth_cache.
				 */
				neigh_fib = ip_prefix_fib->u.grantor.next_fib;

				neigh_ht = &neigh_fib->u.neigh6;
				ret = rte_hash_del_key(neigh_ht->hash_table,
					flow->f.v6.dst);
				if (ret < 0) {
					RTE_LOG(ERR, GATEKEEPER,
						"gk: failed to delete the Ethernet cached header of the Grantor FIB entry for the IP prefix %s\n",
						ip_prefix);
					return -1;
				}

				put_nd((struct in6_addr *)flow->f.v6.dst,
					gk_conf->lcores[0]);

				/*
				 * Add concurrency control to
				 * reset the Ethernet cache entry.
				 */
				write_seqlock(&eth_cache->lock);
				eth_cache->stale = false;
				memset(&eth_cache->eth_hdr, 0,
					sizeof(eth_cache->eth_hdr));
				eth_cache->ref_cnt = 0;
				write_sequnlock(&eth_cache->lock);
			}
		}

		break;
	}

	case GK_FWD_GATEWAY_FRONT_NET:
		/* FALLTHROUGH */
	case GK_FWD_GATEWAY_BACK_NET: {
		struct ipaddr *gw_addr =
			&ip_prefix_fib->u.gateway.ip_addr;
		struct gk_fib *neigh_fib;
		struct neighbor_hash_table *neigh_ht;
		struct ether_cache *eth_cache =
			ip_prefix_fib->u.gateway.eth_cache;

		write_seqlock(&eth_cache->lock);
		eth_cache->ref_cnt--;
		write_sequnlock(&eth_cache->lock);

		/*
		 * Find the FIB entry for the gateway.
		 * We need to release the @eth_cache
		 * Ethernet header entry from the neighbor hash table.
		 */
		if (gw_addr->proto == ETHER_TYPE_IPv4 && gw_addr->ip.v4.s_addr
				== ip_prefix_addr.ip.v4.s_addr) {
			/*
			 * The Ethernet header cache entry is still
			 * referenced by another prefix, so we cannot
			 * release this FIB entry.
			 */
			write_seqlock(&eth_cache->lock);
			if (eth_cache->ref_cnt != 0) {
				RTE_LOG(ERR, GATEKEEPER,
					"gk: delete a gateway fib entry [ip prefix = %s], however, its cached Ethernet header is referenced by other entries\n",
					ip_prefix);
				write_sequnlock(&eth_cache->lock);
				return -1;
			}
			write_sequnlock(&eth_cache->lock);

			if (ip_prefix_fib->action == GK_FWD_GATEWAY_FRONT_NET)
				neigh_fib = gk_conf->neigh_fib_front;
			else
				neigh_fib = gk_conf->neigh_fib_back;

			neigh_ht = &neigh_fib->u.neigh;
			ret = rte_hash_del_key(neigh_ht->hash_table,
				&gw_addr->ip.v4.s_addr);
			if (ret < 0) {
				RTE_LOG(ERR, GATEKEEPER,
					"gk: failed to delete the Ethernet cached header for the IP prefix %s\n",
					ip_prefix);
				return -1;
			}

			put_arp((struct in_addr *)&gw_addr->ip.v4.s_addr,
				gk_conf->lcores[0]);

			/*
			 * Add concurrency control to
			 * reset the Ethernet cache entry.
			 */
			write_seqlock(&eth_cache->lock);
			eth_cache->stale = false;
			memset(&eth_cache->eth_hdr, 0,
				sizeof(eth_cache->eth_hdr));
			eth_cache->ref_cnt = 0;
			write_sequnlock(&eth_cache->lock);
		} else if (gw_addr->proto == ETHER_TYPE_IPv6 &&
				memcmp(gw_addr->ip.v6.s6_addr,
				ip_prefix_addr.ip.v6.s6_addr,
				sizeof(gw_addr->ip.v6) == 0)) {
			/*
			 * The Ethernet header cache entry is still
			 * referenced by another prefix, so we cannot
			 * release this FIB entry.
			 */
			write_seqlock(&eth_cache->lock);
			if (eth_cache->ref_cnt != 0) {
				RTE_LOG(ERR, GATEKEEPER,
					"gk: delete a gateway fib entry [ip prefix = %s], however, its cached Ethernet header is referenced by other entries\n",
					ip_prefix);
				write_sequnlock(&eth_cache->lock);
				return -1;
			}
			write_sequnlock(&eth_cache->lock);

			if (ip_prefix_fib->action == GK_FWD_GATEWAY_FRONT_NET)
				neigh_fib = gk_conf->neigh6_fib_front;
			else
				neigh_fib = gk_conf->neigh6_fib_back;

			neigh_ht = &neigh_fib->u.neigh6;
			ret = rte_hash_del_key(neigh_ht->hash_table,
				gw_addr->ip.v6.s6_addr);
			if (ret < 0) {
				RTE_LOG(ERR, GATEKEEPER,
					"gk: failed to delete the Ethernet cached header for the IP prefix %s\n",
					ip_prefix);
				return -1;
			}

			put_nd((struct in6_addr *)gw_addr->ip.v6.s6_addr,
				gk_conf->lcores[0]);

			/*
			 * Add concurrency control to
			 * reset the Ethernet cache entry.
			 */
			write_seqlock(&eth_cache->lock);
			eth_cache->stale = false;
			memset(&eth_cache->eth_hdr, 0,
				sizeof(eth_cache->eth_hdr));
			eth_cache->ref_cnt = 0;
			write_sequnlock(&eth_cache->lock);
		}

		break;
	}

	case GK_DROP:
		break;

	case GK_FWD_NEIGHBOR_FRONT_NET:
		/* FALLTHROUGH */
	case GK_FWD_NEIGHBOR_BACK_NET:
		/* FALLTHROUGH */
	default:
		return -1;
		break;
	}

	/*
	 * If the updated FIB entry doesn't have an action GK_FWD_GRANTOR,
	 * we don't need to flush the flow tables at all.
	 */
	if (ip_prefix_fib->action == GK_FWD_GRANTOR) {

		rte_atomic16_init(&ip_prefix_fib->num_updated_instances);

		/* Send the FIB entry to the GK mailboxes. */
		for (i = 0; i < gk_conf->num_lcores; i++) {
			notify_flow_flush(ip_prefix_fib,
				&gk_conf->instances[i]);
		}

		/*
		 * Wait until all the GK instances
		 * finish to flush their flow tables.
		 */
		while (rte_atomic16_read(&ip_prefix_fib->num_updated_instances)
				!= gk_conf->num_lcores)
			rte_pause();
	}

	/* Reset the fields of the deleted FIB entry. */
	ip_prefix_fib->action = GK_FIB_MAX;
	ip_prefix_fib->ref_cnt = 0;
	rte_atomic16_init(&ip_prefix_fib->num_updated_instances);
	memset(&ip_prefix_fib->u, 0, sizeof(ip_prefix_fib->u));

	RTE_LOG(NOTICE, GATEKEEPER,
		"gk: delete a fib entry [ip prefix = %s]\n", ip_prefix);

	return 0;
}

static inline struct ether_cache *
neigh_add_ether_cache(struct neighbor_hash_table *neigh, struct ipaddr *addr)
{
	struct ether_cache *eth_cache =
		lookup_ether_cache(neigh, &addr->ip);
	if (eth_cache == NULL) {
		int ret = rte_hash_add_key(neigh->hash_table, &addr->ip);
		if (ret >= 0)
			return &neigh->cache_tbl[ret];

		RTE_LOG(ERR, HASH,
			"Failed to add a cache entry to the neighbor hash table at %s\n",
			__func__);
		return NULL;
	}

	return eth_cache;
}

/*
 * Initialize a gateway FIB entry.
 * @gateway the gateway address informaiton.
 * @ip_prefix the IP prefix,
 * for which the gateway is responsible.
 */
static struct gk_fib *
init_gateway_fib(const char *ip_prefix, enum gk_fib_action action,
	const char *gateway, struct gk_config *gk_conf)
{
	int ret;
	int fib_id = -1;
	int ip_prefix_len;
	struct ipaddr gw_addr;
	struct ipaddr ip_prefix_addr;
	struct ether_cache *eth_cache;
	struct gk_fib *gw_fib = NULL;
	struct gk_fib *neigh_fib = NULL;
	struct gk_fib *ip_prefix_fib = NULL;
	struct gk_lpm *ltbl = &gk_conf->lpm_tbl;
	struct gatekeeper_if *iface;

	/* Initialize the fib entry for the gateway. */
	ret = convert_str_to_ip(gateway, &gw_addr);
	if (ret < 0)
		return NULL;

	ip_prefix_len = parse_ip_prefix(ip_prefix, &ip_prefix_addr);
	if (ip_prefix_len < 0)
		return NULL;

	if (gw_addr.proto != ip_prefix_addr.proto) {
		RTE_LOG(ERR, GATEKEEPER,
			"gk: failed to initialize a fib entry for gateway, since the gateway and its responsible grantors have different IP versions.\n");
		return NULL;
	}

	if (action == GK_FWD_GATEWAY_FRONT_NET)
		iface = &gk_conf->net->front;
	else if (likely(action == GK_FWD_GATEWAY_BACK_NET))
		iface = &gk_conf->net->back;
	else {
		rte_panic("gk: failed to initialize a fib entry for gateway, since it has invalid action %d.\n",
			action);
		return NULL;
	}

	/* Find the FIB entry for the gateway IP address. */
	if (gw_addr.proto == ETHER_TYPE_IPv4 &&
			ipv4_if_configured(iface)) {
		fib_id = lpm_lookup_ipv4(ltbl->lpm, gw_addr.ip.v4.s_addr);
		/*
		 * Invalid gateway entry, since at least we should
		 * obtain the FIB entry for the neighbor table.
		 */
		if (fib_id < 0)
			return NULL;

		neigh_fib = &ltbl->fib_tbl[fib_id];

		/*
		 * Invalid gateway entry, since the neighbor entry
		 * and the gateway entry should be in the same network.
		 */
		if ((action == GK_FWD_GATEWAY_FRONT_NET &&
				neigh_fib->action != GK_FWD_NEIGHBOR_FRONT_NET
				&& neigh_fib->action !=
				GK_FWD_GATEWAY_FRONT_NET)
				|| (action == GK_FWD_GATEWAY_BACK_NET &&
				neigh_fib->action != GK_FWD_NEIGHBOR_BACK_NET &&
				neigh_fib->action != GK_FWD_GATEWAY_BACK_NET)) {
			return NULL;
		}

		/* The gateway FIB entry exists. */
		if (neigh_fib->action == action)
			return neigh_fib;

		/* Create a new FIB entry for the gateway. */
		gw_fib = add_prefix_fib(&gw_addr,
			(sizeof(struct in_addr) * 8), gk_conf);
		if (gw_fib == NULL)
			return NULL;

		eth_cache = neigh_add_ether_cache(
			&neigh_fib->u.neigh, &gw_addr);
		if (eth_cache == NULL) {
			rte_lpm_delete(ltbl->lpm,
				ntohl(gw_addr.ip.v4.s_addr),
				(sizeof(struct in_addr) * 8));
			return NULL;
		}
	} else if (likely(gw_addr.proto == ETHER_TYPE_IPv6)
			&& ipv6_if_configured(iface)) {
		fib_id = lpm_lookup_ipv6(ltbl->lpm6, gw_addr.ip.v6.s6_addr);
		/*
		 * Invalid gateway entry, since at least we should
		 * obtain the FIB entry for the neighbor table.
		 */
		if (fib_id < 0)
			return NULL;

		neigh_fib = &ltbl->fib_tbl6[fib_id];

		/*
		 * Invalid gateway entry, since the neighbor entry
		 * and the gateway entry should be in the same network.
		 */
		if ((action == GK_FWD_GATEWAY_FRONT_NET &&
				neigh_fib->action != GK_FWD_NEIGHBOR_FRONT_NET
				&& neigh_fib->action !=
				GK_FWD_GATEWAY_FRONT_NET)
				|| (action == GK_FWD_GATEWAY_BACK_NET &&
				neigh_fib->action != GK_FWD_NEIGHBOR_BACK_NET &&
				neigh_fib->action != GK_FWD_GATEWAY_BACK_NET)) {
			return NULL;
		}

		/* The gateway FIB entry exists. */
		if (neigh_fib->action == action)
			return neigh_fib;

		/* Create a new FIB entry for the gateway. */
		gw_fib = add_prefix_fib(&gw_addr,
			(sizeof(struct in6_addr) * 8), gk_conf);
		if (gw_fib == NULL)
			return NULL;

		eth_cache = neigh_add_ether_cache(
			&neigh_fib->u.neigh6, &gw_addr);
		if (eth_cache == NULL) {
			rte_lpm6_delete(ltbl->lpm6,
				gw_addr.ip.v6.s6_addr,
				(sizeof(struct in6_addr) * 8));
			return NULL;
		}
	} else
		rte_panic("Unexpected condiction: invalid IP type %hu at interface %s!\n",
			gw_addr.proto, iface->name);

	/* Fill up the fib entry for the gateway. */
	gw_fib->action = action;

	rte_memcpy(&gw_fib->u.gateway.ip_addr,
		&gw_addr, sizeof(gw_fib->u.gateway.ip_addr));

	gw_fib->u.gateway.eth_cache = eth_cache;

	write_seqlock(&eth_cache->lock);
	eth_cache->stale = true;
	eth_cache->eth_hdr.ether_type = gw_addr.proto;

	if (action == GK_FWD_GATEWAY_FRONT_NET) {
		ether_addr_copy(&gk_conf->net->front.eth_addr,
			&eth_cache->eth_hdr.s_addr);
	} else {
		ether_addr_copy(&gk_conf->net->back.eth_addr,
			&eth_cache->eth_hdr.s_addr);
	}

	eth_cache->ref_cnt++;
	write_sequnlock(&eth_cache->lock);

	/*
	 * Add a fib entry for the IP prefix,
	 * for which the gateway is responsible.
	 *
	 * Notice, for this fib, it doesn't need to initialize the
	 * fields @flow and @eth_cache, since it's only used to help
	 * lookup the fib entry for the gateway.
	 */
	ip_prefix_fib = add_prefix_fib(
		&ip_prefix_addr, ip_prefix_len, gk_conf);
	if (ip_prefix_fib != NULL) {
		/* Fills up the FIB entry for the IP prefix. */
		ip_prefix_fib->action = action;
		rte_memcpy(&ip_prefix_fib->u.gateway.ip_addr,
			&gw_addr, sizeof(ip_prefix_fib->u.gateway.ip_addr));

		ip_prefix_fib->u.gateway.eth_cache = eth_cache;

		write_seqlock(&eth_cache->lock);
		eth_cache->ref_cnt++;
		write_sequnlock(&eth_cache->lock);
	} else {
		del_fib_entry(gateway, gk_conf);
		return NULL;
	}

	return gw_fib;
}

static struct gk_fib *
init_grantor_fib(const char *ip_prefix,
	const char *grantor, struct gk_config *gk_conf)
{
	int ret;
	int prefix_len;
	int gt_fib_present;
	int ip_prefix_len;
	struct ipaddr ip_prefix_addr;
	struct ipaddr gt_addr;
	struct ip_flow *flow;
	struct gk_fib *gt_fib = NULL;
	struct gk_fib *gt_prefix_fib = NULL;
	struct gk_fib *ip_prefix_fib;
	struct gk_lpm *ltbl = &gk_conf->lpm_tbl;
	struct ether_cache *eth_cache;

	/* Initialize the fib entry for the Grantor. */
	ret = convert_str_to_ip(grantor, &gt_addr);
	if (ret < 0)
		return NULL;

	ip_prefix_len = parse_ip_prefix(ip_prefix, &ip_prefix_addr);
	if (ip_prefix_len < 0)
		return NULL;

	/*
	 * Find the FIB entry for the Grantor IP prefix.
	 *
	 * There must be an entry for it:
	 * (1) The FIB entry for the Grantor exists.
	 * (2) A FIB entry for the Grantor prefix.
	 * (3) The Grantor is a neighbor, so it has a neighbor FIB entry.
	 */
	if (gt_addr.proto == ETHER_TYPE_IPv4 &&
			ipv4_if_configured(&gk_conf->net->back)) {
		uint32_t fib_id;

		prefix_len = sizeof(struct in_addr) * 8;

		gt_fib_present = rte_lpm_is_rule_present(
			ltbl->lpm, ntohl(gt_addr.ip.v4.s_addr),
			prefix_len, &fib_id);

		ret = lpm_lookup_ipv4(ltbl->lpm, gt_addr.ip.v4.s_addr);
		if (ret >= 0)
			gt_prefix_fib = &ltbl->fib_tbl[ret];
	} else if (likely(gt_addr.proto == ETHER_TYPE_IPv6) &&
			ipv6_if_configured(&gk_conf->net->back)) {
		uint8_t fib_id;

		prefix_len = sizeof(struct in6_addr) * 8;

		gt_fib_present = rte_lpm6_is_rule_present(
			ltbl->lpm6, gt_addr.ip.v6.s6_addr,
			prefix_len, &fib_id);

		ret = lpm_lookup_ipv6(ltbl->lpm6, gt_addr.ip.v6.s6_addr);
		if (ret >= 0)
			gt_prefix_fib = &ltbl->fib_tbl6[ret];
	} else
		rte_panic("Unexpected condiction: invalid IP type %hu at interface %s!\n",
			gt_addr.proto, gk_conf->net->back.name);

	if (gt_prefix_fib == NULL)
		return NULL;

	/* It's the FIB entry for the Grantor. */
	if (gt_fib_present)
		return gt_prefix_fib;

	if ((gt_prefix_fib->action != GK_FWD_GATEWAY_BACK_NET &&
			gt_prefix_fib->action != GK_FWD_NEIGHBOR_BACK_NET)) {
		return NULL;
	}

	gt_fib = add_prefix_fib(&gt_addr, prefix_len, gk_conf);
	if (gt_fib == NULL)
		return NULL;

	gt_fib->action = GK_FWD_GRANTOR;
	flow = &gt_fib->u.grantor.flow;

	if (gt_addr.proto == ETHER_TYPE_IPv4) {
		flow->proto = ETHER_TYPE_IPv4;
		flow->f.v4.src = gk_conf->net->back.ip4_addr.s_addr;
		flow->f.v4.dst = gt_addr.ip.v4.s_addr;
	} else {
		flow->proto = ETHER_TYPE_IPv6;
		rte_memcpy(flow->f.v6.src,
			gk_conf->net->back.ip6_addr.s6_addr,
			sizeof(flow->f.v6.src));
		rte_memcpy(flow->f.v6.dst,
			gt_addr.ip.v6.s6_addr, sizeof(flow->f.v6.dst));
	}

	/* Fill up the @next_fib field in the @gt_fib. */

	/*
	 * The Grantor server is not an neighbor.
	 * So the @next_fib needs to point to the
	 * responsbile gateway entry.
	 */
	if (gt_prefix_fib->action == GK_FWD_GATEWAY_BACK_NET) {
		gt_fib->u.grantor.next_fib = gt_prefix_fib;
		gt_fib->u.grantor.next_fib->ref_cnt++;
		gt_fib->u.grantor.eth_cache =
			gt_prefix_fib->u.gateway.eth_cache;

		write_seqlock(&gt_fib->u.grantor.eth_cache->lock);
		gt_fib->u.grantor.eth_cache->ref_cnt++;
		write_sequnlock(&gt_fib->u.grantor.eth_cache->lock);

		goto out;
	}

	/* The Grantor server is an neighbor. */
	if (gt_addr.proto == ETHER_TYPE_IPv4) {
		eth_cache = neigh_add_ether_cache(
			&gt_prefix_fib->u.neigh, &gt_addr);
		if (eth_cache == NULL) {
			rte_lpm_delete(ltbl->lpm,
				ntohl(gt_addr.ip.v4.s_addr),
				(sizeof(struct in_addr) * 8));
			return NULL;
		}
	} else {
		eth_cache = neigh_add_ether_cache(
			&gt_prefix_fib->u.neigh6, &gt_addr);
		if (eth_cache == NULL) {
			rte_lpm6_delete(ltbl->lpm6,
				gt_addr.ip.v6.s6_addr,
				(sizeof(struct in6_addr) * 8));
			return NULL;
		}
	}

	write_seqlock(&eth_cache->lock);
	eth_cache->stale = true;
	eth_cache->eth_hdr.ether_type = gt_addr.proto;

	/* Grantor server must be forwarded to the back network. `*/
	ether_addr_copy(&gk_conf->net->back.eth_addr,
		&eth_cache->eth_hdr.s_addr);

	eth_cache->ref_cnt++;
	write_sequnlock(&eth_cache->lock);

	gt_fib->u.grantor.eth_cache = eth_cache;
	gt_fib->u.grantor.next_fib = gt_prefix_fib;
	gt_fib->u.grantor.next_fib->ref_cnt++;

out:
	/* Initialize the fib entry for the IP prefix. */
	ip_prefix_fib = add_prefix_fib(
		&ip_prefix_addr, ip_prefix_len, gk_conf);
	if (ip_prefix_fib != NULL) {
		/* Fills up the FIB entry for the IP prefix. */
		ip_prefix_fib->action = GK_FWD_GRANTOR;
		rte_memcpy(&ip_prefix_fib->u,
			&gt_fib->u, sizeof(ip_prefix_fib->u));

		write_seqlock(&ip_prefix_fib->u.grantor.eth_cache->lock);
		ip_prefix_fib->u.grantor.eth_cache->ref_cnt++;
		write_sequnlock(&ip_prefix_fib->u.grantor.eth_cache->lock);

		gt_fib->u.grantor.next_fib->ref_cnt++;
	} else {
		del_fib_entry(grantor, gk_conf);
		return NULL;
	}

	return gt_fib;
}

static void
gk_arp_and_nd_req_cb(const struct lls_map *map, void *arg,
	__attribute__((unused))enum lls_reply_ty ty, int *pcall_again)
{
	struct ether_cache *eth_cache = arg;

	/*
	 * Deal with concurrency control by sequential lock
	 * on the nexthop entry.
	 */
	write_seqlock(&eth_cache->lock);

	if (!map->stale) {
		ether_addr_copy(&map->ha, &eth_cache->eth_hdr.d_addr);
		eth_cache->stale = false;
	} else
		eth_cache->stale = true;

	write_sequnlock(&eth_cache->lock);

	if (pcall_again != NULL)
		*pcall_again = true;
}

static int
gk_hold_arp_and_nd(struct gk_fib *fib, unsigned int lcore_id)
{
	int ret;
	void *ipv4;
	void *ipv6;
	unsigned seq;
	uint16_t ether_type;
	struct ether_cache *eth_cache;

	/*
	 * Fib entry with action GK_FWD_GATEWAY_*_NET should
	 * directly hold on the @nexthop field.
	 *
	 * Fib entry with action GK_FWD_GRANTOR should
	 * be held according to its @next_fib field.
	 *
	 * Other fib entries won't reach here.
	 */
	if (fib->action == GK_FWD_GATEWAY_FRONT_NET ||
			fib->action == GK_FWD_GATEWAY_BACK_NET) {
		eth_cache = fib->u.gateway.eth_cache;
		ipv4 = &fib->u.gateway.ip_addr.ip.v4;
		ipv6 = &fib->u.gateway.ip_addr.ip.v6;
	} else if (fib->action == GK_FWD_GRANTOR) {
		/* The @next_fib indicates it's an gateway or an neighbor. */
		if (fib->u.grantor.next_fib->action == GK_FWD_GATEWAY_FRONT_NET ||
				fib->u.grantor.next_fib->action ==
				GK_FWD_GATEWAY_BACK_NET) {
			eth_cache = fib->u.grantor.
				next_fib->u.gateway.eth_cache;
			ipv4 = &fib->u.grantor.
				next_fib->u.gateway.ip_addr.ip.v4;
			ipv6 = &fib->u.grantor.
				next_fib->u.gateway.ip_addr.ip.v6;
		} else if (fib->u.grantor.next_fib->action ==
				GK_FWD_NEIGHBOR_FRONT_NET ||
				fib->u.grantor.next_fib->action ==
				GK_FWD_NEIGHBOR_BACK_NET) {
			eth_cache = fib->u.grantor.eth_cache;
			ipv4 = &fib->u.grantor.flow.f.v4.dst;
			ipv6 = fib->u.grantor.flow.f.v6.dst;
		} else
			rte_panic("Unexpected condition at %s: the gk fib @next_fib has unknown action (%d) for holding arp or nd!\n",
				__func__, fib->u.grantor.next_fib->action);
	} else
		rte_panic("Unexpected condition at %s: the gk fib has unknown action (%d) for holding arp or nd!\n",
			__func__, fib->action);

	do {
		seq = read_seqbegin(&eth_cache->lock);
		ether_type = eth_cache->eth_hdr.ether_type;
	} while (read_seqretry(&eth_cache->lock, seq));

	if (ether_type == ETHER_TYPE_IPv4) {
		ret = hold_arp(gk_arp_and_nd_req_cb,
			eth_cache, ipv4, lcore_id);
		if (ret < 0)
			return ret;
	} else if (likely(ether_type == ETHER_TYPE_IPv6)) {
		ret = hold_nd(gk_arp_and_nd_req_cb,
			eth_cache, ipv6, lcore_id);
		if (ret < 0)
			return ret;
	} else
		rte_panic("Unexpected condition at %s: the nexthop information has unknown network type %hu\n",
			__func__, ether_type);

	return 0;
}

static struct gk_fib *
init_drop_fib(const char *ip_prefix, struct gk_config *gk_conf)
{
	struct ipaddr ip_prefix_addr;
	int ip_prefix_len;
	struct gk_fib *ip_prefix_fib;

	/* Initialize the fib entry for the IP prefix. */
	ip_prefix_len = parse_ip_prefix(ip_prefix, &ip_prefix_addr);
	if (ip_prefix_len < 0)
		return NULL;

	ip_prefix_fib = add_prefix_fib(
		&ip_prefix_addr, ip_prefix_len, gk_conf);
	if (ip_prefix_fib == NULL)
		return NULL;

	ip_prefix_fib->action = GK_DROP;

	return ip_prefix_fib;
}

static int
add_fib_entry_locked(const char *ip_prefix, enum gk_fib_action action,
	const char *grantor_or_gateway, struct gk_config *gk_conf)
{
	if (ip_prefix == NULL || grantor_or_gateway == NULL)
		return -1;

	switch (action) {
	case GK_FWD_GRANTOR: {

		int ret;
		struct gk_fib *gt_fib = init_grantor_fib(
			ip_prefix, grantor_or_gateway, gk_conf);
		if (gt_fib == NULL)
			return -1;

		/*
		 * Take care of the LLS communication
		 * while editing the LPM table.
		 *
		 * Notice, we only need to do the LLS communication
		 * when editing the nexthop fibs.
		 *
		 * We use the first lcore id as the parameter
		 * to request the resolution.
		 */
		ret = gk_hold_arp_and_nd(gt_fib, gk_conf->lcores[0]);
		if (ret < 0)
			return -1;

		break;
	}

	case GK_FWD_GATEWAY_FRONT_NET:
		/* FALLTHROUGH */
	case GK_FWD_GATEWAY_BACK_NET: {

		int ret;
		struct gk_fib *gw_fib = init_gateway_fib(ip_prefix,
			action, grantor_or_gateway, gk_conf);
		if (gw_fib == NULL)
			return -1;

		/*
		 * Take care of the LLS communication
		 * while editing the LPM table.
		 *
		 * Notice, we only need to do the LLS communication
		 * when editing the nexthop fibs.
		 *
		 * We use the first lcore id as the parameter
		 * to request the resolution.
		 */
		ret = gk_hold_arp_and_nd(gw_fib, gk_conf->lcores[0]);
		if (ret < 0)
			return -1;

		break;
	}

	case GK_DROP: {

		struct gk_fib *ip_prefix_fib =
			init_drop_fib(ip_prefix, gk_conf);
		if (ip_prefix_fib == NULL)
			return -1;

		break;
	}

	case GK_FWD_NEIGHBOR_FRONT_NET:
		/* FALLTHROUGH */
	case GK_FWD_NEIGHBOR_BACK_NET:
		/* FALLTHROUGH */
	default:
		RTE_LOG(ERR, GATEKEEPER,
			"Invalid fib action %u at %s\n", action, __func__);
		return -1;
		break;
	}

	RTE_LOG(NOTICE, GATEKEEPER,
		"gk: add a fib entry [ip prefix = %s, action = %u, grantor_or_gateway = %s]\n",
		ip_prefix, action, grantor_or_gateway);

	return 0;
}

int
add_fib_entry(const char *ip_prefix, enum gk_fib_action action,
	const char *grantor_or_gateway, struct gk_config *gk_conf)
{
	int ret;

	rte_spinlock_lock_tm(&gk_conf->lpm_tbl.lock);
	ret = add_fib_entry_locked(ip_prefix, action,
		grantor_or_gateway, gk_conf);
	rte_spinlock_unlock_tm(&gk_conf->lpm_tbl.lock);

	return ret;
}

int
del_fib_entry(const char *ip_prefix, struct gk_config *gk_conf)
{
	int ret;

	rte_spinlock_lock_tm(&gk_conf->lpm_tbl.lock);
	ret = del_fib_entry_locked(ip_prefix, gk_conf);
	rte_spinlock_unlock_tm(&gk_conf->lpm_tbl.lock);

	return ret;
}
