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

#include <rte_log.h>
#include <rte_debug.h>

#include "gatekeeper_lpm.h"
#include "gatekeeper_main.h"

int
init_lpm_rt(const char *tag,
	const struct rte_lpm_config *lpm_conf,
	const struct rte_lpm6_config *lpm6_conf,
	unsigned int socket_id, unsigned int identifier, struct lpm_rt *rt)
{
	int i;
	int ret;
	int num_succ_ipv4 = 0;
	int num_succ_ipv6 = 0;
	char lpm_name[128];

	ret = snprintf(rt->tag,
		sizeof(rt->tag), "%s_lpm_%u", tag, identifier);
	RTE_ASSERT(ret < sizeof(rt->tag));

	for (i = 0; i < 2; i++) {
		ret = snprintf(lpm_name, sizeof(lpm_name),
			"%s_lpm_%u_ipv4_%d", tag, identifier, i);
		RTE_ASSERT(ret < sizeof(lpm_name));

		rt->ipv4_rt[i] = rte_lpm_create(lpm_name, socket_id, lpm_conf);
		if (rt->ipv4_rt[i] == NULL) {
			RTE_LOG(ERR, GATEKEEPER,
				"Unable to create the IPv4 LPM table %s on socket %u!\n",
				lpm_name, socket_id);
			ret = -1;
			goto free_lpm4;
		}

		num_succ_ipv4++;
	}

	for (i = 0; i < 2; i++) {
		ret = snprintf(lpm_name, sizeof(lpm_name),
			"%s_lpm_%u_ipv6_%d", tag, identifier, i);
		RTE_ASSERT(ret < sizeof(lpm_name));

		rt->ipv6_rt[i] =
			rte_lpm6_create(lpm_name, socket_id, lpm6_conf);
		if (rt->ipv6_rt[i] == NULL) {
			RTE_LOG(ERR, GATEKEEPER,
				"Unable to create the IPv6 LPM table %s on socket %u!\n",
				lpm_name, socket_id);
			ret = -1;
			goto free_lpm6;
		}

		num_succ_ipv6++;
	}

	rte_atomic16_set(&rt->ipv4_aidx, 0);
	rte_atomic16_set(&rt->ipv6_aidx, 0);

	ret = 0;
	goto out;

free_lpm6:
	for (i = 0; i < num_succ_ipv6; i++) {
		rte_lpm6_free(rt->ipv6_rt[i]);
		rt->ipv6_rt[i] = NULL;
	}
free_lpm4:
	for (i = 0; i < num_succ_ipv4; i++) {
		rte_lpm_free(rt->ipv4_rt[i]);
		rt->ipv4_rt[i] = NULL;
	}
out:
	return ret;
}

static int
__lpm_rt_add_ipv4_routes(
	struct rte_lpm *lookup_structure,
	struct ipv4_lpm_route *routes, unsigned int num_routes)
{
	int ret = 0;
	unsigned int i;
	for (i = 0; i < num_routes; i++) {
		ret = rte_lpm_add(lookup_structure, routes[i].ip,
			routes[i].depth, routes[i].policy_id);
		if (ret < 0)
			goto out;
	}

out:
	return ret;
}

int
lpm_rt_add_ipv4_routes(struct lpm_rt *rt,
	struct ipv4_lpm_route *routes, unsigned int num_routes)
{
	int ret = 0;
	/* Index of the lookup structure for update. */
	int16_t uidx = 1 - rte_atomic16_read(&rt->ipv4_aidx);
	ret = __lpm_rt_add_ipv4_routes(rt->ipv4_rt[uidx], routes, num_routes);
	if (ret < 0) {
		RTE_LOG(ERR, LPM,
			"Unable to add an IPv4 entry to the LPM table %s_ipv4_%d!\n",
			rt->tag, uidx);
		goto out;
	}

	/*
	 * After updating the backup lookup structure,
	 * we need to switch the two lookup structures
	 * and update the previous active one, so that
	 * both have the same entries.
	 */
	rte_atomic16_set(&rt->ipv4_aidx, uidx);
	uidx = 1 - uidx;

	ret = __lpm_rt_add_ipv4_routes(rt->ipv4_rt[uidx], routes, num_routes);
	if (ret < 0) {
		RTE_LOG(ERR, LPM,
			"Unable to add an IPv4 entry to the LPM table %s_ipv4_%d!\n",
			rt->tag, uidx);
		goto out;
	}

out:
	return ret;
}

int
lpm_rt_lookup_ipv4(struct lpm_rt *rt, uint32_t ip)
{
	int ret;
	uint32_t next_hop;

	ret = rte_lpm_lookup(
		rt->ipv4_rt[rte_atomic16_read(&rt->ipv4_aidx)],
		ip, &next_hop);
	if (ret == -EINVAL) {
		RTE_LOG(ERR, LPM,
			"lpm: incorrect arguments for IPv4 lookup!\n");
		ret = -1;
		goto out;
	} else if (ret == -ENOENT) {
		RTE_LOG(WARNING, LPM, "lpm: IPv4 lookup miss!\n");
		ret = -1;
		goto out;
	}

	ret = next_hop;

out:
	return ret;
}

static int
__lpm_rt_add_ipv6_routes(
	struct rte_lpm6 *lookup_structure,
	struct ipv6_lpm_route *routes, unsigned int num_routes)
{
	int ret = 0;
	unsigned int i;
	for (i = 0; i < num_routes; i++) {
		ret = rte_lpm6_add(lookup_structure, routes[i].ip,
			routes[i].depth, routes[i].policy_id);
		if (ret < 0)
			goto out;
	}

out:
	return ret;
}

int
lpm_rt_add_ipv6_routes(struct lpm_rt *rt,
	struct ipv6_lpm_route *routes, unsigned int num_routes)
{
	int ret = 0;
	/* Index of the lookup structure for update. */
	int16_t uidx = 1 - rte_atomic16_read(&rt->ipv6_aidx);
	ret = __lpm_rt_add_ipv6_routes(rt->ipv6_rt[uidx], routes, num_routes);
	if (ret < 0) {
		RTE_LOG(ERR, LPM,
			"Unable to add an IPv6 entry to the LPM table %s_ipv6_%d!\n",
			rt->tag, uidx);
		goto out;
	}

	rte_atomic16_set(&rt->ipv6_aidx, uidx);
	uidx = 1 - uidx;

	ret = __lpm_rt_add_ipv6_routes(rt->ipv6_rt[uidx], routes, num_routes);
	if (ret < 0) {
		RTE_LOG(ERR, LPM,
			"Unable to add an IPv6 entry to the LPM table %s_ipv6_%d!\n",
			rt->tag, uidx);
		goto out;
	}

out:
	return ret;
}

int
lpm_rt_lookup_ipv6(struct lpm_rt *rt, uint8_t *ip)
{
	int ret;
	uint8_t next_hop;

	ret = rte_lpm6_lookup(
		rt->ipv6_rt[rte_atomic16_read(&rt->ipv6_aidx)],
		ip, &next_hop);
	if (ret == -EINVAL) {
		RTE_LOG(ERR, LPM,
			"lpm: incorrect arguments for IPv6 lookup!\n");
		ret = -1;
		goto out;
	} else if (ret == -ENOENT) {
		RTE_LOG(WARNING, LPM, "lpm: IPv6 lookup miss!\n");
		ret = -1;
		goto out;
	}

	ret = next_hop;

out:
	return ret;
}

void
destroy_lpm_rt(struct lpm_rt *rt)
{
	int i;
	for (i = 0; i < 2; i++) {
		rte_lpm_free(rt->ipv4_rt[i]);
		rte_lpm6_free(rt->ipv6_rt[i]);
	}
}
