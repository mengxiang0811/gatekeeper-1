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

#ifndef _GATEKEEPER_LPM_H_
#define _GATEKEEPER_LPM_H_

#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_atomic.h>

struct ipv4_lpm_route {
	uint32_t ip;
	uint8_t  depth;
	uint8_t  policy_id;
};

struct ipv6_lpm_route {
	uint8_t ip[16];
	uint8_t depth;
	uint8_t policy_id;
};

struct lpm_rt {
	char            tag[128];
	/*
	 * For ease of update, each structure should maintain
	 * two IPv4 and two IPv6 LPM tables:
	 * one is for lookup, and one is for update.
	 */
	struct rte_lpm  *ipv4_rt[2];
	struct rte_lpm6 *ipv6_rt[2];

	/* Active LPM table index. */
	rte_atomic16_t  ipv4_aidx;
	rte_atomic16_t  ipv6_aidx;
};

/* TODO Implement functions to delete IPv4/IPv6 routes. */

int init_lpm_rt(const char *tag,
	const struct rte_lpm_config *lpm_conf,
	const struct rte_lpm6_config *lpm6_conf,
	unsigned int socket_id, unsigned int identifier, struct lpm_rt *rt);

int lpm_rt_add_ipv4_routes(struct lpm_rt *rt,
	struct ipv4_lpm_route *routes, unsigned int num_routes);

int lpm_rt_lookup_ipv4(struct lpm_rt *rt, uint32_t ip);

int lpm_rt_add_ipv6_routes(struct lpm_rt *rt,
	struct ipv6_lpm_route *routes, unsigned int num_routes);

int lpm_rt_lookup_ipv6(struct lpm_rt *rt, uint8_t *ip);

void destroy_lpm_rt(struct lpm_rt *rt);

#endif /* _GATEKEEPER_LPM_H_ */
