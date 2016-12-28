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

#ifndef _GATEKEEPER_GT_H_
#define _GATEKEEPER_GT_H_

#include <stdint.h>

#include <rte_atomic.h>

#include "gatekeeper_lpm.h"
#include "gatekeeper_config.h"

/* Structure for Lua to set up the LPM routes. */
struct lua_ip_routes {
        const char *ip_addr;
        uint8_t    prefix_len;
        uint8_t    policy_id;
};

struct gt_match_fields {
	union {
		uint32_t v4;
		uint8_t  v6[16];
	} ip;
	uint16_t proto;
	uint16_t dest_port;
};

/* Structures for each GT instance. */
struct gt_instance {
	/* RX queue on the front interface. */
	uint16_t      rx_queue;

	/* TX queue on the front interface. */
	uint16_t      tx_queue;

	/* The lua state that belongs to the instance. */
	lua_State     *lua_state;
};

/* Configuration for the GT functional block. */
struct gt_config {
	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */
	rte_atomic32_t	   ref_cnt;

	/* The lcore ids at which each instance runs. */
	unsigned int       *lcores;

	/* The number of lcore ids in @lcores. */
	int                num_lcores;

	/* The network interface configuration. */
	struct net_config  *net;

	/* The gt instances. */
	struct gt_instance *instances;
};

struct gt_config *alloc_gt_conf(void);
int gt_conf_put(struct gt_config *gt_conf);
int run_gt(struct net_config *net_conf, struct gt_config *gt_conf);
int lua_update_ipv4_lpm(struct rte_lpm *lpm,
	struct lua_ip_routes *routes, unsigned int num_routes);
int lua_update_ipv6_lpm(struct rte_lpm6 *lpm,
	struct lua_ip_routes *routes, unsigned int num_routes);

static inline void
gt_conf_hold(struct gt_config *gt_conf)
{
	rte_atomic32_inc(&gt_conf->ref_cnt);
}

#endif /* _GATEKEEPER_GT_H_ */
