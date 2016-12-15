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

#ifndef _GATEKEEPER_POLICY_H_
#define _GATEKEEPER_POLICY_H_

#include <netinet/in.h>

/* TODO Implement more policy actions. */
enum policy_action {
	/* Forward the packet to a Grantor server. */
	GK_FWD_GT,

	/* Forward the packet to the back interface. */
	GK_FWD_BCAK_NET,

	/* Drop the packet. */
	GK_DROP,
};

struct simple_policy {

	enum policy_action action;

	/* Data that supports different policy actions. */
	union {
		int grantor_id;
	} u;
};

#endif /* _GATEKEEPER_POLICY_H_ */
