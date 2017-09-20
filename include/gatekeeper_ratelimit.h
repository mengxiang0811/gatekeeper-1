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

#ifndef _GATEKEEPER_RATELIMIT_H_
#define _GATEKEEPER_RATELIMIT_H_

#include <stdint.h>
#include <stdbool.h>

#include <rte_log.h>
#include <rte_spinlock.h>

/*
 * The code of this file is mostly a copy of the Linux kernel.
 */

struct ratelimit_state {
	/* Protect the state. */
	rte_spinlock_t lock;

	int            interval;
	int            burst;
	int            printed;
	int            missed;
	uint64_t       begin;
};

void log_ratelimit_init(void);
bool log_ratelimit(void);

#define RTE_LOG_RATELIMIT(l, t, ...)		\
do {						\
	if (!log_ratelimit())			\
		RTE_LOG(l, t, __VA_ARGS__);	\
} while (0)

/*
 * @rs: ratelimit_state data
 *
 * This will allow to enforce a rate limit: not more than @rs->burst callbacks
 * in every @rs->interval milliseconds.
 */
static inline void
ratelimit_state_init(struct ratelimit_state *rs, int interval, int burst)
{
	rte_spinlock_init(&rs->lock);
	rs->interval = interval;
	rs->burst = burst;
	rs->printed = 0;
	rs->missed = 0;
	rs->begin = 0;
}

#endif /* _GATEKEEPER_RATELIMIT_H_ */
