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

#include <rte_cycles.h>

#include "gatekeeper_main.h"
#include "gatekeeper_ratelimit.h"

#define DEFAULT_RATELIMIT_INTERVAL (5)
#define DEFAULT_RATELIMIT_BURST    (100)

static struct ratelimit_state log_ratelimit_state;

void
log_ratelimit_init(void)
{
	ratelimit_state_init(&log_ratelimit_state,
		DEFAULT_RATELIMIT_INTERVAL, DEFAULT_RATELIMIT_BURST);
}

/*
 * Rate limiting log entries.
 *
 * Returns:
 *  true means callbacks will be suppressed.
 *  false means go ahead and do it.
 */
bool
log_ratelimit(void)
{
	int ret;
	struct ratelimit_state *rs = &log_ratelimit_state;

	if (!rs->interval)
		return false;

	/*
	 * If we contend on this state's lock then almost
	 * by definition we are too busy to print a message,
	 * in addition to the one that will be printed by
	 * the entity that is holding the lock already.
	 */
	if (!rte_spinlock_trylock_tm(&rs->lock))
		return true;

	if (!rs->begin)
		rs->begin = rte_rdtsc();

	if (rs->begin + rs->interval * cycles_per_ms < rte_rdtsc()) {
		rs->begin = rte_rdtsc();
		rs->printed = 0;
		rs->missed = 0;
	}

	if (rs->burst && rs->burst > rs->printed) {
		rs->printed++;
		ret = false;
	} else {
		rs->missed++;
		ret = true;
	}

	rte_spinlock_unlock_tm(&rs->lock);

	return ret;
}
