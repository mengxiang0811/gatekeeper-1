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

#ifndef SEQLOCK_H
#define SEQLOCK_H

/*
 * The code of this file is mostly a copy of the Linux kernel,
 * and replace the Linux spinlock with DPDK's rte_spinlock_t.
 */

#include <rte_log.h>
#include <rte_atomic.h>
#include <rte_spinlock.h>

#include "gatekeeper_main.h"

/*
 * TODO Add support for the use of
 * hardware memory transactions (HTM) in DPDK.
 */

/*
 * Reader/writer consistent mechanism without starving writers. This type of
 * lock for data where the reader wants a consistent set of information
 * and is willing to retry if the information changes. There are two types
 * of readers:
 * 1. Sequence readers which never block a writer but they may have to retry
 *    if a writer is in progress by detecting change in sequence number.
 *    Writers do not wait for a sequence reader.
 * 2. Locking readers which will wait if a writer or another locking reader
 *    is in progress. A locking reader in progress will also block a writer
 *    from going forward. Unlike the regular rwlock, the read lock here is
 *    exclusive so that only one locking reader can get it.
 *
 * This is not as cache friendly as brlock. Also, this may not work well
 * for data that contains pointers, because any writer could
 * invalidate a pointer that a reader was following.
 *
 * Expected non-blocking reader usage:
 * 	do {
 *	    seq = read_seqbegin(&foo);
 * 	...
 *      } while (read_seqretry(&foo, seq));
 *
 *
 * On non-SMP the spin locks disappear but the writer still needs
 * to increment the sequence variables because an interrupt routine could
 * change the state of the data.
 *
 * Based on x86_64 vsyscall gettimeofday 
 * by Keith Owens and Andrea Arcangeli
 */

static __always_inline void
data_access_exceeds_word_size(void)
{
	RTE_LOG(WARNING, GATEKEEPER,
		"seqlock: Data access exceeds word size and won't be atomic\n");
}

static __always_inline void
__read_once_size(const volatile void *p, void *res, int size)
{
 	switch (size) {
 	case 1:
		*(uint8_t *)res = *(const volatile uint8_t*)p;
		break;

 	case 2:
		*(uint16_t *)res = *(const volatile uint16_t *)p;
		break;

	case 4:
		*(uint32_t *)res = *(const volatile uint32_t *)p;
		break;

 	case 8:
		*(uint64_t *)res = *(const volatile uint64_t *)p;
		break;

 	default:
 		data_access_exceeds_word_size();
		break;
	}
}

/*
 * Prevent the compiler from merging or refetching reads or writes. The
 * compiler is also forbidden from reordering successive instances of
 * READ_ONCE, WRITE_ONCE and ACCESS_ONCE (see below), but only when the
 * compiler is aware of some particular ordering.  One way to make the
 * compiler aware of ordering is to put the two invocations of READ_ONCE,
 * WRITE_ONCE or ACCESS_ONCE() in different C statements.
 *
 * In contrast to ACCESS_ONCE these two macros will also work on aggregate
 * data types like structs or unions. If the size of the accessed data
 * type exceeds the word size of the machine (e.g., 32 bits or 64 bits)
 * READ_ONCE() and WRITE_ONCE()  will fall back to memcpy and print a
 * compile-time warning.
 *
 * Their two major use cases are: (1) Mediating communication between
 * process-level code and irq/NMI handlers, all running on the same CPU,
 * and (2) Ensuring that the compiler does not  fold, spindle, or otherwise
 * mutilate accesses that either do not require ordering or that interact
 * with an explicit memory barrier or atomic instruction that provides the
 * required ordering.
 */
#define READ_ONCE(x) \
	({ union { typeof(x) __val; char __c[1]; } __u; \
	__read_once_size(&(x), __u.__c, sizeof(x)); __u.__val; })

#define cpu_relax() asm ("rep; nop" ::: "memory")

/*
 * Version using sequence counter only.
 * This can be used when code has its own mutex protecting the
 * updating starting before the write_seqcountbeqin() and ending
 * after the write_seqcount_end().
 */
typedef struct seqcount {
	unsigned sequence;
} seqcount_t;

static inline void
seqcount_init(seqcount_t *s)
{
	s->sequence = 0;
}

/**
 * __read_seqcount_begin - begin a seq-read critical section (without barrier)
 * @s: pointer to seqcount_t
 * Returns: count to be passed to read_seqcount_retry
 *
 * __read_seqcount_begin is like read_seqcount_begin, but has no smp_rmb()
 * barrier. Callers should ensure that smp_rmb() or equivalent ordering is
 * provided before actually loading any of the variables that are to be
 * protected in this critical section.
 *
 * Use carefully, only in critical code, and comment how the barrier is
 * provided.
 */
static inline unsigned
__read_seqcount_begin(const seqcount_t *s)
{
	unsigned ret;

repeat:
	ret = READ_ONCE(s->sequence);
	if (unlikely(ret & 1)) {
		cpu_relax();
		goto repeat;
	}
	return ret;
}

/**
 * raw_read_seqcount - Read the raw seqcount
 * @s: pointer to seqcount_t
 * Returns: count to be passed to read_seqcount_retry
 *
 * raw_read_seqcount opens a read critical section of the given
 * seqcount without any lockdep checking and without checking or
 * masking the LSB. Calling code is responsible for handling that.
 */
static inline unsigned
raw_read_seqcount(const seqcount_t *s)
{
	unsigned ret = READ_ONCE(s->sequence);
	rte_smp_rmb();
	return ret;
}

/**
 * raw_read_seqcount_begin - start seq-read critical section w/o lockdep
 * @s: pointer to seqcount_t
 * Returns: count to be passed to read_seqcount_retry
 *
 * raw_read_seqcount_begin opens a read critical section of the given
 * seqcount, but without any lockdep checking. Validity of the critical
 * section is tested by checking read_seqcount_retry function.
 */
static inline unsigned
raw_read_seqcount_begin(const seqcount_t *s)
{
	unsigned ret = __read_seqcount_begin(s);
	rte_smp_rmb();
	return ret;
}

/**
 * read_seqcount_begin - begin a seq-read critical section
 * @s: pointer to seqcount_t
 * Returns: count to be passed to read_seqcount_retry
 *
 * read_seqcount_begin opens a read critical section of the given seqcount.
 * Validity of the critical section is tested by checking read_seqcount_retry
 * function.
 */
static inline unsigned
read_seqcount_begin(const seqcount_t *s)
{
	return raw_read_seqcount_begin(s);
}

/**
 * raw_seqcount_begin - begin a seq-read critical section
 * @s: pointer to seqcount_t
 * Returns: count to be passed to read_seqcount_retry
 *
 * raw_seqcount_begin opens a read critical section of the given seqcount.
 * Validity of the critical section is tested by checking read_seqcount_retry
 * function.
 *
 * Unlike read_seqcount_begin(), this function will not wait for the count
 * to stabilize. If a writer is active when we begin, we will fail the
 * read_seqcount_retry() instead of stabilizing at the beginning of the
 * critical section.
 */
static inline unsigned
raw_seqcount_begin(const seqcount_t *s)
{
	unsigned ret = READ_ONCE(s->sequence);
	rte_smp_rmb();
	return ret & ~1;
}

/**
 * __read_seqcount_retry - end a seq-read critical section (without barrier)
 * @s: pointer to seqcount_t
 * @start: count, from read_seqcount_begin
 * Returns: 1 if retry is required, else 0
 *
 * __read_seqcount_retry is like read_seqcount_retry, but has no smp_rmb()
 * barrier. Callers should ensure that smp_rmb() or equivalent ordering is
 * provided before actually loading any of the variables that are to be
 * protected in this critical section.
 *
 * Use carefully, only in critical code, and comment how the barrier is
 * provided.
 */
static inline int
__read_seqcount_retry(const seqcount_t *s, unsigned start)
{
	return unlikely(s->sequence != start);
}

/**
 * read_seqcount_retry - end a seq-read critical section
 * @s: pointer to seqcount_t
 * @start: count, from read_seqcount_begin
 * Returns: 1 if retry is required, else 0
 *
 * read_seqcount_retry closes a read critical section of the given seqcount.
 * If the critical section was invalid, it must be ignored (and typically
 * retried).
 */
static inline int
read_seqcount_retry(const seqcount_t *s, unsigned start)
{
	rte_smp_rmb();
	return __read_seqcount_retry(s, start);
}

static inline void
raw_write_seqcount_begin(seqcount_t *s)
{
	s->sequence++;
	rte_smp_wmb();
}

static inline void
raw_write_seqcount_end(seqcount_t *s)
{
	rte_smp_wmb();
	s->sequence++;
}

/*
 * raw_write_seqcount_latch - redirect readers to even/odd copy
 * @s: pointer to seqcount_t
 */
static inline void
raw_write_seqcount_latch(seqcount_t *s)
{
       rte_smp_wmb();      /* prior stores before incrementing "sequence" */
       s->sequence++;
       rte_smp_wmb();      /* increment "sequence" before following stores */
}

static inline void
write_seqcount_begin(seqcount_t *s)
{
	raw_write_seqcount_begin(s);
}

static inline void
write_seqcount_end(seqcount_t *s)
{
	raw_write_seqcount_end(s);
}

/**
 * write_seqcount_barrier - invalidate in-progress read-side seq operations
 * @s: pointer to seqcount_t
 *
 * After write_seqcount_barrier, no read-side seq operations will complete
 * successfully and see data older than this.
 */
static inline void
write_seqcount_barrier(seqcount_t *s)
{
	rte_smp_wmb();
	s->sequence+=2;
}

typedef struct {
	struct seqcount seqcount;
	rte_spinlock_t lock;
} seqlock_t;

#define seqlock_init(x)					\
	do {						\
		seqcount_init(&(x)->seqcount);		\
		rte_spinlock_init(&(x)->lock);		\
	} while (0)

/*
 * Read side functions for starting and finalizing a read side section.
 */
static inline unsigned
read_seqbegin(const seqlock_t *sl)
{
	return read_seqcount_begin(&sl->seqcount);
}

static inline unsigned
read_seqretry(const seqlock_t *sl, unsigned start)
{
	return read_seqcount_retry(&sl->seqcount, start);
}

/*
 * Lock out other writers and update the count.
 * Acts like a normal spin_lock/unlock.
 * Don't need preempt_disable() because that is in the spin_lock already.
 */
static inline void
write_seqlock(seqlock_t *sl)
{
	rte_spinlock_lock_tm(&sl->lock);
	write_seqcount_begin(&sl->seqcount);
}

static inline void write_sequnlock(seqlock_t *sl)
{
	write_seqcount_end(&sl->seqcount);
	rte_spinlock_unlock_tm(&sl->lock);
}

/*
 * A locking reader exclusively locks out other writers and locking readers,
 * but doesn't update the sequence number. Acts like a normal spin_lock/unlock.
 * Don't need preempt_disable() because that is in the spin_lock already.
 */
static inline void
read_seqlock_excl(seqlock_t *sl)
{
	rte_spinlock_lock_tm(&sl->lock);
}

static inline void
read_sequnlock_excl(seqlock_t *sl)
{
	rte_spinlock_unlock_tm(&sl->lock);
}

/**
 * read_seqbegin_or_lock - begin a sequence number check or locking block
 * @lock: sequence lock
 * @seq : sequence number to be checked
 *
 * First try it once optimistically without taking the lock. If that fails,
 * take the lock. The sequence number is also used as a marker for deciding
 * whether to be a reader (even) or writer (odd).
 * N.B. seq must be initialized to an even number to begin with.
 */
static inline void
read_seqbegin_or_lock(seqlock_t *lock, int *seq)
{
	if (!(*seq & 1))	/* Even */
		*seq = read_seqbegin(lock);
	else			/* Odd */
		read_seqlock_excl(lock);
}

static inline int
need_seqretry(seqlock_t *lock, int seq)
{
	return !(seq & 1) && read_seqretry(lock, seq);
}

static inline void
done_seqretry(seqlock_t *lock, int seq)
{
	if (seq & 1)
		read_sequnlock_excl(lock);
}

#endif /* SEQLOCK_H */
