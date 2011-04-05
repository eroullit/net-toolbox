/* __LICENSE_HEADER_BEGIN__ */

/*
 * Copyright (C) 2009-2011	Emmanuel Roullit <emmanuel@netsniff-ng.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 *
 */

 /* __LICENSE_HEADER_END__ */


#ifndef	_NET_THREAD_H_
#define	_NET_THREAD_H_

#include <pthread.h>

enum netsniff_ng_thread_type
{
	RX_THREAD,
	RX_THREAD_COMPAT,
	TX_THREAD,
	SPINNER_THREAD,
};

enum netsniff_ng_thread_status
{
	RUNNING,
	SLEEPING,
	SHOULD_STOP,
	STOPPED,
};

struct netsniff_ng_thread_context
{
	pthread_t			thread;
	pthread_attr_t			thread_attr;
	pthread_mutex_t			wait_mutex;
	pthread_cond_t			wait_cond;
	pthread_spinlock_t		config_lock;
	cpu_set_t			run_on;
	enum netsniff_ng_thread_type 	type;
	enum netsniff_ng_thread_status	status;
};

int thread_context_init(struct netsniff_ng_thread_context * thread_ctx, const cpu_set_t run_on, const int sched_prio, const int sched_policy, const enum netsniff_ng_thread_type thread_type);
void thread_context_destroy(struct netsniff_ng_thread_context * thread_ctx);

enum netsniff_ng_thread_status thread_status_get(struct netsniff_ng_thread_context * thread_ctx);
void thread_status_set(struct netsniff_ng_thread_context * thread_ctx, enum netsniff_ng_thread_status new_status);

int thread_should_stop(struct netsniff_ng_thread_context * thread_ctx);
void thread_stop(struct netsniff_ng_thread_context * thread_ctx);

#endif	/* _NET_THREAD_H_ */
