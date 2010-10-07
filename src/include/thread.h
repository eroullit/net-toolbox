/*
 * Copyright (C) 2009, 2010  Daniel Borkmann <daniel@netsniff-ng.org> and 
 *                           Emmanuel Roullit <emmanuel@netsniff-ng.org>
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
 */

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

int init_thread_context(struct netsniff_ng_thread_context * thread_ctx, const cpu_set_t run_on, const int sched_prio, const int sched_policy, const enum netsniff_ng_thread_type thread_type);
void destroy_thread_context(struct netsniff_ng_thread_context * thread_ctx);

enum netsniff_ng_thread_status get_thread_status(struct netsniff_ng_thread_context * thread_ctx);
void set_thread_status(struct netsniff_ng_thread_context * thread_ctx, enum netsniff_ng_thread_status new_status);

int thread_should_stop(struct netsniff_ng_thread_context * thread_ctx);
void stop_thread(struct netsniff_ng_thread_context * thread_ctx);

#endif	/* _NET_THREAD_H_ */
