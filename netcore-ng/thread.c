/* __LICENSE_HEADER_BEGIN__ */

/*
 * Copyright (C) 2009, 2011  Daniel Borkmann <daniel@netsniff-ng.org> and
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
 *
 */

 /* __LICENSE_HEADER_END__ */


#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <sched.h>

#include <netcore-ng/macros.h>
#include <netcore-ng/thread.h>

static int thread_attr_init(struct netsniff_ng_thread_context * thread_ctx, const int sched_prio, const int sched_policy, const cpu_set_t * const run_on)
{
	struct sched_param sp = { .sched_priority = sched_prio };
	int rc = 0;
	
	if ((rc = pthread_attr_setschedparam(&thread_ctx->thread_attr, &sp)) != 0)
	{
		warn("Cannot initialize scheduling attributes for priority %i\n", sp.sched_priority);
		return (rc);
	}

	if ((rc = pthread_attr_setschedpolicy(&thread_ctx->thread_attr, sched_policy)) != 0)
	{
		warn("Cannot initialize scheduling attributes for policy %i\n", sched_policy);
		return (rc);
	}

	if ((rc = pthread_attr_setaffinity_np(&thread_ctx->thread_attr, sizeof(*run_on), run_on)) != 0)
	{
		warn("Cannot initialize scheduling attributes for CPU affinity %s\n", strerror(rc));
		return (rc);
	}

	pthread_attr_setdetachstate(&thread_ctx->thread_attr, PTHREAD_CREATE_DETACHED);

	return (rc);
}

int thread_context_init(struct netsniff_ng_thread_context * thread_ctx, const cpu_set_t run_on, const int sched_prio, const int sched_policy, const enum netsniff_ng_thread_type thread_type)
{
	int rc;
	assert(thread_ctx);

	memset(thread_ctx, 0, sizeof(*thread_ctx));
	
	if ((rc = pthread_attr_init(&thread_ctx->thread_attr)) != 0)
	{
		warn("Cannot initialize thread attributes\n");
		return (rc);
	}

	if ((rc = thread_attr_init(thread_ctx, sched_prio, sched_policy, &run_on)) != 0)
	{
		pthread_attr_destroy(&thread_ctx->thread_attr);
		warn("Cannot set thread attributes\n");
		return (rc);
	}

	if ((rc = pthread_mutex_init(&thread_ctx->wait_mutex, NULL)) != 0)
	{
		pthread_attr_destroy(&thread_ctx->thread_attr);
		warn("Cannot initialize thread mutex\n");
		return (rc);
	}
	
	if ((rc = pthread_cond_init(&thread_ctx->wait_cond, NULL)) != 0)
	{
		pthread_mutex_destroy(&thread_ctx->wait_mutex);
		pthread_attr_destroy(&thread_ctx->thread_attr);
		warn("Cannot initialize thread condition\n");
		return (rc);
	}

	if ((rc = pthread_spin_init(&thread_ctx->config_lock, PTHREAD_PROCESS_PRIVATE)) != 0)
	{
		pthread_cond_destroy(&thread_ctx->wait_cond);
		pthread_mutex_destroy(&thread_ctx->wait_mutex);
		pthread_attr_destroy(&thread_ctx->thread_attr);
		warn("Cannot initialize thread config lock\n");
		return (rc);
	}

	thread_ctx->run_on = run_on;
	thread_ctx->type = thread_type;
	thread_ctx->status = STOPPED;

	return(rc);
}

void thread_context_destroy(struct netsniff_ng_thread_context * thread_ctx)
{
	assert(thread_ctx);

	pthread_attr_destroy(&thread_ctx->thread_attr);
	pthread_mutex_destroy(&thread_ctx->wait_mutex);
	pthread_cond_destroy(&thread_ctx->wait_cond);
	pthread_spin_destroy(&thread_ctx->config_lock);
}

enum netsniff_ng_thread_status thread_status_get(struct netsniff_ng_thread_context * thread_ctx)
{
	enum netsniff_ng_thread_status ret = STOPPED;

	assert(thread_ctx);

	pthread_spin_lock(&thread_ctx->config_lock);
	ret = thread_ctx->status;
	pthread_spin_unlock(&thread_ctx->config_lock);

	return (thread_ctx->status);
}

void thread_status_set(struct netsniff_ng_thread_context * thread_ctx, enum netsniff_ng_thread_status new_status)
{
	assert(thread_ctx);

	pthread_spin_lock(&thread_ctx->config_lock);
	thread_ctx->status = new_status;
	pthread_spin_unlock(&thread_ctx->config_lock);
}

int thread_should_stop(struct netsniff_ng_thread_context * thread_ctx)
{
	return (thread_status_get(thread_ctx) == SHOULD_STOP);
}

void thread_stop(struct netsniff_ng_thread_context * thread_ctx)
{
	thread_status_set(thread_ctx, SHOULD_STOP);
}

