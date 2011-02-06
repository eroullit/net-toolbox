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

#ifndef	__RX_JOB_ACCESSOR_H__
#define	__RX_JOB_ACCESSOR_H__

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/queue.h>
#include <pthread.h>

struct netsniff_ng_rx_thread_context;
struct frame_map;

struct rx_job
{
	ssize_t (*rx_job)(const struct netsniff_ng_rx_thread_context * const ctx, const struct frame_map * const fm);
	SLIST_ENTRY(rx_job)	entry;
};

struct rx_job_list
{
	pthread_spinlock_t		lock;
	SLIST_HEAD(rx_job_head, rx_job)	head;
};

static inline int rx_job_list_init(struct rx_job_list * job_list)
{
	assert(job_list);
	
	SLIST_INIT(&job_list->head);

	return (pthread_spin_init(&job_list->lock, PTHREAD_PROCESS_SHARED));
}

static inline void rx_job_list_cleanup(struct rx_job_list * job_list)
{
	struct rx_job * job = NULL;

	assert(job_list);

	while(SLIST_EMPTY(&job_list->head) != 0)
	{
		job = SLIST_FIRST(&job_list->head);
		SLIST_REMOVE_HEAD(&job_list->head, entry);
		free(job);
	}
}

static inline int rx_job_list_insert(struct rx_job_list * job_list, ssize_t (*rx_job)(const struct netsniff_ng_rx_thread_context * const ctx, const struct frame_map * const fm))
{
	struct rx_job * cur = NULL;
	struct rx_job * job = NULL;

	assert(job_list);

	if ((job = malloc(sizeof(*job))) == NULL)
	{
		return (ENOMEM);
	}
	
	memset(job, 0, sizeof(*job));
	job->rx_job = rx_job;

	pthread_spin_lock(&job_list->lock);
	SLIST_FOREACH(cur, &job_list->head, entry)
	{
		/* Check if the same job is already registered */
		if (cur->rx_job == rx_job)
		{
			pthread_spin_unlock(&job_list->lock);
			free(job);
			return (EINVAL);
		}
	}

	SLIST_INSERT_HEAD(&job_list->head, job, entry);
	
	pthread_spin_unlock(&job_list->lock);

	return (0);
}
#endif	/* __RX_JOB_ACCESSOR_H__ */
