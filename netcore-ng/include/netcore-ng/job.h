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

#ifndef	__JOB_H__
#define	__JOB_H__

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/queue.h>
#include <pthread.h>

struct generic_nic_context;

struct job
{
	const char *            id;
	uint64_t                total_call;
	struct timeval          elapsed_time;
	ssize_t (*job)(const struct generic_nic_context * const ctx);
	SLIST_ENTRY(job)	entry;
};

struct job_list
{
	pthread_spinlock_t		lock;
	SLIST_HEAD(job_head, job)	head;
};

int job_list_init(struct job_list * job_list);
void job_list_cleanup(struct job_list * job_list);
int job_list_insert(struct job_list * job_list, ssize_t (*job)(const struct generic_nic_context * const ctx), const char * job_id);
int job_list_run(struct job_list * job_list, const struct generic_nic_context * const ctx);
void job_list_print_profiling(struct job_list * job_list);

int pcap_writev_job_register(struct job_list * job_list);
int ethernet_dissector_register(struct job_list * job_list);

#endif	/* __JOB_H__ */
