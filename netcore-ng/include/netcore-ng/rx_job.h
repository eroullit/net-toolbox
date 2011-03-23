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

#ifndef	__RX_JOB_H__
#define	__RX_JOB_H__

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/queue.h>
#include <pthread.h>

struct rx_generic_nic_context;
struct frame_map;

struct rx_job
{
	ssize_t (*rx_job)(const struct rx_generic_nic_context * const ctx, const struct frame_map * const fm);
	SLIST_ENTRY(rx_job)	entry;
};

struct rx_job_list
{
	pthread_spinlock_t		lock;
	SLIST_HEAD(rx_job_head, rx_job)	head;
};

int rx_job_list_init(struct rx_job_list * job_list);
void rx_job_list_cleanup(struct rx_job_list * job_list);
int rx_job_list_insert(struct rx_job_list * job_list, ssize_t (*rx_job)(const struct rx_generic_nic_context * const ctx, const struct frame_map * const fm));

int pcap_write_job_register(struct rx_job_list * job_list);
int ethernet_dissector_register(struct rx_job_list * job_list);

#endif	/* __RX_JOB_H__ */
