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

#include <netcore-ng/types.h>
#include <netcore-ng/pcap.h>
#include <netcore-ng/generic.h>
#include <netcore-ng/job.h>
#include <netcore-ng/dissector/ethernet/dissector.h>

int job_list_init(struct job_list * job_list)
{
	assert(job_list);
	
	SLIST_INIT(&job_list->head);

	return (pthread_spin_init(&job_list->lock, PTHREAD_PROCESS_SHARED));
}

void job_list_cleanup(struct job_list * job_list)
{
	struct job * job = NULL;

	assert(job_list);

	while(SLIST_EMPTY(&job_list->head) == 0)
	{
		job = SLIST_FIRST(&job_list->head);
		SLIST_REMOVE_HEAD(&job_list->head, entry);
		free(job);
	}

	pthread_spin_destroy(&job_list->lock);
}

int job_list_insert(struct job_list * job_list, ssize_t (*job)(const struct generic_nic_context * const ctx))
{
	struct job * cur = NULL;
	struct job * jobp = NULL;

	assert(job_list);

	if ((jobp = malloc(sizeof(*jobp))) == NULL)
	{
		return (ENOMEM);
	}
	
	memset(jobp, 0, sizeof(*jobp));
	jobp->job = job;

	pthread_spin_lock(&job_list->lock);

	SLIST_FOREACH(cur, &job_list->head, entry)
	{
		/* Check if the same job is already registered */
		if (cur->job == job)
		{
			pthread_spin_unlock(&job_list->lock);
			free(jobp);
			return (EINVAL);
		}
	}

	SLIST_INSERT_HEAD(&job_list->head, jobp, entry);
	
	pthread_spin_unlock(&job_list->lock);

	return (0);
}

static ssize_t pcap_write_job(const struct generic_nic_context * const ctx)
{
	assert(ctx);

	return(pcap_write_payload(ctx->pcap_fd, &ctx->pkt_ctx));
}

int pcap_write_job_register(struct job_list * job_list)
{
	return (job_list_insert(job_list, pcap_write_job));
}

static ssize_t ethernet_dissector_job(const struct generic_nic_context * const ctx)
{
	assert(ctx);

	return(ethernet_dissector_run(ctx->pkt_ctx.pkt_buf, ctx->pkt_ctx.pkt_len));
}

int ethernet_dissector_register(struct job_list * job_list)
{
	return (job_list_insert(job_list, ethernet_dissector_job));
}
