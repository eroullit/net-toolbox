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

#include <netcore-ng/types.h>
#include <netcore-ng/pcap.h>
#include <netcore-ng/generic.h>
#include <netcore-ng/job.h>
#include <netcore-ng/time.h>
#include <netcore-ng/dissector/ethernet/dissector.h>

int job_list_init(struct job_list * job_list)
{
	assert(job_list);
	
	SLIST_INIT(&job_list->head);

	return (pthread_spin_init(&job_list->lock, PTHREAD_PROCESS_SHARED));
}

void job_list_cleanup(struct job_list * job_list)
{
	struct job * jobp = NULL;

	assert(job_list);

	while(SLIST_EMPTY(&job_list->head) == 0)
	{
		jobp = SLIST_FIRST(&job_list->head);
		SLIST_REMOVE_HEAD(&job_list->head, entry);
		info("Job took %ld.%06ld s and was called %"PRIu64" times\n", jobp->elapsed_time.tv_sec, jobp->elapsed_time.tv_usec, jobp->total_call);
		free(jobp);
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

int job_list_run(struct job_list * job_list, const struct generic_nic_context * const ctx)
{
	struct timeval before, after, diff;
	struct job * job;

	pthread_spin_lock(&job_list->lock);

	SLIST_FOREACH(job, &job_list->head, entry)
	{
		gettimeofday(&before, NULL);

		/* TODO Make proper return values handling */
		job->job(ctx);

		gettimeofday(&after, NULL);

		timeval_subtract(&diff, &after, &before);
		timeval_add(&job->elapsed_time, &job->elapsed_time, &diff);

		job->total_call++;
	}

	pthread_spin_unlock(&job_list->lock);

	return (0);
}

static ssize_t pcap_writev_job(const struct generic_nic_context * const ctx)
{
	assert(ctx);
	return(pcap_writev(ctx->pcap_fd, &ctx->pkt_vec));
}

int pcap_writev_job_register(struct job_list * job_list)
{
	return (job_list_insert(job_list, pcap_writev_job));
}

static ssize_t ethernet_dissector_job(const struct generic_nic_context * const ctx)
{
	uint8_t * pkt;
	size_t len;

	assert(ctx);

	pkt = packet_iovec_packet_payload_get(&ctx->pkt_vec);
	len = packet_iovec_packet_length_get(&ctx->pkt_vec);

	return(ethernet_dissector_run(pkt, len));
}

int ethernet_dissector_register(struct job_list * job_list)
{
	return (job_list_insert(job_list, ethernet_dissector_job));
}
