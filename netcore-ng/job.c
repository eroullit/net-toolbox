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

	job_list_print_profiling(job_list);

	pthread_spin_lock(&job_list->lock);

	while(SLIST_EMPTY(&job_list->head) == 0)
	{
		jobp = SLIST_FIRST(&job_list->head);
		SLIST_REMOVE_HEAD(&job_list->head, entry);
		free(jobp);
	}

	pthread_spin_unlock(&job_list->lock);

	pthread_spin_destroy(&job_list->lock);
}

int job_list_insert(struct job_list * job_list, ssize_t (*job)(const struct generic_nic_context * const ctx), const char * job_id)
{
	struct job * cur = NULL;
	struct job * jobp = NULL;

	assert(job_list);
	assert(job);
	assert(job_id);

	if ((jobp = malloc(sizeof(*jobp))) == NULL)
	{
		return (ENOMEM);
	}
	
	memset(jobp, 0, sizeof(*jobp));
	jobp->job = job;
	jobp->id = job_id;

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
	ssize_t ret;
	struct timeval before, after, diff;
	struct job * job;

	pthread_spin_lock(&job_list->lock);

	SLIST_FOREACH(job, &job_list->head, entry)
	{
		gettimeofday(&before, NULL);

		/* TODO Make proper return values handling */
		ret = job->job(ctx);

		gettimeofday(&after, NULL);

		timeval_subtract(&diff, &after, &before);
		timeval_add(&job->total_time, &job->total_time, &diff);

		if (ret < 0)
			job->total_errors++;
		else
			job->total_bytes += ret;

		job->total_calls++;
		job->total_packets++;
	}

	pthread_spin_unlock(&job_list->lock);

	return (0);
}

void job_list_print_profiling(struct job_list * job_list)
{
	struct job * job;

	assert(job_list);

	pthread_spin_lock(&job_list->lock);

	SLIST_FOREACH(job, &job_list->head, entry)
	{
		info("%s=%s\n", stringify(job->id), job->id);
		info("%s=%"PRIu64"\n", stringify(job->total_calls), job->total_calls);
		info("%s=%"PRIu64"\n", stringify(job->total_errors), job->total_errors);
		info("%s=%"PRIu64"\n", stringify(job->total_packets), job->total_packets);
		info("%s=%"PRIu64"\n", stringify(job->total_bytes), job->total_bytes);
		info("%s=%ld.%06ld s\n", stringify(job->total_time), job->total_time.tv_sec, job->total_time.tv_usec);
		info("\n");
	}

	pthread_spin_unlock(&job_list->lock);
}

static ssize_t pcap_writev_job(const struct generic_nic_context * const ctx)
{
	assert(ctx);
	return(pcap_writev(ctx->pcap_fd, &ctx->pkt_vec));
}

int pcap_writev_job_register(struct job_list * job_list)
{
	return (job_list_insert(job_list, pcap_writev_job, stringify(pcap_writev_job)));
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
	return (job_list_insert(job_list, ethernet_dissector_job, stringify(ethernet_dissector_job)));
}
