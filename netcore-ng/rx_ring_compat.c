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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/time.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>

#include <netcore-ng/bpf.h>
#include <netcore-ng/cursor.h>
#include <netcore-ng/pcap.h>
#include <netcore-ng/macros.h>
#include <netcore-ng/types.h>
#include <netcore-ng/rx_ring_compat.h>
#include <netcore-ng/netdev.h>
#include <netcore-ng/xmalloc.h>
#include <netcore-ng/strlcpy.h>

static int sock_dev_bind(const char * dev, int sock)
{
	struct sockaddr saddr;
        int rc;

	memset(&saddr, 0, sizeof(saddr));
        strlcpy(saddr.sa_data, dev, sizeof(saddr.sa_data));

        rc = bind(sock, &saddr, sizeof(saddr));

        if (rc == -1) {
                err("bind() failed");
                return (rc);
        }

        return (0);
}

void * rx_thread_compat_listen(void * arg)
{
	struct netsniff_ng_rx_thread_compat_context * thread_ctx = (struct netsniff_ng_rx_thread_compat_context *) arg;
	struct netsniff_ng_rx_nic_compat_context * nic_ctx = NULL;
	struct packet_ctx * pkt_ctx = NULL;
	struct rx_job * job = NULL;
	struct sockaddr_ll      from;
        socklen_t               from_len = sizeof(from);

	if (thread_ctx == NULL)
	{
		pthread_exit(NULL);
	}

	memset(&from, 0, sizeof(from));

	nic_ctx = &thread_ctx->nic_ctx;
	pkt_ctx = &nic_ctx->generic.pkt_ctx;

	pkt_ctx->pkt_buf = nic_ctx->pkt_buf;

	info("--- Listening (Compatibility mode)---\n\n");

	for(;;)
	{
		pkt_ctx->pkt_len = recvfrom(nic_ctx->generic.dev_fd, pkt_ctx->pkt_buf, sizeof(nic_ctx->pkt_buf), MSG_TRUNC, (struct sockaddr *) &from, &from_len);

		if (errno == EINTR)
                        break;

		gettimeofday(&pkt_ctx->pkt_ts, NULL);

		pkt_ctx->pkt_snaplen = pkt_ctx->pkt_len;

		SLIST_FOREACH(job, &nic_ctx->generic.job_list.head, entry)
		{
			/* TODO think about return values handling */
			job->rx_job(&nic_ctx->generic);
		}
	}

	pthread_exit(NULL);
}

void rx_nic_compat_ctx_destroy(struct netsniff_ng_rx_nic_compat_context * nic_ctx)
{
	assert(nic_ctx);
	
	rx_job_list_cleanup(&nic_ctx->generic.job_list);

	if (nic_ctx->generic.bpf.filter)
	{
		bpf_kernel_reset(nic_ctx->generic.dev_fd);
		free(nic_ctx->generic.bpf.filter);
	}

	close(nic_ctx->generic.dev_fd);
	close(nic_ctx->generic.pcap_fd);
}

int rx_nic_compat_ctx_init(struct netsniff_ng_rx_thread_compat_context * thread_ctx, const char * rx_dev, const char * bpf_path, const char * pcap_path)
{
	struct netsniff_ng_rx_nic_compat_context * nic_ctx = NULL;
	int dev_arp_type;
	int rc;

	assert(thread_ctx);
	assert(rx_dev);

	nic_ctx = &thread_ctx->nic_ctx;

	if (!is_device_ready(rx_dev))
	{
		warn("Device %s is not ready\n", rx_dev);
		return (EAGAIN);
	}

	strlcpy(nic_ctx->generic.rx_dev, rx_dev, IFNAMSIZ);

	if ((rc = get_arp_type(nic_ctx->generic.rx_dev, &dev_arp_type)) != 0)
	{
		goto error;
	}

	if ((rc = pcap_get_link_type(dev_arp_type, &nic_ctx->generic.linktype)) != 0)
	{
		goto error;
	}

	if ((nic_ctx->generic.dev_fd = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0)
	{
		warn("Could not open socket for %s\n", nic_ctx->generic.rx_dev);
		rc = EPERM;
		goto error;
	}

	if (sock_dev_bind(rx_dev, nic_ctx->generic.dev_fd))
	{
		warn("Could not dev %s to socket\n", nic_ctx->generic.rx_dev);
		rc = EAGAIN;
		goto error;
	}

	if ((rc = rx_job_list_init(&nic_ctx->generic.job_list)) != 0)
	{
		warn("Could not create job list\n");
		goto error;
	}

	if (bpf_path)
	{
		if(bpf_parse(bpf_path, &nic_ctx->generic.bpf) == 0)
		{
			warn("Could not parse BPF file %s\n", bpf_path);
			rc = EINVAL;
			goto error;
		}

		bpf_kernel_inject(nic_ctx->generic.dev_fd, &nic_ctx->generic.bpf);
	}

	if (pcap_path)
	{
		if ((nic_ctx->generic.pcap_fd = pcap_create(pcap_path, nic_ctx->generic.linktype)) < 0)
		{
			warn("Failed to prepare pcap : %s\n", pcap_path);
			rc = EINVAL;
			goto error;
		}

		if ((rc = pcap_write_job_register(&nic_ctx->generic.job_list)) != 0)
		{
			warn("Could not register pcap write job\n");
			goto error;
		}
	}

	if ((rc = ethernet_dissector_register(&nic_ctx->generic.job_list)) != 0)
	{
		warn("Could not register ethernet dissector job\n");
		goto error;
	}

	return(0);
error:
	rx_nic_compat_ctx_destroy(nic_ctx);
	return(rc);
}

void rx_thread_compat_destroy(struct netsniff_ng_rx_thread_compat_context * thread_config)
{
	assert(thread_config);

	if (thread_config->thread_ctx.thread)
		pthread_cancel(thread_config->thread_ctx.thread);
	
	thread_context_destroy(&thread_config->thread_ctx);
	rx_nic_compat_ctx_destroy(&thread_config->nic_ctx);

	xfree(thread_config);
}

struct netsniff_ng_rx_thread_compat_context * rx_thread_compat_create(const cpu_set_t run_on, const int sched_prio, const int sched_policy, const char * rx_dev, const char * bpf_path, const char * pcap_path)
{
	int rc;
	struct netsniff_ng_rx_thread_compat_context * thread_config = NULL;

	thread_config = xzmalloc(sizeof(*thread_config));

	memset(thread_config, 0, sizeof(*thread_config));

	if ((rc = thread_context_init(&thread_config->thread_ctx, run_on, sched_prio, sched_policy, RX_THREAD_COMPAT)) != 0)
	{
		warn("Cannot initialize thread\n");
		goto error;
	}

	if ((rc = rx_nic_compat_ctx_init(thread_config, rx_dev, bpf_path, pcap_path)) != 0)
	{
		warn("Cannot initialize RX NIC context\n");
		goto error;
	}

	pthread_create(&thread_config->thread_ctx.thread, &thread_config->thread_ctx.thread_attr, rx_thread_compat_listen, thread_config);

	return (thread_config);
error:
	rx_thread_compat_destroy(thread_config);
	return (NULL);
}

