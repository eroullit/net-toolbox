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
	struct packet_vector * pkt_vec = NULL;
	struct packet_ctx * pkt_ctx = NULL;
	struct timeval		now;
	struct sockaddr_ll      from;
        socklen_t               from_len = sizeof(from);
        size_t a;
        size_t read;

	if (thread_ctx == NULL)
	{
		pthread_exit(NULL);
	}

	memset(&from, 0, sizeof(from));

	nic_ctx = &thread_ctx->nic_ctx;
	pkt_vec = &nic_ctx->generic.pkt_vec;

	info("--- Listening (Compatibility mode)---\n\n");

	for(;;)
	{
		for(a = 0; a < pkt_vec->pkt_nr; a++)
		{
			pkt_ctx = &pkt_vec->pkt[a];

			read = recvfrom(nic_ctx->generic.dev_fd, pkt_ctx->pkt_buf, pkt_ctx->mtu, MSG_TRUNC, (struct sockaddr *) &from, &from_len);

			if (errno == EINTR)
				break;

			pkt_ctx->pkt_hdr.len = read;
			pkt_ctx->pkt_hdr.caplen = read;
			
			gettimeofday(&now, NULL);

			pkt_ctx->pkt_hdr.ts.tv_sec = now.tv_sec;
			pkt_ctx->pkt_hdr.ts.tv_usec = now.tv_usec;

			//info("pkt %zu/%zu len %zu at %i.%i s\n", a, pkt_vec->pkt_nr, read, pkt_ctx->pkt_hdr.ts.tv_sec, pkt_ctx->pkt_hdr.ts.tv_usec);

			pkt_vec->pkt_io_vec[a * 2].iov_len = sizeof(pkt_ctx->pkt_hdr);
			pkt_vec->pkt_io_vec[(a * 2) + 1].iov_len = read;

#if 0
			SLIST_FOREACH(job, &nic_ctx->generic.job_list.head, entry)
			{
				/* TODO think about return values handling */
				job->job(&nic_ctx->generic);
			}
#endif
		}

		//info("Will call writev()\n");

		pcap_writev(nic_ctx->generic.pcap_fd, pkt_vec);
		packet_vector_reset(pkt_vec);
	}

	pthread_exit(NULL);
}

void rx_nic_compat_ctx_destroy(struct netsniff_ng_rx_nic_compat_context * nic_ctx)
{
	assert(nic_ctx);
	
	packet_vector_destroy(&nic_ctx->generic.pkt_vec);
	job_list_cleanup(&nic_ctx->generic.job_list);

	if (nic_ctx->generic.bpf.filter)
	{
		bpf_kernel_reset(nic_ctx->generic.dev_fd);
		free(nic_ctx->generic.bpf.filter);
	}

	close(nic_ctx->generic.dev_fd);
	close(nic_ctx->generic.pcap_fd);
}

int rx_nic_compat_ctx_init(struct netsniff_ng_rx_thread_compat_context * thread_ctx, const char * dev_name, const char * bpf_path, const char * pcap_path)
{
	struct netsniff_ng_rx_nic_compat_context * nic_ctx = NULL;
	int dev_arp_type;
	int rc;

	assert(thread_ctx);
	assert(dev_name);

	nic_ctx = &thread_ctx->nic_ctx;

	if (!is_device_ready(dev_name))
	{
		warn("Device %s is not ready\n", dev_name);
		return (EAGAIN);
	}

	strlcpy(nic_ctx->generic.dev_name, dev_name, IFNAMSIZ);

	if ((rc = get_arp_type(nic_ctx->generic.dev_name, &dev_arp_type)) != 0)
	{
		goto error;
	}

	if ((rc = pcap_link_type_get(dev_arp_type, &nic_ctx->generic.linktype)) != 0)
	{
		goto error;
	}

	if ((nic_ctx->generic.dev_fd = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0)
	{
		warn("Could not open socket for %s\n", nic_ctx->generic.dev_name);
		rc = EPERM;
		goto error;
	}

	if (sock_dev_bind(dev_name, nic_ctx->generic.dev_fd))
	{
		warn("Could not dev %s to socket\n", nic_ctx->generic.dev_name);
		rc = EAGAIN;
		goto error;
	}

	if ((rc = job_list_init(&nic_ctx->generic.job_list)) != 0)
	{
		warn("Could not create job list\n");
		goto error;
	}

	if ((rc = packet_vector_create(&nic_ctx->generic.pkt_vec, 32, get_mtu(nic_ctx->generic.dev_name))) != 0)
	{
		warn("Could not create packet vector\n");
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

struct netsniff_ng_rx_thread_compat_context * rx_thread_compat_create(const cpu_set_t run_on, const int sched_prio, const int sched_policy, const char * dev_name, const char * bpf_path, const char * pcap_path)
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

	if ((rc = rx_nic_compat_ctx_init(thread_config, dev_name, bpf_path, pcap_path)) != 0)
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

