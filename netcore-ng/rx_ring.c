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

#include <net/if.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/types.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>

#include <netcore-ng/pcap.h>
#include <netcore-ng/cursor.h>
#include <netcore-ng/macros.h>
#include <netcore-ng/types.h>
#include <netcore-ng/rx_ring.h>
#include <netcore-ng/netdev.h>
#include <netcore-ng/bpf.h>
#include <netcore-ng/xmalloc.h>
#include <netcore-ng/strlcpy.h>

#ifndef POLLRDNORM
# define POLLRDNORM      0x0040
#endif
#ifndef POLLWRNORM
# define POLLWRNORM      0x0100
#endif

static void * rx_thread_listen(void * arg)
{
	struct job * job;
	struct pollfd pfd;
	int rc;
	struct timeval pkt_ts;
	struct netsniff_ng_rx_thread_context * thread_ctx = (struct netsniff_ng_rx_thread_context *) arg;
	struct netsniff_ng_rx_nic_context * nic_ctx = NULL;
	struct packet_mmap_ctx * pkt_mmap_ctx = NULL;
	struct packet_iovec * pkt_vec = NULL;

	if (thread_ctx == NULL)
	{
		pthread_exit(NULL);
	}

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	
	nic_ctx = &thread_ctx->nic_ctx;
	pkt_mmap_ctx = &nic_ctx->pkt_mmap_ctx;
	pkt_vec = &nic_ctx->generic.pkt_vec;
	
	memset(&pfd, 0, sizeof(pfd));
	pfd.events = POLLIN|POLLRDNORM|POLLERR;
	pfd.fd = nic_ctx->generic.dev_fd;

	info("--- Listening ---\n\n");

	for (;;)
	{
		packet_iovec_reset(pkt_vec);

		for(packet_mmap_ctx_reset(pkt_mmap_ctx); !packet_mmap_ctx_end(pkt_mmap_ctx); packet_mmap_ctx_next(pkt_mmap_ctx))
		{
			if ((packet_mmap_ctx_status_get(pkt_mmap_ctx) & TP_STATUS_KERNEL) == TP_STATUS_KERNEL)
			{
				/* Force sleep here when the user wants */
				if ((rc = poll(&pfd, 1, -1)) < 0)
				{
					err("polling error %i", rc);
					continue;
				}
			}

			/* TODO Add support for TP_STATUS_COPY */
			if ((packet_mmap_ctx_status_get(pkt_mmap_ctx) & TP_STATUS_USER) == TP_STATUS_USER)
			{
				pkt_ts = packet_mmap_ctx_ts_get(pkt_mmap_ctx);
				packet_mmap_ctx_set(pkt_mmap_ctx);
				packet_iovec_set(pkt_vec, packet_mmap_ctx_payload_get(pkt_mmap_ctx), packet_mmap_ctx_payload_len_get(pkt_mmap_ctx), &pkt_ts);

				SLIST_FOREACH(job, &nic_ctx->generic.processing_job_list.head, entry)
				{
					/* TODO think about return values handling */
					job->job(&nic_ctx->generic);
				}

				packet_iovec_next(pkt_vec);
			}
		}

		SLIST_FOREACH(job, &nic_ctx->generic.cleanup_job_list.head, entry)
		{
			/* TODO think about return values handling */
			job->job(&nic_ctx->generic);
		}
	}
	
	pthread_exit(NULL);
}

static void rx_nic_ctx_destroy(struct netsniff_ng_rx_nic_context * nic_ctx)
{
	struct job * job;

	assert(nic_ctx);

        SLIST_FOREACH(job, &nic_ctx->generic.cleanup_job_list.head, entry)
	{
		/* TODO think about return values handling */
		job->job(&nic_ctx->generic);
	}

	packet_mmap_ctx_destroy(&nic_ctx->pkt_mmap_ctx);
	packet_iovec_destroy(&nic_ctx->generic.pkt_vec);
	
	job_list_cleanup(&nic_ctx->generic.processing_job_list);
	job_list_cleanup(&nic_ctx->generic.cleanup_job_list);

	/* 
	 * If there is a BPF filter loaded, then it
	 * must be unbound from the device and freed
	 */

	if (nic_ctx->generic.bpf.filter)
	{
		bpf_kernel_reset(nic_ctx->generic.dev_fd);
		free(nic_ctx->generic.bpf.filter);
	}

	close(nic_ctx->generic.dev_fd);
	close(nic_ctx->generic.pcap_fd);
}

static int rx_nic_ctx_init(struct netsniff_ng_rx_thread_context * thread_ctx, const char * dev_name, const char * bpf_path, const char * pcap_path)
{
	struct tpacket_req layout;
	struct netsniff_ng_rx_nic_context * nic_ctx = NULL;
	int dev_arp_type;
	int rc = 0;

	assert(thread_ctx);
	assert(dev_name);

	nic_ctx = &thread_ctx->nic_ctx;
	
	memset(&layout, 0, sizeof(layout));

	/* tp_frame_size should be carefully chosen to fit closely to snapshot len */
	layout.tp_frame_size = TPACKET_ALIGNMENT << 7;
	layout.tp_block_size = getpagesize() << 2;
	layout.tp_block_nr = ((128 * 1024) / layout.tp_block_size); /* 128kB mmap */
	layout.tp_frame_nr = layout.tp_block_size / layout.tp_frame_size * layout.tp_block_nr;

	if (!is_device_ready(dev_name))
	{
		warn("Device %s is not ready\n", dev_name);
		return (EAGAIN);
	}

	strlcpy(nic_ctx->generic.dev_name, dev_name, IFNAMSIZ);
	nic_ctx->generic.dev_fd = get_pf_socket();
	
	if ((rc = get_arp_type(nic_ctx->generic.dev_name, &dev_arp_type)) != 0)
	{
		goto error;
	}

	if ((rc = pcap_link_type_get(dev_arp_type, &nic_ctx->generic.linktype)) != 0)
	{
		goto error;
	}

	if (nic_ctx->generic.dev_fd < 0)
	{
		warn("Could not open PF_PACKET socket\n");
		rc = EPERM;
		goto error;
	}

	if ((rc = job_list_init(&nic_ctx->generic.processing_job_list)) != 0)
	{
		warn("Could not create processing job list\n");
		goto error;
	}

		if ((rc = job_list_init(&nic_ctx->generic.cleanup_job_list)) != 0)
	{
		warn("Could not create cleanup job list\n");
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
		
		if ((rc = pcap_writev_job_register(&nic_ctx->generic.cleanup_job_list)) != 0)
		{
			warn("Could not register pcap write job\n");
			goto error;
		}
	}

	if ((rc = ethernet_dissector_register(&nic_ctx->generic.processing_job_list)) != 0)
	{
		warn("Could not register ethernet dissector job\n");
		goto error;
	}

	if ((rc = packet_iovec_create(&nic_ctx->generic.pkt_vec, layout.tp_frame_nr) != 0))
	{
		pcap_destroy(nic_ctx->generic.pcap_fd, pcap_path);
		goto error;
	}

	if ((rc = packet_mmap_ctx_create(&nic_ctx->pkt_mmap_ctx, &layout, ethdev_to_ifindex(dev_name), nic_ctx->generic.dev_fd, PACKET_MMAP_RX)) != 0)
	{
		pcap_destroy(nic_ctx->generic.pcap_fd, pcap_path);
		goto error;
	}

	return(0);

error:
	rx_nic_ctx_destroy(nic_ctx);
	return (rc);
}

void rx_thread_destroy(struct netsniff_ng_rx_thread_context * thread_config)
{
	assert(thread_config);

	if (thread_config->thread_ctx.thread)
		pthread_cancel(thread_config->thread_ctx.thread);

	thread_context_destroy(&thread_config->thread_ctx);
	rx_nic_ctx_destroy(&thread_config->nic_ctx);
	xfree(thread_config);
}

struct netsniff_ng_rx_thread_context * rx_thread_create(const cpu_set_t run_on, const int sched_prio, const int sched_policy, const char * dev_name, const char * bpf_path, const char * pcap_path)
{
	int rc;
	struct netsniff_ng_rx_thread_context * thread_config = NULL;

	if ((thread_config = xzmalloc(sizeof(*thread_config))) == NULL)
	{
		warn("Cannot allocate rx thread configuration\n");
		return (NULL);
	}

	if ((rc = thread_context_init(&thread_config->thread_ctx, run_on, sched_prio, sched_policy, RX_THREAD)) != 0)
	{
		goto error;
	}

	if ((rc = rx_nic_ctx_init(thread_config, dev_name, bpf_path, pcap_path)) != 0)
	{
		warn("Cannot initialize RX NIC context\n");
		goto error;
	}

	if ((rc = pthread_create(&thread_config->thread_ctx.thread, &thread_config->thread_ctx.thread_attr, rx_thread_listen, thread_config)))
	{
		warn("Could not start RX thread\n");
		goto error;
	}

	return (thread_config);

error:
	rx_thread_destroy(thread_config);
	return (NULL);
}

