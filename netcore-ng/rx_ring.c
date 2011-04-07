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

static int rx_ring_register(int sock, struct tpacket_req * req)
{
	/* Loop to reduce requested ring buffer is it cannot be allocated */
	/* Break when not supported */

	if (setsockopt(sock, SOL_PACKET, PACKET_RX_RING, (void *)(req), sizeof(*req)) < 0) {
		err("setsockopt: creation of rx_ring failed");
		return (EAGAIN);
	}

	return (0);
}

static void rx_ring_unregister(int sock)
{
	struct tpacket_req req;
	memset(&req, 0, sizeof(req));
	setsockopt(sock, SOL_PACKET, PACKET_RX_RING, (void *)&req, sizeof(req));
}

static int rx_ring_mmap(int sock, struct ring_buff * rb)
{
	assert(rb);

	rb->buffer = mmap(0, rb->size, PROT_READ | PROT_WRITE, MAP_SHARED, sock, 0);
	if (rb->buffer == MAP_FAILED) {
		err("mmap: cannot mmap the rx_ring");
		return (EINVAL);
	}

	return (0);
}

static void rx_ring_munmap(struct ring_buff * rb)
{
	assert(rb);

	if (rb->buffer)
	{
		munmap(rb->buffer, rb->size);
		rb->buffer = NULL;
		rb->size = 0;
	}
}

static int rx_ring_bind(int sock, int ifindex)
{
	struct sockaddr_ll sll;

	memset(&sll, 0, sizeof(sll));

	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = ifindex;

	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		err("bind: cannot bind device");
		return (EINVAL);
	}

	/* Check error and if dev is ready */

	return (0);
}

static inline int frame_buffer_create(struct ring_buff * rb, struct tpacket_req req)
{
	uint32_t i = 0;

	assert(rb);

	rb->frames = malloc(req.tp_frame_nr * sizeof(*rb->frames));
	if (!rb->frames) {
		err("No mem left");
		return (ENOMEM);
	}

	memset(rb->frames, 0, req.tp_frame_nr * sizeof(*rb->frames));

	for (i = 0; i < req.tp_frame_nr; ++i) {
		rb->frames[i].iov_base = (uint8_t *) ((long)rb->buffer) + (i * req.tp_frame_size);
		rb->frames[i].iov_len = req.tp_frame_size;
	}

	return (0);
}

static inline void frame_buffer_destroy(struct ring_buff * rb)
{
	assert(rb);

	free(rb->frames);
}

static void * rx_thread_listen(void * arg)
{
	struct job * job = NULL;
	struct pollfd pfd;
	int rc;
	struct frame_map * fm = NULL;
	struct netsniff_ng_rx_thread_context * thread_ctx = (struct netsniff_ng_rx_thread_context *) arg;
	struct netsniff_ng_rx_nic_context * nic_ctx = NULL;
	struct packet_ctx * pkt_ctx = NULL;
	struct ring_buff * rb = NULL;

	if (thread_ctx == NULL)
	{
		pthread_exit(NULL);
	}

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	
	nic_ctx = &thread_ctx->nic_ctx;
	pkt_ctx = &nic_ctx->generic.pkt_ctx;
	rb = &nic_ctx->nic_rb;
	
	memset(&pfd, 0, sizeof(pfd));
	pfd.events = POLLIN|POLLRDNORM|POLLERR;
	pfd.fd = nic_ctx->generic.dev_fd;

	info("--- Listening ---\n\n");

	for(;;)
	{
		while (rb->cur_frame < rb->layout.tp_frame_nr)
		{
			fm = rb->frames[rb->cur_frame].iov_base;

			if ((frame_map_pkt_status_get(fm) & TP_STATUS_KERNEL) == TP_STATUS_KERNEL)
			{
				/* Force sleep here when the user wants */
				if ((rc = poll(&pfd, 1, -1)) < 0)
				{
					err("polling error %i", rc);
					continue;
				}
			}

			/* TODO Add support for TP_STATUS_COPY */
			if ((frame_map_pkt_status_get(fm) & TP_STATUS_USER) == TP_STATUS_USER)
			{
				pkt_ctx->pkt_buf = frame_map_pkt_buf_get(fm);
				pkt_ctx->pkt_ts.tv_sec = fm->tp_h.tp_sec;
				pkt_ctx->pkt_ts.tv_usec = fm->tp_h.tp_usec;
				pkt_ctx->pkt_len = fm->tp_h.tp_len;
				pkt_ctx->pkt_snaplen = fm->tp_h.tp_snaplen;

				SLIST_FOREACH(job, &nic_ctx->generic.job_list.head, entry)
				{
					/* TODO think about return values handling */
					job->job(&nic_ctx->generic);
				}
			}
	
			frame_map_pkt_status_kernel(fm);
			rb->cur_frame = (rb->cur_frame + 1) % rb->layout.tp_frame_nr;
		}
	}

	pthread_exit(NULL);
}


static int rx_ring_create(int sock, struct ring_buff * rb, const char *ifname)
{
	struct tpacket_req req;

	assert(rb);
	assert(ifname);

	memset(&req, 0, sizeof(req));
	/* max: getpagesize() << 11 for i386 */
	req.tp_block_size = getpagesize() << 2;

	/* tp_frame_size should be carefully chosen to fit closely to snapshot len */
	req.tp_frame_size = TPACKET_ALIGNMENT << 7;

	req.tp_block_nr = ((1024 * 1024) / req.tp_block_size);
	req.tp_frame_nr = req.tp_block_size / req.tp_frame_size * req.tp_block_nr;

	if (rx_ring_register(sock, &req))
	{
		err("Cannot register RX ring buffer for %s", ifname);
		return (EAGAIN);
	}

	rb->size = req.tp_block_size * req.tp_block_nr;

	if (rx_ring_mmap(sock, rb))
	{
		rx_ring_unregister(sock);
		err("Cannot prepare RX ring buffer for interface %s for userspace", ifname);
		return (EAGAIN);
	}

	if (frame_buffer_create(rb, req))
	{
		rx_ring_munmap(rb);
		rx_ring_unregister(sock);
		err("Cannot allocate RX ring buffer frame buffer for %s", ifname);
		return (ENOMEM);
	}

	if (rx_ring_bind(sock, ethdev_to_ifindex(ifname)))
	{
		frame_buffer_destroy(rb);
		rx_ring_munmap(rb);
		rx_ring_unregister(sock);
		err("Cannot bind %s to RX ring buffer frame buffer", ifname);
		return (EAGAIN);
	}

	rb->layout = req;

	/* XXX Make it human readable */
	info("%.2f MB allocated for receive ring \n", 1.f * rb->size / (1024 * 1024));
	info(" [ %d blocks, %d frames ] \n", req.tp_block_nr, req.tp_frame_nr);
	info(" [ %d frames per block ]\n", req.tp_block_size / req.tp_frame_size);
	info(" [ framesize: %d bytes, blocksize: %d bytes ]\n\n", req.tp_frame_size, req.tp_block_size);

	return (0);
}

static void rx_ring_destroy(int sock, struct ring_buff * rb)
{
	assert(rb);

	rx_ring_munmap(rb);
	rx_ring_unregister(sock);
	frame_buffer_destroy(rb);
}


static void rx_nic_ctx_destroy(struct netsniff_ng_rx_nic_context * nic_ctx)
{
	assert(nic_ctx);

	rx_ring_destroy(nic_ctx->generic.dev_fd, &nic_ctx->nic_rb);
	job_list_cleanup(&nic_ctx->generic.job_list);

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
	struct netsniff_ng_rx_nic_context * nic_ctx = NULL;
	int dev_arp_type;
	int rc = 0;

	assert(thread_ctx);
	assert(dev_name);

	nic_ctx = &thread_ctx->nic_ctx;

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

	if ((rc = job_list_init(&nic_ctx->generic.job_list)) != 0)
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

	if ((rc = rx_ring_create(nic_ctx->generic.dev_fd, &nic_ctx->nic_rb, dev_name)) != 0)
	{
		/* If something goes wrong here, the create PCAP must be deleted */
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

