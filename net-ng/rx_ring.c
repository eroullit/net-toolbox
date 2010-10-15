/*
 * Copyright (C) 2009, 2010  Daniel Borkmann <daniel@netsniff-ng.org> and 
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
 */

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

#include <net-ng/pcap.h>
#include <net-ng/cursor.h>
#include <net-ng/dump.h>
#include <net-ng/macros.h>
#include <net-ng/types.h>
#include <net-ng/rx_ring.h>
#include <net-ng/rxtx_common.h>
#include <net-ng/netdev.h>
#include <net-ng/bpf.h>
#include <net-ng/xmalloc.h>
#include <net-ng/strlcpy.h>

static int register_rx_ring(int sock, struct tpacket_req * req)
{
	/* Loop to reduce requested ring buffer is it cannot be allocated */
	/* Break when not supported */

	if (setsockopt(sock, SOL_PACKET, PACKET_RX_RING, (void *)(req), sizeof(*req)) < 0) {
		err("setsockopt: creation of rx_ring failed");
		return (EAGAIN);
	}

	return (0);
}

static void unregister_rx_ring(int sock)
{
	struct tpacket_req req = {0};
	setsockopt(sock, SOL_PACKET, PACKET_RX_RING, (void *)&req, sizeof(req));
}

static int mmap_rx_ring(int sock, struct ring_buff * rb)
{
	assert(rb);

	rb->buffer = mmap(0, rb->size, PROT_READ | PROT_WRITE, MAP_SHARED, sock, 0);
	if (rb->buffer == MAP_FAILED) {
		err("mmap: cannot mmap the rx_ring");
		return (EINVAL);
	}

	return (0);
}

static void munmap_rx_ring(struct ring_buff * rb)
{
	assert(rb);

	if (rb->buffer)
	{
		munmap(rb->buffer, rb->size);
		rb->buffer = NULL;
		rb->size = 0;
	}
}

static int bind_dev_to_rx_ring(int sock, int ifindex)
{
	struct sockaddr_ll sll = {0};

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

static void * rx_thread_listen(void * arg)
{
	struct pollfd pfd = {0};
	int rc;
	uint8_t * pkt_buf = NULL;
	struct frame_map * fm = NULL;
	struct netsniff_ng_rx_thread_context * thread_ctx = (struct netsniff_ng_rx_thread_context *) arg;
	struct netsniff_ng_rx_nic_context * nic_ctx = NULL;
	struct ring_buff * rb = NULL;

	if (thread_ctx == NULL)
	{
		pthread_exit(NULL);
	}

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	pfd.events = POLLIN|POLLRDNORM|POLLERR;
	
	nic_ctx = &thread_ctx->nic_ctx;
	rb = &nic_ctx->nic_rb;
	pfd.fd = nic_ctx->dev_fd;


	info("--- Listening ---\n\n");

	for(;;)
	{
		while (rb->cur_frame < rb->layout.tp_frame_nr)
		{
			fm = rb->frames[rb->cur_frame].iov_base;

			if (fm->tp_h.tp_status == TP_STATUS_KERNEL)
			{
				/* Force sleep here when the user wants */
				if ((rc = poll(&pfd, 1, -1)) < 0)
				{
					err("polling error %i", rc);
					continue;
				}
			}

			/* TODO Add support for TP_STATUS_COPY */
			if (fm->tp_h.tp_status == TP_STATUS_USER)
			{
				pkt_buf = ((uint8_t *)fm) + fm->tp_h.tp_mac;
				info("Process frame %zu/%u state : %lu on %s: %u bytes %p\n", rb->cur_frame, rb->layout.tp_frame_nr, fm->tp_h.tp_status, nic_ctx->rx_dev, fm->tp_h.tp_len, pkt_buf);

				if (nic_ctx->pcap_fd > 0)
					pcap_write_payload(nic_ctx->pcap_fd, &fm->tp_h, (struct ethhdr *)pkt_buf);
			}
	
			fm->tp_h.tp_status = TP_STATUS_KERNEL;
			rb->cur_frame = (rb->cur_frame + 1) % rb->layout.tp_frame_nr;
		}
	}

	pthread_exit(NULL);
}


static int create_rx_ring(int sock, struct ring_buff * rb, const char *ifname)
{
	struct tpacket_req req = {0};

	assert(rb);
	assert(ifname);

	/* max: getpagesize() << 11 for i386 */
	req.tp_block_size = getpagesize() << 2;

	/* tp_frame_size should be carefully chosen to fit closely to snapshot len */
	req.tp_frame_size = TPACKET_ALIGNMENT << 7;

	req.tp_block_nr = ((1024 * 1024) / req.tp_block_size);
	req.tp_frame_nr = req.tp_block_size / req.tp_frame_size * req.tp_block_nr;

	if (register_rx_ring(sock, &req))
	{
		err("Cannot register RX ring buffer for %s", ifname);
		return (EAGAIN);
	}

	rb->size = req.tp_block_size * req.tp_block_nr;

	if (mmap_rx_ring(sock, rb))
	{
		unregister_rx_ring(sock);
		err("Cannot prepare RX ring buffer for interface %s for userspace", ifname);
		return (EAGAIN);
	}

	if (create_frame_buffer(rb, req))
	{
		munmap_rx_ring(rb);
		unregister_rx_ring(sock);
		err("Cannot allocate RX ring buffer frame buffer for %s", ifname);
		return (ENOMEM);
	}

	if (bind_dev_to_rx_ring(sock, ethdev_to_ifindex(ifname)))
	{
		destroy_frame_buffer(rb);
		munmap_rx_ring(rb);
		unregister_rx_ring(sock);
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

static void destroy_rx_ring(int sock, struct ring_buff * rb)
{
	assert(rb);

	munmap_rx_ring(rb);
	unregister_rx_ring(sock);
	destroy_frame_buffer(rb);
}


static void destroy_rx_nic_ctx(struct netsniff_ng_rx_nic_context * nic_ctx)
{
	assert(nic_ctx);

	destroy_rx_ring(nic_ctx->dev_fd, &nic_ctx->nic_rb);

	/* 
	 * If there is a BPF filter loaded, then it
	 * must be unbound from the device and freed
	 */

	if (nic_ctx->bpf.filter)
	{
		reset_kernel_bpf(nic_ctx->dev_fd);
		free(nic_ctx->bpf.filter);
	}

	close(nic_ctx->dev_fd);
	close(nic_ctx->pcap_fd);
}

static int init_rx_nic_ctx(struct netsniff_ng_rx_thread_context * thread_ctx, const char * rx_dev, const char * bpf_path, const char * pcap_path)
{
	struct netsniff_ng_rx_nic_context * nic_ctx = NULL;
	int rc = 0;

	assert(thread_ctx);
	assert(rx_dev);

	nic_ctx = &thread_ctx->nic_ctx;

	if (!is_device_ready(rx_dev))
	{
		warn("Device %s is not ready\n", rx_dev);
		return (EAGAIN);
	}

	strlcpy(nic_ctx->rx_dev, rx_dev, IFNAMSIZ);
	nic_ctx->dev_fd = get_pf_socket();
	
	if (nic_ctx->dev_fd < 0)
	{
		warn("Could not open PF_PACKET socket\n");
		rc = EPERM;
		goto error;
	}

	if (bpf_path)
	{
		if(parse_rules(bpf_path, &nic_ctx->bpf) == 0)
		{
			warn("Could not parse BPF file %s\n", bpf_path);
			rc = EINVAL;
			goto error;
		}

		inject_kernel_bpf(nic_ctx->dev_fd, &nic_ctx->bpf);
	}

	if (pcap_path)
	{
		if ((nic_ctx->pcap_fd = prepare_pcap(pcap_path)) < 0)
		{
			warn("Failed to prepare pcap : %s\n", pcap_path);
			rc = EINVAL;
			goto error;
		}
	}

	if ((rc = create_rx_ring(nic_ctx->dev_fd, &nic_ctx->nic_rb, rx_dev)) != 0)
	{
		/* If something goes wrong here, the create PCAP must be deleted */
		remove_pcap(nic_ctx->pcap_fd, pcap_path);
		goto error;
	}

	return(0);

error:
	destroy_rx_nic_ctx(nic_ctx);
	return (rc);
}

void destroy_rx_thread(struct netsniff_ng_rx_thread_context * thread_config)
{
	assert(thread_config);

	if (thread_config->thread_ctx.thread)
		pthread_cancel(thread_config->thread_ctx.thread);

	destroy_thread_context(&thread_config->thread_ctx);
	destroy_rx_nic_ctx(&thread_config->nic_ctx);
	xfree(thread_config);
}

struct netsniff_ng_rx_thread_context * create_rx_thread(const cpu_set_t run_on, const int sched_prio, const int sched_policy, const char * rx_dev, const char * bpf_path, const char * pcap_path)
{
	int rc;
	struct netsniff_ng_rx_thread_context * thread_config = NULL;

	if ((thread_config = xzmalloc(sizeof(*thread_config))) == NULL)
	{
		warn("Cannot allocate rx thread configuration\n");
		return (NULL);
	}

	if ((rc = init_thread_context(&thread_config->thread_ctx, run_on, sched_prio, sched_policy, RX_THREAD)) != 0)
	{
		goto error;
	}

	if ((rc = init_rx_nic_ctx(thread_config, rx_dev, bpf_path, pcap_path)) != 0)
	{
		warn("Cannot initialize RX NIC context\n");
		goto error;
	}

	if ((rc = pthread_create(&thread_config->thread_ctx.thread, &thread_config->thread_ctx.thread_attr, rx_thread_listen, thread_config)))
	{
		warn("Could not start RX thread\n")
		goto error;
	}

	return (thread_config);

error:
	destroy_rx_thread(thread_config);
	return (NULL);
}

