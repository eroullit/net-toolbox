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

#include <net/if.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/types.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>

#include <netcore-ng/strlcpy.h>
#include <netcore-ng/xmalloc.h>
#include <netcore-ng/pcap.h>
#include <netcore-ng/netdev.h>
#include <netcore-ng/bpf.h>
#include <netcore-ng/tx_ring.h>

static int tx_ring_register(int sock, struct tpacket_req * req)
{
	/* Loop to reduce requested ring buffer is it cannot be allocated */
	/* Break when not supported */

	if (setsockopt(sock, SOL_PACKET, PACKET_TX_RING, (void *)(req), sizeof(*req)) < 0) {
		err("setsockopt: creation of tx_ring failed");
		return (EAGAIN);
	}

	return (0);
}

static void tx_ring_unregister(int sock)
{
	struct tpacket_req req;

	memset(&req, 0, sizeof(req));

	setsockopt(sock, SOL_PACKET, PACKET_TX_RING, (void *)&req, sizeof(req));
}

static int tx_ring_mmap(int sock, struct ring_buff * rb)
{
	assert(rb);

	rb->buffer = mmap(0, rb->size, PROT_READ | PROT_WRITE, MAP_SHARED, sock, 0);
	if (rb->buffer == MAP_FAILED) {
		err("mmap: cannot mmap the tx_ring");
		return (EINVAL);
	}

	return (0);
}

static void tx_ring_munmap(struct ring_buff * rb)
{
	assert(rb);

	if (rb->buffer)
	{
		munmap(rb->buffer, rb->size);
		rb->buffer = NULL;
		rb->size = 0;
	}
}

static int tx_ring_bind(int sock, int ifindex)
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

static int packet_loss_discard_set(int sock)
{
	int ret;
	int foo = 1;		/* we discard wrong packets */

	ret = setsockopt(sock, SOL_PACKET, PACKET_LOSS, (void *)&foo, sizeof(foo));
	
	if (ret < 0) {
		err("setsockopt: cannot set packet loss");
	}

	return (ret);
}

static void * tx_thread_listen(void * arg)
{
	struct pollfd pfd;
	struct tpacket_hdr *header = NULL;
	int ret = 0;
	uint32_t pkt_put = 0;
	uint32_t i = 0;
	struct netsniff_ng_tx_thread_context * thread_ctx = (struct netsniff_ng_tx_thread_context *) arg;
	struct netsniff_ng_tx_nic_context * nic_ctx = NULL;
	struct packet_ctx pkt_ctx;
	struct ring_buff * rb = NULL;

	if (thread_ctx == NULL)
	{
		pthread_exit(NULL);
	}

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	
	nic_ctx = &thread_ctx->nic_ctx;
	rb = &nic_ctx->nic_rb;
	
	/* XXX packet context should go in NIC context */
	memset(&pkt_ctx, 0, sizeof(pkt_ctx));

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = nic_ctx->dev_fd;
	pfd.events = POLLOUT;

	info("--- Transmitting ---\n\n");

	do {
		for (i = 0; i < rb->layout.tp_block_nr; i++) {
			header = (struct tpacket_hdr *)rb->frames[i].iov_base;
			pkt_ctx.pkt_buf = (uint8_t *) ((uintptr_t) header + TPACKET_HDRLEN - sizeof(struct sockaddr_ll));
			pkt_ctx.pkt_len = header->tp_len;
			pkt_ctx.pkt_snaplen = header->tp_snaplen;
			pkt_ctx.pkt_ts.tv_sec = header->tp_sec;
			pkt_ctx.pkt_ts.tv_usec = header->tp_usec;

			info("Slot %u/%u %lx\n", i + 1, rb->layout.tp_block_nr, header->tp_status);

			switch ((volatile uint32_t)header->tp_status) {
			case TP_STATUS_AVAILABLE:
				while ((pkt_ctx.pkt_len =
					pcap_fetch_next_packet(nic_ctx->pcap_fd, &pkt_ctx)) != 0) {
					/* If the fetch packet does not match the BPF, take the next one */
					if (bpf_filter(&nic_ctx->bpf, pkt_ctx.pkt_buf, pkt_ctx.pkt_len)) {
						break;
					}
				}

				/* No packets to replay or error, time to exit */
				if (pkt_ctx.pkt_len == 0)
					goto flush_pkt;

				/* Mark packet as ready to send */
				header->tp_status = TP_STATUS_SEND_REQUEST;
				pkt_put++;
				break;

			case TP_STATUS_WRONG_FORMAT:
				warn("An error during transfer!\n");
				exit(EXIT_FAILURE);
				break;

			default:
				break;
			}
		}

flush_pkt:
		ret = send(nic_ctx->dev_fd, NULL, 0, MSG_DONTWAIT);

		info("send() returned %i: %s\n", ret, strerror(errno));

		if (ret < 0) {
			err("Cannot flush tx_ring with send");
		}

		/* Now we wait that the kernel place all packet on the medium */
		ret = poll(&pfd, 1, -1);
		
		if (ret < 0)
			err("An error occured while polling on %s\n", nic_ctx->tx_dev);

	} while (pkt_ctx.pkt_len);

	info("Placed %u packets\n", pkt_put);
	pthread_exit(NULL);
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

static int tx_ring_create(int sock, struct ring_buff * rb, const char *ifname)
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

	if (tx_ring_register(sock, &req))
	{
		err("Cannot register TX ring buffer for %s", ifname);
		return (EAGAIN);
	}

	rb->size = req.tp_block_size * req.tp_block_nr;

	if (tx_ring_mmap(sock, rb))
	{
		tx_ring_unregister(sock);
		err("Cannot prepare TX ring buffer for interface %s for userspace", ifname);
		return (EAGAIN);
	}

	if (frame_buffer_create(rb, req))
	{
		tx_ring_munmap(rb);
		tx_ring_unregister(sock);
		err("Cannot allocate TX ring buffer frame buffer for %s", ifname);
		return (ENOMEM);
	}

	if (tx_ring_bind(sock, ethdev_to_ifindex(ifname)))
	{
		frame_buffer_destroy(rb);
		tx_ring_munmap(rb);
		tx_ring_unregister(sock);
		err("Cannot bind %s to TX ring buffer frame buffer", ifname);
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

static void tx_ring_destroy(int sock, struct ring_buff * rb)
{
	assert(rb);

	tx_ring_munmap(rb);
	tx_ring_unregister(sock);
	frame_buffer_destroy(rb);
}


static void tx_nic_ctx_destroy(struct netsniff_ng_tx_nic_context * nic_ctx)
{
	assert(nic_ctx);

	tx_ring_destroy(nic_ctx->dev_fd, &nic_ctx->nic_rb);

	/* 
	 * If there is a BPF filter loaded, then it
	 * must be unbound from the device and freed
	 */

	if (nic_ctx->bpf.filter)
	{
		bpf_kernel_reset(nic_ctx->dev_fd);
		free(nic_ctx->bpf.filter);
	}

	close(nic_ctx->dev_fd);
	close(nic_ctx->pcap_fd);
}

static int tx_nic_ctx_init(struct netsniff_ng_tx_thread_context * thread_ctx, const char * tx_dev, const char * bpf_path, const char * pcap_path)
{
	struct netsniff_ng_tx_nic_context * nic_ctx = NULL;
	int rc = 0;

	assert(thread_ctx);
	assert(tx_dev);

	nic_ctx = &thread_ctx->nic_ctx;

	if (!is_device_ready(tx_dev))
	{
		warn("Device %s is not ready\n", tx_dev);
		return (EAGAIN);
	}

	strlcpy(nic_ctx->tx_dev, tx_dev, IFNAMSIZ);
	nic_ctx->dev_fd = get_pf_socket();
	
	if (nic_ctx->dev_fd < 0)
	{
		warn("Could not open PF_PACKET socket\n");
		rc = EPERM;
		goto error;
	}
	
	if ((rc = packet_loss_discard_set(nic_ctx->dev_fd)) != 0)
	{
		goto error;
	}

	if (bpf_path)
	{
		if(bpf_parse(bpf_path, &nic_ctx->bpf) == 0)
		{
			warn("Could not parse BPF file %s\n", bpf_path);
			rc = EINVAL;
			goto error;
		}

		bpf_kernel_inject(nic_ctx->dev_fd, &nic_ctx->bpf);
	}

	if (pcap_path)
	{
		if ((nic_ctx->pcap_fd = pcap_open(pcap_path, O_RDONLY)) < 0)
		{
			warn("Failed to prepare pcap : %s\n", pcap_path);
			rc = EINVAL;
			goto error;
		}
	}

	if ((rc = tx_ring_create(nic_ctx->dev_fd, &nic_ctx->nic_rb, tx_dev)) != 0)
	{
		goto error;
	}


	return(0);

error:
	tx_nic_ctx_destroy(nic_ctx);
	return (rc);
}

void tx_thread_destroy(struct netsniff_ng_tx_thread_context * thread_config)
{
	assert(thread_config);

	if (thread_config->thread_ctx.thread)
		pthread_cancel(thread_config->thread_ctx.thread);

	thread_context_destroy(&thread_config->thread_ctx);
	tx_nic_ctx_destroy(&thread_config->nic_ctx);
	xfree(thread_config);
}

struct netsniff_ng_tx_thread_context * tx_thread_create(const cpu_set_t run_on, const int sched_prio, const int sched_policy, const char * tx_dev, const char * bpf_path, const char * pcap_path)
{
	int rc;
	struct netsniff_ng_tx_thread_context * thread_config = NULL;

	if ((thread_config = xzmalloc(sizeof(*thread_config))) == NULL)
	{
		warn("Cannot allocate tx thread configuration\n");
		return (NULL);
	}

	if ((rc = thread_context_init(&thread_config->thread_ctx, run_on, sched_prio, sched_policy, TX_THREAD)) != 0)
	{
		goto error;
	}

	if ((rc = tx_nic_ctx_init(thread_config, tx_dev, bpf_path, pcap_path)) != 0)
	{
		warn("Cannot initialize TX NIC context\n");
		goto error;
	}

	if ((rc = pthread_create(&thread_config->thread_ctx.thread, &thread_config->thread_ctx.thread_attr, tx_thread_listen, thread_config)))
	{
		warn("Could not start TX thread\n");
		goto error;
	}

	return (thread_config);

error:
	tx_thread_destroy(thread_config);
	return (NULL);
}

