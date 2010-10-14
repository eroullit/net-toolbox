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

#include "bpf.h"
#include "cursor.h"
#include "dump.h"
#include "macros.h"
#include "types.h"
#include "rx_ring_compat.h"
#include "netdev.h"
#include "xmalloc.h"
#include "strlcpy.h"

static int bind_dev_to_sock(const char * dev, int sock)
{
	struct sockaddr saddr = { 0 };
        int rc;

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
	struct timeval          now;
	struct sockaddr_ll      from = {0};
	struct tpacket_hdr tp_h = {0};
        socklen_t               from_len = sizeof(from);
	ssize_t pkt_len;

	if (thread_ctx == NULL)
	{
		pthread_exit(NULL);
	}

	nic_ctx = &thread_ctx->nic_ctx;

	info("--- Listening (Compatibility mode)---\n\n");

	for(;;)
	{
		pkt_len = recvfrom(nic_ctx->dev_fd, nic_ctx->pkt_buf, nic_ctx->pkt_buf_len, MSG_TRUNC, (struct sockaddr *) &from, &from_len);

		if (errno == EINTR)
                        break;

		gettimeofday(&now, NULL);

                tp_h.tp_sec = now.tv_sec;
                tp_h.tp_usec = now.tv_usec;
                tp_h.tp_len = tp_h.tp_snaplen = pkt_len;

		if (nic_ctx->pcap_fd > 0)
		{
			pcap_write_payload(nic_ctx->pcap_fd, &tp_h, (struct ethhdr *) nic_ctx->pkt_buf);
		}
	}

	pthread_exit(NULL);
}

void destroy_rx_nic_compat_ctx(struct netsniff_ng_rx_nic_compat_context * nic_ctx)
{
	assert(nic_ctx);
	
	if (nic_ctx->bpf.filter)
	{
		reset_kernel_bpf(nic_ctx->dev_fd);
		free(nic_ctx->bpf.filter);
	}

	if (nic_ctx->pkt_buf)
		xfree(nic_ctx->pkt_buf);

	close(nic_ctx->dev_fd);
	close(nic_ctx->pcap_fd);
}

int init_rx_nic_compat_ctx(struct netsniff_ng_rx_thread_compat_context * thread_ctx, const char * rx_dev, const char * bpf_path, const char * pcap_path)
{
	struct netsniff_ng_rx_nic_compat_context * nic_ctx = NULL;
	int rc;

	assert(thread_ctx);
	assert(rx_dev);

	nic_ctx = &thread_ctx->nic_ctx;

	if (!is_device_ready(rx_dev))
	{
		warn("Device %s is not ready\n", rx_dev);
		return (EAGAIN);
	}

	strlcpy(nic_ctx->rx_dev, rx_dev, IFNAMSIZ);
	nic_ctx->pkt_buf_len = get_mtu(nic_ctx->rx_dev);

	nic_ctx->pkt_buf = xzmalloc(nic_ctx->pkt_buf_len);

	if ((nic_ctx->dev_fd = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0)
	{
		warn("Could not open socket for %s\n", nic_ctx->rx_dev);
		rc = EPERM;
		goto error;
	}

	if (bind_dev_to_sock(rx_dev, nic_ctx->dev_fd))
	{
		warn("Could not dev %s to socket\n", nic_ctx->rx_dev);
		rc = EAGAIN;
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
			remove_pcap(nic_ctx->pcap_fd, pcap_path);
			rc = EINVAL;
			goto error;
		}
	}

	return(0);
error:
	destroy_rx_nic_compat_ctx(nic_ctx);
	return(rc);
}

void destroy_rx_thread_compat(struct netsniff_ng_rx_thread_compat_context * thread_config)
{
	assert(thread_config);

	if (thread_config->thread_ctx.thread)
		pthread_cancel(thread_config->thread_ctx.thread);
	
	destroy_thread_context(&thread_config->thread_ctx);
	destroy_rx_nic_compat_ctx(&thread_config->nic_ctx);
	xfree(thread_config);
}

struct netsniff_ng_rx_thread_compat_context * create_rx_thread_compat(const cpu_set_t run_on, const int sched_prio, const int sched_policy, const char * rx_dev, const char * bpf_path, const char * pcap_path)
{
	int rc;
	struct netsniff_ng_rx_thread_compat_context * thread_config = NULL;

	thread_config = xzmalloc(sizeof(*thread_config));

	memset(thread_config, 0, sizeof(*thread_config));

	if ((rc = init_thread_context(&thread_config->thread_ctx, run_on, sched_prio, sched_policy, RX_THREAD_COMPAT)) != 0)
	{
		warn("Cannot initialize thread\n");
		goto error;
	}

	if ((rc = init_rx_nic_compat_ctx(thread_config, rx_dev, bpf_path, pcap_path)) != 0)
	{
		warn("Cannot initialize RX NIC context\n");
		goto error;
	}

	pthread_create(&thread_config->thread_ctx.thread, &thread_config->thread_ctx.thread_attr, rx_thread_compat_listen, thread_config);

	return (thread_config);
error:
	destroy_rx_thread_compat(thread_config);
	return (NULL);
}

