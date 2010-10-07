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

#ifndef _NET_RX_RING_H_
#define _NET_RX_RING_H_

#include <stdlib.h>
#include <assert.h>
#include <net/if.h>
#include <sys/queue.h>

#include "macros.h"
#include "types.h"
#include "thread.h"
#include "rxtx_common.h"
#include "config.h"

/* Function signatures */
/* a rx ring must only belong to one entity */
struct netsniff_ng_rx_nic_context
{
	struct pollfd 				pfd;
	/* Structure which describe a nic instead? */
	char 					rx_dev[IFNAMSIZ];
	/* Maybe multiple ring buffer for one device */
	uint32_t				flags;
	int					dev_fd;
	int 					pcap_fd;
	struct sock_fprog 			bpf;
	struct ring_buff			nic_rb;
};

struct netsniff_ng_rx_thread_context
{
	struct netsniff_ng_thread_context	thread_ctx;
	struct netsniff_ng_rx_nic_context	nic_ctx;
};

/* Function signatures */
extern struct netsniff_ng_rx_thread_context * create_rx_thread(const cpu_set_t run_on, const int sched_prio, const int sched_policy, const char * rx_dev, const char * bpf_path, const char * pcap_path);
extern void destroy_rx_thread(struct netsniff_ng_rx_thread_context * thread_config);


#define DEFAULT_RX_RING_SILENT_MESSAGE "Receive ring dumping ... |"

/* Inline stuff */

/**
 * mem_notify_user_for_rx - Checks whether kernel has written its data into our 
 *                          virtual RX_RING
 * @frame:                 ethernet frame data
 */
static inline int mem_notify_user_for_rx(struct iovec frame)
{
	struct tpacket_hdr *header = frame.iov_base;
	return (header->tp_status == TP_STATUS_USER);
}

/**
 * mem_notify_kernel_for_rx - We tell the kernel that we are done with processing 
 *                            data from our virtual RX_RING
 * @header:                  packet header with status flag
 */
static inline void mem_notify_kernel_for_rx(struct tpacket_hdr *header)
{
	assert(header);
	header->tp_status = TP_STATUS_KERNEL;
	barrier();
}

#endif				/* _NET_RX_RING_H_ */
