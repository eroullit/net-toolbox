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

#ifndef _NET_RX_RING_COMPAT_H_
#define _NET_RX_RING_COMPAT_H_

#include <net/if.h>
#include <net-ng/bpf.h>
#include <net-ng/thread.h>

/* a rx ring must only belong to one entity */
struct netsniff_ng_rx_nic_compat_context
{
	/* Structure which describe a nic instead? */
	char 					rx_dev[IFNAMSIZ];
	/* Maybe multiple ring buffer for one device */
	uint32_t				flags;
	int					dev_fd;
	int 					pcap_fd;
	struct sock_fprog 			bpf;
	size_t					pkt_buf_len;
	uint8_t	*				pkt_buf;
};

struct netsniff_ng_rx_thread_compat_context
{
	struct netsniff_ng_thread_context		thread_ctx;
	struct netsniff_ng_rx_nic_compat_context	nic_ctx;
};

/* Function signatures */
extern struct netsniff_ng_rx_thread_compat_context * create_rx_thread_compat(const cpu_set_t run_on, const int sched_prio, const int sched_policy, const char * rx_dev, const char * bpf_path, const char * pcap_path);
extern void destroy_rx_thread_compat(struct netsniff_ng_rx_thread_compat_context * thread_config);

#define DEFAULT_RX_RING_COMPAT_SILENT_MESSAGE "Receive ring dumping (Compatibility mode)... |"

#endif				/* _NET_RX_RING_COMPAT_H_ */
