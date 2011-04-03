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


#ifndef _NET_TX_RING_H_
#define _NET_TX_RING_H_

#include <stdlib.h>
#include <assert.h>
#include <net/if.h>
#include <sys/queue.h>
#include <sys/poll.h>

#include <netcore-ng/macros.h>
#include <netcore-ng/types.h>
#include <netcore-ng/thread.h>
#include <netcore-ng/rx_job.h> 
#include <netcore-ng/rx_generic.h>

/* a tx ring must only belong to one entity */
struct netsniff_ng_tx_nic_context
{
	struct rx_generic_nic_context		generic;
	struct ring_buff			nic_rb;
};

struct netsniff_ng_tx_thread_context
{
	struct netsniff_ng_thread_context	thread_ctx;
	struct netsniff_ng_tx_nic_context	nic_ctx;
};

/* Function signatures */
extern struct netsniff_ng_tx_thread_context * tx_thread_create(const cpu_set_t run_on, const int sched_prio, const int sched_policy, const char * tx_dev, const char * bpf_path, const char * pcap_path);
extern void tx_thread_destroy(struct netsniff_ng_tx_thread_context * thread_config);


#define DEFAULT_TX_RING_SILENT_MESSAGE "Transmitting ... |"

#endif				/* _NET_TX_RING_H_ */
