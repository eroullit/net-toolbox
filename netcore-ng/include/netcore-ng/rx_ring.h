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


#ifndef _NET_RX_RING_H_
#define _NET_RX_RING_H_

#include <netcore-ng/nic.h>
#include <netcore-ng/packet_mmap.h>

struct rx_thread_ctx
{
	struct packet_mmap_ctx 	pkt_mmap;
	struct nic_ctx		nic;
};

struct rx_thread_ctx * rx_thread_create(const char * const dev_name);
void rx_thread_destroy(struct rx_thread_ctx * thread_config);

#endif				/* _NET_RX_RING_H_ */
