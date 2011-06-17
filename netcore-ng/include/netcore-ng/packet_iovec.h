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


#ifndef	__PACKET_H__
#define __PACKET_H__

#include <stdint.h>
#include <sys/uio.h>

#include <netcore-ng/pcap.h>

struct packet_iovec
{
	size_t			used;
	size_t			total;
	struct pcap_sf_pkthdr *	pkt_pcap_hdr;
	struct iovec *		pkt_io_vec;
};

void packet_iovec_reset(struct packet_iovec * pkt_vec);
void packet_iovec_destroy(struct packet_iovec * pkt_vec);
int packet_iovec_create(struct packet_iovec * pkt_vec, const size_t pkt_nr);
int packet_iovec_end(const struct packet_iovec * const pkt_vec);

uint8_t * packet_iovec_packet_payload_get(const struct packet_iovec * const pkt_vec);
size_t packet_iovec_packet_length_get(const struct packet_iovec * const pkt_vec);
int packet_iovec_next(struct packet_iovec * pkt_vec);
void packet_iovec_set(struct packet_iovec * pkt_vec, uint8_t * pkt, const size_t len, const struct timeval * ts);
#endif				/* __PACKET_H__ */
