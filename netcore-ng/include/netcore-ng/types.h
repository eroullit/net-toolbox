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


#ifndef _NET_TYPES_H_
#define _NET_TYPES_H_

#include <stdint.h>
#include <time.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

/*
 * Internal data structures
 */

struct ring_buff {
	struct tpacket_req layout;
	size_t	size;
	size_t	cur_frame;
	struct iovec *frames;
	uint8_t *buffer;
};

struct frame_map {
	struct tpacket_hdr tp_h __attribute__ ((aligned(TPACKET_ALIGNMENT)));
	struct sockaddr_ll s_ll __attribute__ ((aligned(TPACKET_ALIGNMENT)));
};

static inline uint8_t * frame_map_pkt_buf_get(const struct frame_map * fm)
{
	return ((uint8_t *)fm + fm->tp_h.tp_mac);
}

static inline void frame_map_pkt_status_kernel(struct frame_map * fm)
{
	fm->tp_h.tp_status = TP_STATUS_KERNEL;
}

static inline unsigned long frame_map_pkt_status_get(struct frame_map * fm)
{
	return (fm->tp_h.tp_status);
}

/*
 * Some external data structures (wich are used for
 * data transmission via a unix domain socket inode)
 */

struct fb_count {
	unsigned long long frames;
	unsigned long long bytes;
};

struct ring_buff_stat {
	struct fb_count total;
	struct fb_count per_sec;
	struct fb_count per_min;
	struct fb_count s_per_sec;
	struct fb_count s_per_min;
	uint16_t t_elapsed;
	struct timespec m_start;
};

#endif				/* _NET_TYPES_H_ */
