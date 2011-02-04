
#ifndef _NET_TYPES_H_
#define _NET_TYPES_H_

#include <stdint.h>

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
