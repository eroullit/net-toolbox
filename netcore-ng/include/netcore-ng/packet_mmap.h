#ifndef __PACKET_MMAP_H__
#define __PACKET_MMAP_H__

#include <stdint.h>
#include <linux/if_packet.h>

enum packet_mmap_ctx_type
{
	PACKET_MMAP_RX = PACKET_RX_RING,
	PACKET_MMAP_TX = PACKET_TX_RING
};

struct packet_mmap_ctx
{
	enum tpacket_versions 		version;
	enum packet_mmap_ctx_type 	type;
	int 				sock;
	int 				ifindex;
	struct tpacket_req		layout;
	size_t 				used;
	struct iovec *			mmap_vec;
	uint8_t *			mmap_buf;
};

struct packet_mmap_header 
{
	struct tpacket_hdr tp_h __attribute__ ((aligned(TPACKET_ALIGNMENT)));
	struct sockaddr_ll s_ll __attribute__ ((aligned(TPACKET_ALIGNMENT)));
};

#endif /* __PACKET_MMAP_H__ */
