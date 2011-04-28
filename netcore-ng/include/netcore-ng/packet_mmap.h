#ifndef __PACKET_MMAP_H__
#define __PACKET_MMAP_H__

#include <stdint.h>
#include <sys/time.h>
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

void packet_mmap_ctx_reset(struct packet_mmap_ctx * pkt_mmap_ctx);
int packet_mmap_ctx_is_full(const struct packet_mmap_ctx * pkt_mmap_ctx);
int packet_mmap_ctx_next(struct packet_mmap_ctx * pkt_mmap_ctx);
unsigned long packet_mmap_ctx_status_get(struct packet_mmap_ctx * pkt_mmap_ctx);
struct timeval packet_mmap_ctx_ts_get(struct packet_mmap_ctx * pkt_mmap_ctx);
uint8_t * packet_mmap_ctx_payload_get(struct packet_mmap_ctx * pkt_mmap_ctx);
size_t packet_mmap_ctx_payload_len_get(struct packet_mmap_ctx * pkt_mmap_ctx);

int packet_mmap_ctx_create(struct packet_mmap_ctx * pkt_mmap_ctx, const struct tpacket_req const * req, const int ifindex, const int sock, const enum packet_mmap_ctx_type type);
void packet_mmap_ctx_destroy(struct packet_mmap_ctx * pkt_mmap_ctx);

#endif /* __PACKET_MMAP_H__ */
