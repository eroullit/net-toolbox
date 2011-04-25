#ifndef __PACKET_COMPAT_H__
#define __PACKET_COMPAT_H__

#include <stdint.h>

struct packet
{
	size_t 		mtu;
	size_t 		len;
	uint8_t *	buf;
};

struct packet_compat_ctx
{
	int 		sock;
	int 		ifindex;
	size_t		used;
	size_t		total;
	struct packet * pkt;
};

void packet_compat_ctx_destroy(struct packet_compat_ctx * pkt_ctx);
int packet_compat_ctx_create(struct packet_compat_ctx * pkt_ctx, const size_t pkt_nr, const size_t mtu, const int ifindex, const int sock);
void packet_compat_ctx_reset(struct packet_compat_ctx * pkt_ctx);
int packet_compat_ctx_is_full(const struct packet_compat_ctx * const pkt_ctx);
int packet_compat_ctx_next(struct packet_compat_ctx * pkt_ctx);
struct packet * packet_compat_ctx_get(struct packet_compat_ctx * pkt_ctx);

#endif /* __PACKET_COMPAT_H__ */
