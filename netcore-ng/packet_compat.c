#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <netcore-ng/packet_compat.h>

void packet_compat_ctx_destroy(struct packet_compat_ctx * pkt_ctx)
{
	size_t a;

	for (a = 0; a < pkt_ctx->total; a++)
		free(pkt_ctx->pkt[a].buf);

	free(pkt_ctx->pkt);
}

int packet_compat_ctx_create(struct packet_compat_ctx * pkt_ctx, const size_t pkt_nr, const size_t mtu, const int ifindex, const int sock)
{
	size_t a;
	int rc = 0;

	assert(pkt_ctx);
	assert(pkt_nr);
	assert(mtu);
	assert(sock);

	memset(pkt_ctx, 0, sizeof(*pkt_ctx));
	pkt_ctx->ifindex = ifindex;
	pkt_ctx->sock = sock;

	pkt_ctx->pkt = calloc(pkt_nr, sizeof(*pkt_ctx->pkt));

	if (!pkt_ctx->pkt)
	{
		rc = ENOMEM;
		goto out;
	}

	pkt_ctx->total = pkt_nr;

	for (a = 0; a < pkt_ctx->total; a++)
	{
		pkt_ctx->pkt[a].buf = calloc(mtu, sizeof(*pkt_ctx->pkt[a].buf));

		if (!pkt_ctx->pkt[a].buf)
		{
			rc = ENOMEM;
			goto out;
		}

		pkt_ctx->pkt[a].mtu = mtu;
	}

	return (0);
out:
	packet_compat_ctx_destroy(pkt_ctx);
	return (rc);
}

void packet_compat_ctx_reset(struct packet_compat_ctx * pkt_ctx)
{
	size_t a;
	
	assert(pkt_ctx);

	for (a = 0; a < pkt_ctx->total; a++)
	{
		memset(pkt_ctx->pkt[a].buf, 0, sizeof(*pkt_ctx->pkt[a].buf) * pkt_ctx->pkt[a].mtu);
		pkt_ctx->pkt[a].len = 0;
	}
	
	pkt_ctx->used = 0;
}

int packet_compat_ctx_end(const struct packet_compat_ctx * const pkt_ctx)
{
	assert(pkt_ctx);
	return (pkt_ctx->used >= pkt_ctx->total);
}

int packet_compat_ctx_next(struct packet_compat_ctx * pkt_ctx)
{
	if (packet_compat_ctx_end(pkt_ctx))
		return (EAGAIN);

	pkt_ctx->used++;

	return (0);
}

struct packet * packet_compat_ctx_get(struct packet_compat_ctx * pkt_ctx)
{
	assert(pkt_ctx);
	return (&pkt_ctx->pkt[pkt_ctx->used]);
}
