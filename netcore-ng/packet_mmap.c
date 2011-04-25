#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

#include <netcore-ng/macros.h>
#include <netcore-ng/packet_mmap.h>

static int packet_mmap_ctx_register(const struct packet_mmap_ctx * const pkt_mmap_ctx)
{
	assert(pkt_mmap_ctx);

	if (setsockopt(pkt_mmap_ctx->sock, SOL_PACKET, pkt_mmap_ctx->type, (void *)(&pkt_mmap_ctx->layout), sizeof(pkt_mmap_ctx->layout)) < 0) {
		err("Could not register packet mmap context");
		return (EAGAIN);
	}

	return (0);
}

static void packet_mmap_ctx_unregister(struct packet_mmap_ctx * pkt_mmap_ctx)
{
	assert(pkt_mmap_ctx);

	memset(&pkt_mmap_ctx->layout, 0, sizeof(pkt_mmap_ctx->layout));

	setsockopt(pkt_mmap_ctx->sock, SOL_PACKET, pkt_mmap_ctx->type, (void *)(&pkt_mmap_ctx->layout), sizeof(pkt_mmap_ctx->layout));
}

static int packet_mmap_ctx_mmap(struct packet_mmap_ctx * pkt_mmap_ctx)
{
	assert(pkt_mmap_ctx);

	pkt_mmap_ctx->mmap_buf = mmap(0, pkt_mmap_ctx->layout.tp_block_size * pkt_mmap_ctx->layout.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED, pkt_mmap_ctx->sock, 0);

	if (pkt_mmap_ctx->mmap_buf == MAP_FAILED)
	{
		err("Could not mmap the packet mmap context");
		return (EINVAL);
	}

	return (0);
}

static void packet_mmap_ctx_munmap(struct packet_mmap_ctx * pkt_mmap_ctx)
{
	assert(pkt_mmap_ctx);

	if (pkt_mmap_ctx->mmap_buf)
	{
		munmap(pkt_mmap_ctx->mmap_buf, pkt_mmap_ctx->layout.tp_block_size * pkt_mmap_ctx->layout.tp_block_nr);
		pkt_mmap_ctx->mmap_buf = NULL;
	}
}

static int packet_mmap_ctx_bind(const struct packet_mmap_ctx * const pkt_mmap_ctx)
{
	struct sockaddr_ll sll;
	
	assert(pkt_mmap_ctx);

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = pkt_mmap_ctx->ifindex;

	if (bind(pkt_mmap_ctx->sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		err("Could not bind packet mmap context to device");
		return (EINVAL);
	}

	/* Check error and if dev is ready */

	return (0);
}

static int packet_mmap_ctx_vector_create(struct packet_mmap_ctx * pkt_mmap_ctx)
{
	size_t a;

	assert(pkt_mmap_ctx);
	assert(pkt_mmap_ctx->mmap_buf);

	pkt_mmap_ctx->mmap_vec = calloc(pkt_mmap_ctx->layout.tp_frame_nr, sizeof(*pkt_mmap_ctx->mmap_vec));

	if (!pkt_mmap_ctx->mmap_vec)
	{
		err("Could not allocate packet mmap I/O vectors");
		return (ENOMEM);
	}

	for (a = 0; a < pkt_mmap_ctx->layout.tp_frame_nr; a++)
	{
		pkt_mmap_ctx->mmap_vec[a].iov_base = &pkt_mmap_ctx->mmap_buf[a * pkt_mmap_ctx->layout.tp_frame_size];
		pkt_mmap_ctx->mmap_vec[a].iov_len = pkt_mmap_ctx->layout.tp_frame_size;
	}

	return (0);
}

static void packet_mmap_ctx_vector_destroy(struct packet_mmap_ctx * pkt_mmap_ctx)
{
	assert(pkt_mmap_ctx);
	free(pkt_mmap_ctx->mmap_vec);
}

void packet_mmap_ctx_destroy(struct packet_mmap_ctx * pkt_mmap_ctx)
{
	assert(pkt_mmap_ctx);

	packet_mmap_ctx_vector_destroy(pkt_mmap_ctx);
	packet_mmap_ctx_munmap(pkt_mmap_ctx);
	packet_mmap_ctx_unregister(pkt_mmap_ctx);

	memset(pkt_mmap_ctx, 0, sizeof(*pkt_mmap_ctx));
}

int packet_mmap_ctx_create(struct packet_mmap_ctx * pkt_mmap_ctx, const struct tpacket_req const * req, const int ifindex, const int sock, const enum packet_mmap_ctx_type type)
{
	int rc = 0;

	assert(pkt_mmap_ctx);
	assert(req);

	memset(pkt_mmap_ctx, 0, sizeof(*pkt_mmap_ctx));
	pkt_mmap_ctx->type = type;
	pkt_mmap_ctx->layout = *req;
	pkt_mmap_ctx->sock = sock;
	pkt_mmap_ctx->ifindex = ifindex;

	if ((rc = packet_mmap_ctx_register(pkt_mmap_ctx)) != 0)
	{
		goto out;
	}

	if ((rc = packet_mmap_ctx_mmap(pkt_mmap_ctx)) != 0)
	{
		goto out;
	}

	if ((rc = packet_mmap_ctx_vector_create(pkt_mmap_ctx)) != 0)
	{
		goto out;
	}

	if ((rc = packet_mmap_ctx_bind(pkt_mmap_ctx)) != 0)
	{
		goto out;
	}

	return (0);
out:
	packet_mmap_ctx_destroy(pkt_mmap_ctx);
	return (rc);
}

unsigned long packet_mmap_ctx_status_get(struct packet_mmap_ctx * pkt_mmap_ctx)
{
	struct packet_mmap_header * mmap_hdr;

	assert(pkt_mmap_ctx);

	mmap_hdr = pkt_mmap_ctx->mmap_vec[pkt_mmap_ctx->used].iov_base;

	return (mmap_hdr->tp_h.tp_status);
}

void packet_mmap_ctx_status_set(struct packet_mmap_ctx * pkt_mmap_ctx, const int status)
{
	struct packet_mmap_header * mmap_hdr;

	assert(pkt_mmap_ctx);

	mmap_hdr = pkt_mmap_ctx->mmap_vec[pkt_mmap_ctx->used].iov_base;

	mmap_hdr->tp_h.tp_status = status;
}

int packet_mmap_ctx_is_full(const struct packet_mmap_ctx * pkt_mmap_ctx)
{
	assert(pkt_mmap_ctx);

	return (pkt_mmap_ctx->used >= pkt_mmap_ctx->layout.tp_frame_size);
}

int packet_mmap_ctx_next(struct packet_mmap_ctx * pkt_mmap_ctx)
{
	if (packet_mmap_ctx_is_full(pkt_mmap_ctx))
		return (EAGAIN);

	pkt_mmap_ctx->used++;

	return (0);
}

void packet_mmap_ctx_reset(struct packet_mmap_ctx * pkt_mmap_ctx)
{
	assert(pkt_mmap_ctx);

	pkt_mmap_ctx->used = 0;
}
