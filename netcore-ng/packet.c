#include <stdlib.h>
#include <string.h>

#include <netcore-ng/packet.h>

void packet_context_destroy(struct packet_ctx * pkt_ctx)
{
	assert(pkt_ctx);

	free(pkt_ctx->pkt_buf);
	memset(pkt_ctx, 0. sizeof(*pkt_ctx));

	return (0);
}

int packet_context_create(struct packet_ctx * pkt_ctx, const size_t mtu)
{
	assert(pkt_ctx);
	assert(mtu);

	memset(pkt_ctx, 0, sizeof(*pkt_ctx));

	if ((pkt_ctx->pkt_buf = malloc(sizeof(*pkt_ctx->pkt_buf) * mtu)) == NULL)
	{
		return (ENOMEM);
	}

	memset(pkt_ctx->pkt_buf, 0, sizeof(*pkt_ctx->pkt_buf) * mtu);
	pkt_ctx->mtu = pkt_mtu;

	return (0);
}

void packet_vector_destroy(struct packet_vector * pkt_vec)
{
	size_t a;
	int rc = 0;

	assert(pkt_vec);

	for (a = 0; a < pkt_vec->pkt_nr; a++)
	{
		packet_context_destroy(&pkt_vec->pkt[a]);
	}

	free(pkt_vec->pkt);

	memset(pkt_vec, 0, sizeof(*pkt_vec));
}

int packet_vector_create(struct packet_vector * pkt_vec, const size_t pkt_nr, const size_t mtu)
{
	size_t a;
	int rc = 0;

	assert(pkt_vec);
	assert(pkt_nr);
	assert(mtu);

	memset(pkt_vec, 0, sizeof(*pkt_vec));

	if ((pkt_vec->pkt = malloc(sizeof(*pkt_vec->pkt) * pkt_nr)) == NULL)
	{
		rc = ENOMEM;
		goto error;
	}

	memset(pkt_vec->pkt, 0, sizeof(*pkt_vec->pkt) * pkt_nr);
	pkt_vec->pkt_nr = pkt_nr;

	for (a = 0; a < pkt_nr; a++)
	{
		if ((rc = packet_context_create(&pkt_vec->pkt[a])) != 0)
		{
			goto error;
		}
	}

	return (0);

error:
	packet_vector_destroy(pkt_vec);
	return (rc);
}
