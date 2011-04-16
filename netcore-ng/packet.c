#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <netcore-ng/packet.h>

void packet_context_destroy(struct packet_ctx * pkt_ctx)
{
	assert(pkt_ctx);

	free(pkt_ctx->pkt_buf);
	memset(pkt_ctx, 0, sizeof(*pkt_ctx));
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
	pkt_ctx->mtu = mtu;

	return (0);
}

void packet_vector_destroy(struct packet_vector * pkt_vec)
{
	size_t a;

	assert(pkt_vec);

	for (a = 0; a < pkt_vec->pkt_nr; a++)
	{
		packet_context_destroy(&pkt_vec->pkt[a]);
	}

	free(pkt_vec->pkt_io_vec);
	free(pkt_vec->pkt);

	memset(pkt_vec, 0, sizeof(*pkt_vec));
}

int packet_vector_create(struct packet_vector * pkt_vec, const size_t pkt_nr, const size_t mtu)
{
	size_t a;
	int rc = 0;
	size_t setup_pkt;

	assert(pkt_vec);
	assert(pkt_nr);
	assert(mtu);

	memset(pkt_vec, 0, sizeof(*pkt_vec));

	/* One vector for the PCAP header, one for the packet itself */
	pkt_vec->total_pkt_io_vec = pkt_nr * 2;
	pkt_vec->pkt_nr = pkt_nr;

	pkt_vec->pkt = malloc(sizeof(*pkt_vec->pkt) * pkt_nr);
	pkt_vec->pkt_io_vec = malloc(sizeof(*pkt_vec->pkt_io_vec) * pkt_vec->total_pkt_io_vec);

	if (pkt_vec->pkt == NULL || pkt_vec->pkt_io_vec == NULL)
	{
		rc = ENOMEM;
		goto error;
	}

	memset(pkt_vec->pkt, 0, sizeof(*pkt_vec->pkt) * pkt_vec->pkt_nr);
	memset(pkt_vec->pkt_io_vec, 0, sizeof(*pkt_vec->pkt_io_vec) * pkt_vec->total_pkt_io_vec);
	
	for (a = 0; a < pkt_vec->pkt_nr; a++)
	{
		if ((rc = packet_context_create(&pkt_vec->pkt[a], mtu)) != 0)
		{
			goto error;
		}
	}

	for (a = 0, setup_pkt = 0; a < pkt_vec->total_pkt_io_vec; a++)
	{
		if (a % 2 == 0)
		{
			pkt_vec->pkt_io_vec[a].iov_base = &pkt_vec->pkt[setup_pkt].pkt_hdr;
			/* The ring routine must set the valid PCAP packet header in the IO vector */
			pkt_vec->pkt_io_vec[a].iov_len = 0;
		}
		else
		{
			pkt_vec->pkt_io_vec[a].iov_base = pkt_vec->pkt[setup_pkt].pkt_buf;
			/* The ring routine must set the valid packet length in the IO vector */
			pkt_vec->pkt_io_vec[a].iov_len = 0;

			/* At this point, the packet buffer has its PCAP header, so setup the next one*/
			setup_pkt++;
		}
	}

	return (0);

error:
	packet_vector_destroy(pkt_vec);
	return (rc);
}

void packet_vector_reset(struct packet_vector * pkt_vec)
{
	size_t a;
	
	/* Only the length need to be reset */
	for (a = 0; a < pkt_vec->total_pkt_io_vec; a++)
	{
		pkt_vec->pkt_io_vec[a].iov_len = 0;
	}

	pkt_vec->used_pkt_io_vec = 0;
}
