#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <netcore-ng/pcap.h>
#include <netcore-ng/packet_iovec.h>

void packet_iovec_destroy(struct packet_iovec * pkt_vec)
{
	assert(pkt_vec);

	free(pkt_vec->pkt_io_vec);
	free(pkt_vec->pkt_pcap_hdr);

	memset(pkt_vec, 0, sizeof(*pkt_vec));
}

int packet_iovec_create(struct packet_iovec * pkt_vec, const size_t pkt_nr)
{
	int rc = 0;

	assert(pkt_vec);
	assert(pkt_nr);

	memset(pkt_vec, 0, sizeof(*pkt_vec));

	/* One vector for the PCAP header, one for the packet itself */
	pkt_vec->total = pkt_nr * 2;

	pkt_vec->pkt_io_vec = calloc(pkt_vec->total, sizeof(*pkt_vec->pkt_io_vec));
	pkt_vec->pkt_pcap_hdr = calloc(pkt_nr, sizeof(*pkt_vec->pkt_pcap_hdr));

	if (pkt_vec->pkt_io_vec == NULL || pkt_vec->pkt_pcap_hdr == NULL)
	{
		rc = ENOMEM;
		goto error;
	}

	return (0);

error:
	packet_iovec_destroy(pkt_vec);
	return (rc);
}

struct pcap_sf_pkthdr * packet_iovec_pcap_hdr_set(struct packet_iovec * pkt_vec)
{
	return (&pkt_vec->pkt_pcap_hdr[pkt_vec->used/2]);
}

void packet_iovec_reset(struct packet_iovec * pkt_vec)
{
	memset(pkt_vec->pkt_io_vec, 0, sizeof(*pkt_vec->pkt_io_vec) * pkt_vec->total);
	
	pkt_vec->used = 0;
}

int packet_iovec_end(const struct packet_iovec * const pkt_vec)
{
	assert(pkt_vec);
	return (pkt_vec->used >= pkt_vec->total);
}

int packet_iovec_next(struct packet_iovec * pkt_vec)
{
	if (packet_iovec_end(pkt_vec))
		return (EAGAIN);

	pkt_vec->used += 2;

	return (0);
}

uint8_t * packet_iovec_packet_payload_get(const struct packet_iovec * const pkt_vec)
{
	return (pkt_vec->pkt_io_vec[pkt_vec->used + 1].iov_base);
}

size_t packet_iovec_packet_length_get(const struct packet_iovec * const pkt_vec)
{
	return (pkt_vec->pkt_io_vec[pkt_vec->used + 1].iov_len);
}

void packet_iovec_set(struct packet_iovec * pkt_vec, uint8_t * pkt, const size_t len, const struct timeval * ts)
{
	struct pcap_sf_pkthdr * hdr = NULL;

	assert(pkt_vec);
	assert(pkt);
	assert(len);
	assert(ts);

	hdr = &pkt_vec->pkt_pcap_hdr[pkt_vec->used/2];

	pcap_packet_header_set(hdr, ts, len);
	pkt_vec->pkt_io_vec[pkt_vec->used].iov_base = hdr;
	pkt_vec->pkt_io_vec[pkt_vec->used].iov_len = sizeof(*hdr);

	pkt_vec->pkt_io_vec[pkt_vec->used + 1].iov_base = pkt;
	pkt_vec->pkt_io_vec[pkt_vec->used + 1].iov_len = len;
}
