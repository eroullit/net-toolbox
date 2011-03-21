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

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <netinet/tcp.h>

#include <netcore-ng/macros.h>
#include <netcore-ng/dissector/ethernet/tcp.h>

size_t tcphdr_size_get(void);
uint16_t tcphdr_key_get(const uint8_t * const pkt, const size_t len, const size_t off);
void tcphdr_display_set(const enum display_type dtype);

static struct protocol_dissector tcphdr_dissector = 
{
	.display = NULL,
	.get_offset = tcphdr_size_get,
	.get_next_key = tcphdr_key_get,
	.display_set = tcphdr_display_set,
	.key = IPPROTO_TCP
};

size_t tcphdr_size_get(void)
{
	return(sizeof(struct tcphdr));
}

size_t tcphdr_display(const uint8_t * const pkt, const size_t len, const size_t off)
{
	struct tcphdr * tcphdr = (struct tcphdr *) &pkt[off];
	size_t tcp_len = tcphdr_size_get();

	assert(pkt);
	assert(len >= off + tcp_len);

	info(" [ TCP ");
	info("Port (%u => %u, %s), ", ntohs(tcphdr->source), ntohs(tcphdr->dest), "TODO");
	info("SN (0x%x), ", ntohl(tcphdr->seq));
	info("AN (0x%x), ", ntohl(tcphdr->ack_seq));
	info("DataOff (%u), ", tcphdr->doff);
	info("Res (%x/%x), ", tcphdr->res1, tcphdr->res2);
	info("Flags (");
	
	if (tcphdr->fin)
		info("FIN ");
	if (tcphdr->syn)
		info("SYN ");
	if (tcphdr->rst)
		info("RST ");
	if (tcphdr->psh)
		info("PSH ");
	if (tcphdr->ack)
		info("ACK ");
	if (tcphdr->urg)
		info("URG ");

	info("), ");

	info("Window (%u), ", ntohs(tcphdr->window));
	info("CSum (0x%.4x), ", ntohs(tcphdr->check));
	info("UrgPtr (%u)", ntohs(tcphdr->urg_ptr));
	info(" ]\n");

	return (tcp_len);
}

size_t tcphdr_display_less(const uint8_t * const pkt, const size_t len, const size_t off)
{
	struct tcphdr * tcphdr = (struct tcphdr *) &pkt[off];
	size_t tcp_len = tcphdr_size_get();

	assert(pkt);
	assert(len >= off + tcp_len);
	
	info(" [ TCP (%u => %u) ]\n", ntohs(tcphdr->source), ntohs(tcphdr->dest));

	return (tcp_len);
}

size_t tcphdr_display_hex(const uint8_t * const pkt, const size_t len, const size_t off)
{
	size_t a;
	size_t tcp_len = tcphdr_size_get();

	assert(pkt);
	assert(len >= off + tcp_len);

	info(" [ TCP ");
	
	for (a = 0; a < tcp_len; a++)
	{
		info("%.2x ", pkt[off + a]);
	}

	info(") ]\n");
	
	return (tcp_len);
}

size_t tcphdr_display_c_style(const uint8_t * const pkt, const size_t len, const size_t off)
{
	size_t a;
	size_t tcp_len = tcphdr_size_get();

	assert(pkt);
	assert(len >= off + tcp_len);

	info("const uint8_t tcp_hdr[] = {");

	for (a = 0; a < tcp_len - 1; a++)
	{
		info("0x%.2x, ", pkt[off + a]);
	}

	info("0x%.2x };\n", pkt[off + tcp_len]);

	return (tcp_len);
}

uint16_t tcphdr_key_get(const uint8_t * const pkt, const size_t len, const size_t off)
{
	assert(pkt);
	assert(len >= off + tcphdr_size_get());

	return (RAW_DEFAULT_KEY); 
}

void tcphdr_display_set(const enum display_type dtype)
{
	switch(dtype)
	{
		case DISPLAY_NORMAL:
			tcphdr_dissector.display = tcphdr_display;
		break;

		case DISPLAY_LESS:
			tcphdr_dissector.display = tcphdr_display_less;
		break;

		case DISPLAY_C_STYLE:
			tcphdr_dissector.display = tcphdr_display_c_style;
		break;

		case DISPLAY_HEX:
			tcphdr_dissector.display = tcphdr_display_hex;
		break;

		case DISPLAY_NONE:
			tcphdr_dissector.display = NULL;
		break;

		default:

		break;
	}
}

int dissector_tcphdr_insert(void)
{
	return (ethernet_dissector_insert(&tcphdr_dissector));
}
