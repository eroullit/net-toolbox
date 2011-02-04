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

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

#include <netcore-ng/macros.h>
#include <netcore-ng/dissector/ethernet/ip.h>

#define	FRAG_OFF_RESERVED_FLAG(x)      ((x) & IP_RF)
#define	FRAG_OFF_NO_FRAGMENT_FLAG(x)   ((x) & IP_DF)
#define	FRAG_OFF_MORE_FRAGMENT_FLAG(x) ((x) & IP_MF)
#define	FRAG_OFF_FRAGMENT_OFFSET(x)    ((x) & IP_OFFMASK)

size_t ip_size_get(void);
uint16_t ip_key_get(const uint8_t * const pkt, const size_t len, const size_t off);
void ip_display_set(const enum display_type dtype);

static struct protocol_dissector ip_dissector = 
{
	.display = NULL,
	.get_offset = ip_size_get,
	.get_next_key = ip_key_get,
	.display_set = ip_display_set,
	.key = ETHERTYPE_IP
};

size_t ip_size_get(void)
{
	return(sizeof(struct iphdr));
}

size_t ip_display(const uint8_t * const pkt, const size_t len, const size_t off)
{
	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];
	struct iphdr * ip = (struct iphdr *) &pkt[off];
	size_t ip_len = ip_size_get();
	uint16_t frag_off;
	/* TODO csum */

	assert(pkt);
	assert(len >= off + ip_len);

	frag_off = ntohs(ip->frag_off);

	inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

	info(" [ IPv4 ");
	info("Addr (%s => %s), ", src_ip, dst_ip);
	info("Proto (%u), ", ip->protocol);
	info("TTL (%u), ", ip->ttl);
	info("TOS (%u), ", ip->tos);
	info("Ver (%u), ", ip->version);
	info("IHL (%u), ", ip->ihl);
	info("Tlen (%u), ", ntohs(ip->tot_len));
	info("ID (%u), ", ntohs(ip->id));
	info("Res (%u), NoFrag (%u), MoreFrag (%u), FragOff (%u), ",
		FRAG_OFF_RESERVED_FLAG(frag_off) ? 1 : 0,
		FRAG_OFF_NO_FRAGMENT_FLAG(frag_off) ? 1 : 0,
		FRAG_OFF_MORE_FRAGMENT_FLAG(frag_off) ? 1 : 0,
		FRAG_OFF_FRAGMENT_OFFSET(frag_off));

	info(" ]\n");

	return (ip_len);
}

size_t ip_display_less(const uint8_t * const pkt, const size_t len, const size_t off)
{
	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];
	struct iphdr * ip = (struct iphdr *) &pkt[off];
	size_t ip_len = ip_size_get();

	assert(pkt);
	assert(len >= off + ip_len);
	
	inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

	info(" [ IPv4 Addr (%s => %s) ]\n", src_ip, dst_ip);

	return (ip_len);
}

size_t ip_display_hex(const uint8_t * const pkt, const size_t len, const size_t off)
{
	size_t a;
	size_t ip_len = ip_size_get();

	assert(pkt);
	assert(len >= off + ip_len);

	info(" [ IPv4 ");
	
	for (a = 0; a < ip_len; a++)
	{
		info("%.2x ", pkt[off + a]);
	}

	info(") ]\n");
	
	return (ip_len);
}

size_t ip_display_c_style(const uint8_t * const pkt, const size_t len, const size_t off)
{
	size_t a;
	size_t ip_len = ip_size_get();

	assert(pkt);
	assert(len >= off + ip_len);

	info("const uint8_t ip_hdr[] = {");

	for (a = 0; a < ip_len - 1; a++)
	{
		info("0x%.2x, ", pkt[off + a]);
	}

	info("0x%.2x };\n", pkt[off + ip_len]);

	return (ip_len);
}

uint16_t ip_key_get(const uint8_t * const pkt, const size_t len, const size_t off)
{
	assert(pkt);
	assert(len >= off + ip_size_get());

	/* TODO return L4 ID */
	return (RAW_DEFAULT_KEY); 
}

void ip_display_set(const enum display_type dtype)
{
	switch(dtype)
	{
		case DISPLAY_NORMAL:
			ip_dissector.display = ip_display;
		break;

		case DISPLAY_LESS:
			ip_dissector.display = ip_display_less;
		break;

		case DISPLAY_C_STYLE:
			ip_dissector.display = ip_display_c_style;
		break;

		case DISPLAY_HEX:
			ip_dissector.display = ip_display_hex;
		break;

		case DISPLAY_NONE:
			ip_dissector.display = NULL;
		break;

		default:

		break;
	}
}

int dissector_ip_insert(void)
{
	return (ethernet_dissector_insert(&ip_dissector));
}
