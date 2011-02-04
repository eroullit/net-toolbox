/* __LICENSE_HEADER_BEGIN__ */

/*
 * Copyright (C) 2009, 2010  Daniel Borkmann <daniel@netsniff-ng.org> and
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

#include <net/ethernet.h>
#include <netinet/ether.h>

#include <netcore-ng/dissector/ethernet/ethernet.h>

size_t ethernet_size_get(void);
uint16_t ethernet_key_get(const uint8_t * const pkt, const size_t len, const size_t off);
void ethernet_display_set(const enum display_type dtype);

static struct protocol_dissector eth_dissector = 
{
	.display = NULL,
	.get_offset = ethernet_size_get,
	.get_next_key = ethernet_key_get,
	.display_set = ethernet_display_set,
	.key = ETHERNET_HDR_DEFAULT_KEY
};

size_t ethernet_size_get(void)
{
	return(sizeof(struct ether_header));
}


size_t ethernet_display(const uint8_t * const pkt, const size_t len, const size_t off)
{
	char mac_str[32] = { 0 };
	size_t eth_len = ethernet_size_get();
	struct ether_header * hdr = (struct ether_header *) &pkt[off];
	const char * ether_type_str = NULL;
	const char * svendor_id = NULL;
	const char * dvendor_id = NULL;

	assert(pkt);
	assert(len >= off + eth_len);

	ether_types_hash_search(ntohs(hdr->ether_type), &ether_type_str);

	/* Is there a prettier way to get the OUI part of a MAC addr? */
	oui_hash_search(hdr->ether_shost[0] << 16 | hdr->ether_shost[1] << 8 | hdr->ether_shost[2], &svendor_id);
	oui_hash_search(hdr->ether_dhost[0] << 16 | hdr->ether_dhost[1] << 8 | hdr->ether_dhost[2], &dvendor_id);

	info(" [ Eth ");
	info("MAC (%s => %s), Proto (0x%.4x %s) ", ether_ntoa_r((struct ether_addr *) &hdr->ether_shost, mac_str), ether_ntoa_r((struct ether_addr *) &hdr->ether_dhost, mac_str), ntohs(hdr->ether_type), ether_type_str);
	info("Vendor (%s => %s) ]\n", svendor_id, dvendor_id);

	return (eth_len);
}

size_t ethernet_display_less(const uint8_t * const pkt, const size_t len, const size_t off)
{
	char mac_str[32] = { 0 };
	size_t eth_len = ethernet_size_get();
	struct ether_header * hdr = (struct ether_header *) &pkt[off];
	const char * ether_type_str = NULL;
	
	assert(pkt);
	assert(len >= off + eth_len);

	ether_types_hash_search(ntohs(hdr->ether_type), &ether_type_str);
	
	info("%s => %s, (%s)\n", ether_ntoa_r((struct ether_addr *) &hdr->ether_shost, mac_str), ether_ntoa_r((struct ether_addr *) &hdr->ether_dhost, mac_str), ether_type_str);
	
	return (eth_len);
}

size_t ethernet_display_hex(const uint8_t * const pkt, const size_t len, const size_t off)
{
	size_t a;
	size_t eth_len = ethernet_size_get();

	assert(pkt);
	assert(len >= off + eth_len);

	info(" [ MAC header (");
	for (a = 0; a < eth_len; a++)
	{
		info("%.2x ", pkt[off + a]);
	}

	info(") ]\n");
	
	return (eth_len);
}

size_t ethernet_display_c_style(const uint8_t * const pkt, const size_t len, const size_t off)
{
	size_t a;
	size_t eth_len = ethernet_size_get();

	assert(pkt);
	assert(len >= off + eth_len);

	info("const uint8_t mac_hdr[] = {");

	for (a = 0; a < eth_len - 1; a++)
	{
		info("0x%.2x, ", pkt[off + a]);
	}

	info("0x%.2x};\n", pkt[off + eth_len]);

	return (eth_len);
}

uint16_t ethernet_key_get(const uint8_t * const pkt, const size_t len, const size_t off)
{
	struct ether_header * hdr = (struct ether_header *) &pkt[off];
	assert(pkt);
	assert(len >= off + ethernet_size_get());

	return(ntohs(hdr->ether_type));
}

void ethernet_display_set(const enum display_type dtype)
{
	switch(dtype)
	{
		case DISPLAY_NORMAL:
			eth_dissector.display = ethernet_display;
		break;

		case DISPLAY_LESS:
			eth_dissector.display = ethernet_display_less;
		break;

		case DISPLAY_C_STYLE:
			eth_dissector.display = ethernet_display_c_style;
		break;

		case DISPLAY_HEX:
			eth_dissector.display = ethernet_display_hex;
		break;

		case DISPLAY_NONE:
			eth_dissector.display = NULL;
		break;

		default:

		break;
	}
}

int dissector_ethernet_insert(void)
{
	/* As the ethernet header is the first thing to come, its key ID is ETHERNET_HDR_DEFAULT_KEY */
	return (ethernet_dissector_insert(&eth_dissector));
}

