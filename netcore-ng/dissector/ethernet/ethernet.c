#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <net/ethernet.h>
#include <netinet/ether.h>

#include <netcore-ng/dissector/ethernet/ethernet.h>

size_t ethernet_offset_get(const uint8_t * const pkt, const size_t len);
uint16_t ethernet_key_get(const uint8_t * const pkt, const size_t len);
void ethernet_display_set(const enum display_type dtype);

static struct protocol_dissector eth_dissector = 
{
	.display = NULL,
	.get_offset = ethernet_offset_get,
	.get_next_key = ethernet_key_get,
	.display_set = ethernet_display_set,
	.key = ETHERNET_HDR_DEFAULT_KEY
};

void ethernet_display(const uint8_t * const pkt, const size_t len)
{
	char mac_str[32] = { 0 };
	struct ether_header * hdr = (struct ether_header *) pkt;
	const char * ether_type_str = NULL;
	const char * svendor_id = NULL;
	const char * dvendor_id = NULL;

	assert(pkt);
	assert(len >= sizeof(*hdr));

	ether_types_hash_search(ntohs(hdr->ether_type), &ether_type_str);

	/* Is there a prettier way to get the OUI part of a MAC addr? */
	oui_hash_search(hdr->ether_shost[0] << 16 | hdr->ether_shost[1] << 8 | hdr->ether_shost[2], &svendor_id);
	oui_hash_search(hdr->ether_dhost[0] << 16 | hdr->ether_dhost[1] << 8 | hdr->ether_dhost[2], &dvendor_id);

	info(" [ Eth ");
	info("MAC (%s => %s), Proto (0x%.4x %s) ", ether_ntoa_r((struct ether_addr *) &hdr->ether_shost, mac_str), ether_ntoa_r((struct ether_addr *) &hdr->ether_dhost, mac_str), ntohs(hdr->ether_type), ether_type_str);
	info("Vendor (%s => %s) ]\n", svendor_id, dvendor_id);
}

void ethernet_display_less(const uint8_t * const pkt, const size_t len)
{
	char mac_str[32] = { 0 };
	struct ether_header * hdr = (struct ether_header *) pkt;
	const char * ether_type_str = NULL;
	
	assert(pkt);
	assert(len >= sizeof(*hdr));

	ether_types_hash_search(ntohs(hdr->ether_type), &ether_type_str);
	
	info("%s => %s, (%s)\n", ether_ntoa_r((struct ether_addr *) &hdr->ether_shost, mac_str), ether_ntoa_r((struct ether_addr *) &hdr->ether_dhost, mac_str), ether_type_str);
}

void ethernet_display_hex(const uint8_t * const pkt, const size_t len)
{
	size_t a;

	assert(pkt);
	assert(len >= sizeof(struct ether_header));

	info(" [ MAC header (");
	for (a = 0; a < sizeof(struct ether_header); a++)
	{
		info("%.2x ", pkt[a]);
	}

	info(") ]\n");
}

void ethernet_display_c_style(const uint8_t * const pkt, const size_t len)
{
	size_t a;

	assert(pkt);
	assert(len >= sizeof(struct ether_header));

	info("const uint8_t mac_hdr[] = {");

	for (a = 0; a < sizeof(struct ether_header) - 1; a++)
	{
		info("0x%.2x, ", pkt[a]);
	}

	if (len > 0)
		info("0x%.2x\n", pkt[sizeof(struct ether_header)]);

	info("};\n");
}

size_t ethernet_offset_get(const uint8_t * const pkt, const size_t len)
{
	assert(pkt);
	assert(len >= sizeof(struct ether_header));

	return(sizeof(struct ether_header));
}

uint16_t ethernet_key_get(const uint8_t * const pkt, const size_t len)
{
	struct ether_header * hdr = (struct ether_header *) pkt;
	assert(pkt);
	assert(len >= sizeof(*hdr));

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

