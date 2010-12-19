#include <stdio.h>
#include <errno.h>

#include <net/ethernet.h>
#include <netinet/ether.h>

#include <net-ng/dissector/ethernet/ethernet.h>

void ethernet_display(const uint8_t * const pkt, const size_t len)
{
	char mac_str[32] = { 0 };
	struct ether_header * hdr = (struct ether_header *) pkt;
	const char * ether_type_str = NULL;
	const char * svendor_id = NULL;
	const char * dvendor_id = NULL;

	assert(pkt);
	assert(len >= sizeof(*hdr));
	/* XXX Not sure if valid */
	assert(ETHER_IS_VALID_LEN(len));

	ether_types_hash_search(ntohs(hdr->ether_type), &ether_type_str);
	oui_hash_search(hdr->ether_shost[0] << 16 | hdr->ether_shost[1] << 8 | hdr->ether_shost[2], &svendor_id);
	oui_hash_search(hdr->ether_dhost[0] << 16 | hdr->ether_dhost[1] << 8 | hdr->ether_dhost[2], &dvendor_id);

	printf(" [ Eth ");
	printf("MAC (%s => %s), Proto (%x %s) ] \n", ether_ntoa_r((struct ether_addr *) &hdr->ether_shost, mac_str), ether_ntoa_r((struct ether_addr *) &hdr->ether_dhost, mac_str), ntohs(hdr->ether_type), ether_type_str);
	printf("Vendor (%s => %s) ]\n", svendor_id, dvendor_id);
}

void ethernet_display_less(const uint8_t * const pkt, const uint16_t len)
{
	char mac_str[32] = { 0 };
	struct ether_header * hdr = (struct ether_header *) pkt;
	const char * ether_type_str = NULL;
	
	assert(pkt);
	assert(len >= sizeof(*hdr));
	/* XXX Not sure if valid */
	assert(ETHER_IS_VALID_LEN(len));

	ether_types_hash_search(ntohs(hdr->ether_type), &ether_type_str);
	
	printf("%s => %s, (%s)\n", ether_ntoa_r((struct ether_addr *) &hdr->ether_shost, mac_str), ether_ntoa_r((struct ether_addr *) &hdr->ether_dhost, mac_str), ether_type_str);
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

int dissector_ethernet_insert(void)
{
	struct protocol_dissector dis =
	{
		.display = NULL,
		.get_offset = ethernet_offset_get,
		.get_next_key = ethernet_key_get
	};

	/* As the ethernet header is the first thing to come, its key ID is 0 */
	return (ethernet_dissector_insert(0, &dis));
}

int dissector_ethernet_print_set(const enum display_type type)
{
	switch(type)
	{
		default:
			break;
	}

	return (0);
}
