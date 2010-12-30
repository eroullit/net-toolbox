#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <net/if_arp.h>
#include <net/ethernet.h>

#include <net-ng/macros.h>
#include <net-ng/dissector/ethernet/arp.h>

size_t arp_offset_get(const uint8_t * const pkt, const size_t len);
uint16_t arp_key_get(const uint8_t * const pkt, const size_t len);
void arp_display_set(const enum display_type dtype);

static const char * arp_opcode_str[ARPOP_NAK + 1] = 
{
	[ARPOP_REQUEST] = "ARP request",
	[ARPOP_REPLY] = "ARP reply",
	[ARPOP_RREQUEST] = "RARP request",
	[ARPOP_RREPLY] = "RARP reply",
	[ARPOP_InREQUEST] = "InARP request",
	[ARPOP_InREPLY] = "InARP reply",
	[ARPOP_NAK] = "ARP NAK",
};

static struct protocol_dissector arp_dissector = 
{
	.display = NULL,
	.get_offset = arp_offset_get,
	.get_next_key = arp_key_get,
	.display_set = arp_display_set,
	.key = ETHERTYPE_ARP
};

void arp_display(const uint8_t * const pkt, const size_t len)
{
	struct arphdr * arp = (struct arphdr *) pkt;
	uint16_t arp_op;

	assert(pkt);
	assert(len >= sizeof(*arp));

	arp_op = ntohs(arp->ar_op);

	printf(" [ ARP ");
	printf("Format HA (%u), ", ntohs(arp->ar_hrd));
	printf("Format Proto (%u), ", ntohs(arp->ar_pro));
	printf("HA Len (%u), \n", ntohs(arp->ar_hln));
	printf("   Proto Len (%u), ", ntohs(arp->ar_pln));

	if (arp_op < ARRAY_SIZE(arp_opcode_str))
	{
		printf("Opcode (%s)", arp_opcode_str[arp_op]);
	}
	else
	{
		printf("Opcode (Unknown)");
	}

	printf(" ] \n");
}

void arp_display_less(const uint8_t * const pkt, const size_t len)
{
	struct arphdr * arp = (struct arphdr *) pkt;
	uint16_t arp_op;
	
	assert(pkt);
	assert(len >= sizeof(*arp));

	arp_op = ntohs(arp->ar_op);
	
	printf(" [ ARP ");
	
	if (arp_op < ARRAY_SIZE(arp_opcode_str))
	{
		printf("Opcode (%s)", arp_opcode_str[arp_op]);
	}
	else
	{
		printf("Opcode (Unknown)");
	}

	printf(" ] \n");
}

void arp_display_hex(const uint8_t * const pkt, const size_t len)
{
	assert(pkt);
	assert(len >= sizeof(struct arphdr));

}

void arp_display_c_style(const uint8_t * const pkt, const size_t len)
{
	assert(pkt);
	assert(len >= sizeof(struct arphdr));

}

size_t arp_offset_get(const uint8_t * const pkt, const size_t len)
{
	assert(pkt);
	assert(len >= sizeof(struct arphdr));

	return(sizeof(struct arphdr));
}

uint16_t arp_key_get(const uint8_t * const pkt, const size_t len)
{
	assert(pkt);
	assert(len >= sizeof(struct arphdr));

	return (EINVAL); 
}

void arp_display_set(const enum display_type dtype)
{
	switch(dtype)
	{
		case DISPLAY_NORMAL:
			arp_dissector.display = arp_display;
		break;

		case DISPLAY_LESS:
			arp_dissector.display = arp_display_less;
		break;

		case DISPLAY_C_STYLE:
			arp_dissector.display = arp_display_c_style;
		break;

		case DISPLAY_HEX:
			arp_dissector.display = arp_display_hex;
		break;

		case DISPLAY_NONE:
			arp_dissector.display = NULL;
		break;

		default:

		break;
	}
}

int dissector_arp_insert(void)
{
	return (ethernet_dissector_insert(arp_dissector.key, &arp_dissector));
}
