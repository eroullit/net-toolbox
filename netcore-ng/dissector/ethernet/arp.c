#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <net/if_arp.h>
#include <net/ethernet.h>

#include <netcore-ng/macros.h>
#include <netcore-ng/dissector/ethernet/arp.h>

size_t arp_size_get(void);
uint16_t arp_key_get(const uint8_t * const pkt, const size_t len, const size_t off);
void arp_display_set(const enum display_type dtype);

static const char * arp_opcode_str[] = 
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
	.get_offset = arp_size_get,
	.get_next_key = arp_key_get,
	.display_set = arp_display_set,
	.key = ETHERTYPE_ARP
};

size_t arp_size_get(void)
{
	return(sizeof(struct arphdr));
}

size_t arp_display(const uint8_t * const pkt, const size_t len, const size_t off)
{
	struct arphdr * arp = (struct arphdr *) &pkt[off];
	size_t arp_len = arp_size_get();
	uint16_t arp_op;

	assert(pkt);
	assert(len >= off + arp_len);

	arp_op = ntohs(arp->ar_op);

	info(" [ ARP ");
	info("Format HA (%u), ", ntohs(arp->ar_hrd));
	info("Format Proto (%u), ", ntohs(arp->ar_pro));
	info("HA Len (%u), \n", ntohs(arp->ar_hln));
	info("Proto Len (%u), ", ntohs(arp->ar_pln));

	if (arp_op < ARRAY_SIZE(arp_opcode_str))
	{
		info("Opcode (%s)", arp_opcode_str[arp_op]);
	}
	else
	{
		info("Opcode (Unknown)");
	}

	info(" ] \n");

	return (arp_len);
}

size_t arp_display_less(const uint8_t * const pkt, const size_t len, const size_t off)
{
	struct arphdr * arp = (struct arphdr *) &pkt[off];
	size_t arp_len = arp_size_get();
	uint16_t arp_op;
	
	assert(pkt);
	assert(len >= off + arp_len);

	arp_op = ntohs(arp->ar_op);
	
	info(" [ ARP ");
	
	if (arp_op < ARRAY_SIZE(arp_opcode_str))
	{
		info("Opcode (%s)", arp_opcode_str[arp_op]);
	}
	else
	{
		info("Opcode (Unknown)");
	}

	info(" ] \n");
	
	return (arp_len);
}

size_t arp_display_hex(const uint8_t * const pkt, const size_t len, const size_t off)
{
	size_t a;
	size_t arp_len = arp_size_get();
	
	assert(pkt);
	assert(len >= off + arp_len);

	info(" [ ARP header (");

	for (a = 0; a < arp_len; a++)
	{
		info("%.2x ", pkt[off + a]);
	}

	info(") ]\n");

	return (arp_len);
}

size_t arp_display_c_style(const uint8_t * const pkt, const size_t len, const size_t off)
{
	size_t a;
	size_t arp_len = arp_size_get();

	assert(pkt);
	assert(len >= off + arp_len);

	info("const uint8_t arp_hdr[] = {");

	for (a = 0; a < arp_len - 1; a++)
	{
		info("0x%.2x, ", pkt[off + a]);
	}

	info("0x%.2x};\n", pkt[off + arp_len]);

	return (arp_len);
}

uint16_t arp_key_get(const uint8_t * const pkt, const size_t len, const size_t off)
{
	assert(pkt);
	assert(len >= off + arp_size_get());

	return (RAW_DEFAULT_KEY); 
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
	return (ethernet_dissector_insert(&arp_dissector));
}
