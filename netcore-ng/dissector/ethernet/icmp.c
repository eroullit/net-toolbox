#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <netinet/ip_icmp.h>

#include <netcore-ng/macros.h>
#include <netcore-ng/dissector/ethernet/icmp.h>

/* 
 * TODO Check if checsum is fine
 * 	Print all info of ICMP header
 */

size_t icmp_offset_get(const uint8_t * const pkt, const size_t len);
uint16_t icmp_key_get(const uint8_t * const pkt, const size_t len);
void icmp_display_set(const enum display_type dtype);

static const char * icmp_types_str[] = 
{
	[ICMP_ECHOREPLY] = "Echo Reply",
	[ICMP_DEST_UNREACH] = "Destination Unreachable",
	[ICMP_SOURCE_QUENCH] = "Source Quench",
	[ICMP_REDIRECT] = "Redirect",
	[ICMP_ECHO] = "Echo Request",
	[ICMP_TIME_EXCEEDED] = "Time Exceeded",
	[ICMP_PARAMETERPROB] = "Parameter Problem",
	[ICMP_TIMESTAMP] = "Timestamp Request",
	[ICMP_TIMESTAMPREPLY] = "Timestamp Reply",
	[ICMP_INFO_REQUEST] = "Information Request",
	[ICMP_INFO_REPLY] = "Information Reply",
	[ICMP_ADDRESS] = "Address Mask Request",
	[ICMP_ADDRESSREPLY] = "Address Mask Reply"
};

static const char * icmp_unreach_str[] = 
{
	[ICMP_NET_UNREACH] = "Network Unreachable",
	[ICMP_HOST_UNREACH] = "Host Unreachable",
	[ICMP_PROT_UNREACH] = "Protocol Unreachable",
	[ICMP_PORT_UNREACH] = "Port Unreachable",
	[ICMP_FRAG_NEEDED] = "Fragmentation Needed/DF set",
	[ICMP_SR_FAILED] = "Source Route failed",
	[ICMP_NET_UNKNOWN] = "Network unknown",
	[ICMP_HOST_UNKNOWN] = "Host unknown",
	[ICMP_HOST_ISOLATED] = "Host isolated",
	[ICMP_NET_ANO] = "Network ANO", /* XXX */
	[ICMP_HOST_ANO] = "Host ANO", /* XXX */
	[ICMP_NET_UNR_TOS] = "Network UNR ANO TOS", /* XXX */
	[ICMP_HOST_UNR_TOS] = "Host UNR ANO TOS", /* XXX */
	[ICMP_PKT_FILTERED] = "Packet filtered",
	[ICMP_PREC_VIOLATION] = "Precedence violation",
	[ICMP_PREC_CUTOFF] = "Precedence cut off"
};

static const char * icmp_redirect_str[] = 
{
	[ICMP_REDIR_NET] = "Redirect Net",
	[ICMP_REDIR_HOST] = "Redirect Host",
	[ICMP_REDIR_NETTOS] = "Redirect Net for TOS",
	[ICMP_REDIR_HOSTTOS] = "Redirect Host for TOS"
};

static const char * icmp_time_exceeded_str[ICMP_EXC_FRAGTIME + 1] = 
{
	[ICMP_EXC_TTL] = "TTL count exceeded",
	[ICMP_EXC_FRAGTIME] = "Fragment Reass time exceeded",
};

static struct protocol_dissector icmp_dissector = 
{
	.display = NULL,
	.get_offset = icmp_offset_get,
	.get_next_key = icmp_key_get,
	.display_set = icmp_display_set,
	.key = IPPROTO_ICMP
};

void icmp_display(const uint8_t * const pkt, const size_t len)
{
	struct icmphdr * icmp = (struct icmphdr *) pkt;

	assert(pkt);
	assert(len >= sizeof(*icmp));

	info(" [ ICMP ");

	if (icmp->type < ARRAY_SIZE(icmp_types_str))
	{
		info("Type (%s), ", icmp_types_str[icmp->type]);
	}
	else
	{
		info("Type (unknown), ");
	}

	switch(icmp->type)
	{
		case ICMP_DEST_UNREACH:
			if (icmp->code < ARRAY_SIZE(icmp_unreach_str))
			{
				info("Code (%s), ", icmp_unreach_str[icmp->code]);
			}
			else
			{
				info("Code (unknown (%u)), ", icmp->code);
			}
		break;

		case ICMP_REDIRECT:
			if (icmp->code < ARRAY_SIZE(icmp_redirect_str))
			{
				info("Code (%s), ", icmp_redirect_str[icmp->code]);
			}
			else
			{
				info("Code (unknown (%u)), ", icmp->code);
			}
		break;

		case ICMP_TIME_EXCEEDED:
			if (icmp->code < ARRAY_SIZE(icmp_time_exceeded_str))
			{
				info("Code (%s), ", icmp_time_exceeded_str[icmp->code]);
			}
			else
			{
				info("Code (unknown (%u)), ", icmp->code);
			}
		break;

		default:
			info("Code (%u), ", icmp->code);
		break;
	}

	info("Csum (0x%x), \n", icmp->checksum);

	info(" ] \n");
}

void icmp_display_less(const uint8_t * const pkt, const size_t len)
{
	struct icmphdr * icmp = (struct icmphdr *) pkt;

	assert(pkt);
	assert(len >= sizeof(*icmp));

	info(" [ ICMP ");

	info("Type (%u), ", icmp->type);
	info("Code (%u), ", icmp->code);
	info("Csum (0x%x), \n", icmp->checksum);

	info(" ] \n");
}

void icmp_display_hex(const uint8_t * const pkt, const size_t len)
{
	size_t a;

	assert(pkt);
	assert(len >= sizeof(struct icmphdr));

	info(" [ ICMP (");
	for (a = 0; a < sizeof(struct icmphdr); a++)
	{
		info("%.2x ", pkt[a]);
	}

	info(") ]\n");

}

void icmp_display_c_style(const uint8_t * const pkt, const size_t len)
{
	size_t a;

	assert(pkt);
	assert(len >= sizeof(struct icmphdr));

	info("const uint8_t icmp[] = {");

	for (a = 0; a < len - 1; a++)
	{
		info("0x%.2x, ", pkt[a]);
	}

	if (len > 0)
		info("0x%.2x };\n", pkt[len]);

	info("};\n");

}

size_t icmp_offset_get(const uint8_t * const pkt, const size_t len)
{
	assert(pkt);
	assert(len >= sizeof(struct icmphdr));

	return(sizeof(struct icmphdr));
}

uint16_t icmp_key_get(const uint8_t * const pkt, const size_t len)
{
	assert(pkt);
	assert(len >= sizeof(struct icmphdr));

	return (PAYLOAD_DEFAULT_KEY); 
}

void icmp_display_set(const enum display_type dtype)
{
	switch(dtype)
	{
		case DISPLAY_NORMAL:
			icmp_dissector.display = icmp_display;
		break;

		case DISPLAY_LESS:
			icmp_dissector.display = icmp_display_less;
		break;

		case DISPLAY_C_STYLE:
			icmp_dissector.display = icmp_display_c_style;
		break;

		case DISPLAY_HEX:
			icmp_dissector.display = icmp_display_hex;
		break;

		case DISPLAY_NONE:
			icmp_dissector.display = NULL;
		break;

		default:

		break;
	}
}

int dissector_icmp_insert(void)
{
	return (ethernet_dissector_insert(&icmp_dissector));
}
