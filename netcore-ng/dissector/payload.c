#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <netcore-ng/dissector/payload.h>

size_t payload_offset_get(const uint8_t * const pkt, const size_t len);
uint16_t payload_key_get(const uint8_t * const pkt, const size_t len);
void payload_display_set(const enum display_type dtype);

static struct protocol_dissector payload_dissector = 
{
	.display = NULL,
	.get_offset = NULL,
	.get_next_key = NULL,
	.display_set = payload_display_set,
	.key = PAYLOAD_DEFAULT_KEY
};

void payload_display(const uint8_t * const pkt, const size_t len)
{
	size_t a;

	info("[ Payload ");

	for (a = 0; a < len; a++)
	{
		info("%c ", isprint(pkt[a]) ? pkt[a] : '.');
	}

	info("]\n");
}

void payload_display_hex(const uint8_t * const pkt, const size_t len)
{
	size_t a;

	info("[ Payload ");

	for (a = 0; a < len; a++)
	{
		info("%.2x ", pkt[a]);
	}

	info("]\n");
}

void payload_display_c_style(const uint8_t * const pkt, const size_t len)
{
	size_t a;

	info("const char payload[] = {");

	for (a = 0; a < len - 1; a++)
	{
		info("0x%.2x, ", pkt[a]);
	}

	if (len > 0)
		info("0x%.2x };\n", pkt[len]);

	info("};\n");
}

void payload_display_set(const enum display_type dtype)
{
	switch(dtype)
	{
		case DISPLAY_NORMAL:
			payload_dissector.display = payload_display;
		break;

		case DISPLAY_LESS:	
		case DISPLAY_HEX:
			payload_dissector.display = payload_display_hex;
		break;

		case DISPLAY_C_STYLE:
			payload_dissector.display = payload_display_c_style;
		break;

		case DISPLAY_NONE:
			payload_dissector.display = NULL;
		break;

		default:

		break;
	}
}

int dissector_payload_insert(int (*dissector_insert)(const uint16_t key, const struct protocol_dissector * const dis))
{
	assert(dissector_insert);
	return (dissector_insert(payload_dissector.key, &payload_dissector));
}

