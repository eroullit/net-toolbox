#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <netcore-ng/dissector/raw.h>

size_t raw_offset_get(const uint8_t * const pkt, const size_t len);
void raw_display_set(const enum display_type dtype);

static struct protocol_dissector raw_dissector = 
{
	.display = NULL,
	.get_offset = NULL,
	.get_next_key = NULL,
	.display_set = raw_display_set,
	.key = RAW_DEFAULT_KEY
};

size_t _raw_display_less(const uint8_t * const pkt, const size_t len, const size_t off)
{
	size_t a;
	size_t read = min(len - off, RAW_CHUNK);

	assert(len > off);

	for (a = 0; a < read; a++)
	{
		info("%c", isprint(pkt[off + a]) ? pkt[off + a] : '.');
	}

	return(read);
}

size_t _raw_display_hex(const uint8_t * const pkt, const size_t len, const size_t off)
{
	size_t a;
	size_t read = min(len - off, RAW_CHUNK);
	
	assert(len > off);

	info("0x%.4zX | ", off);

	for (a = 0; a < read; a++)
	{
		info("%.2x ", pkt[off + a]);
	}

	return(read);
}

size_t raw_display(const uint8_t * const pkt, const size_t len, const size_t off)
{
	size_t a = off;

	while (a < len)
	{
		_raw_display_hex(pkt, len, a);
		info(" | ");
		a += _raw_display_less(pkt, len, a);
		info("\n");
	}

	return (len - a);
}

size_t raw_display_hex(const uint8_t * const pkt, const size_t len, const size_t off)
{
	size_t a = off;

	while (a < len)
	{
		a += _raw_display_hex(pkt, len, a);
		info("\n");
	}

	return (len - a);
}

size_t raw_display_less(const uint8_t * const pkt, const size_t len, const size_t off)
{
	size_t a = off;

	while (a < len)
	{
		a += _raw_display_less(pkt, len, a);
		info("\n");
	}

	return (len - a);
}

size_t raw_display_c_style(const uint8_t * const pkt, const size_t len, const size_t off)
{
	size_t a;

	assert(len > off);

	info("const uint8_t raw[] = {");

	for (a = off; a < len - 1; a++)
	{
		info("0x%.2x, ", pkt[a]);
	}

	info("0x%.2x};\n", pkt[len]);

	return(len - off);
}

void raw_display_set(const enum display_type dtype)
{
	switch(dtype)
	{
		case DISPLAY_NORMAL:
			raw_dissector.display = raw_display;
		break;

		case DISPLAY_LESS:	
			raw_dissector.display = raw_display_less;
		break;

		case DISPLAY_HEX:
			raw_dissector.display = raw_display_hex;
		break;

		case DISPLAY_C_STYLE:
			raw_dissector.display = raw_display_c_style;
		break;

		case DISPLAY_NONE:
			raw_dissector.display = NULL;
		break;

		default:

		break;
	}
}

int dissector_raw_insert(int (*dissector_insert)(const struct protocol_dissector * const dis))
{
	assert(dissector_insert);
	return (dissector_insert(&raw_dissector));
}

