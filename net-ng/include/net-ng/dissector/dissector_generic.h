#ifndef	__DISSECTOR_GENERIC_H__
#define	__DISSECTOR_GENERIC_H__

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <netinet/in.h>

#include <net-ng/ether_types.h>

#define DISSECTOR_MAX	100

enum display_type
{
	DISPLAY_NORMAL,
	DISPLAY_LESS,
	DISPLAY_HEX,
	DISPLAY_C_LIKE,
	DISPLAY_NONE,
};

struct protocol_dissector
{
	void (*display)(const uint8_t * const pkt, const size_t len);
	size_t (*get_offset)(const uint8_t * const pkt, const size_t len);
	uint16_t (*get_next_key)(const uint8_t * const pkt, const size_t len);
};

#endif	/* __DISSECTOR_GENERIC_H__ */
