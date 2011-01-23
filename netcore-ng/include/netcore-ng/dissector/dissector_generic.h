#ifndef	__DISSECTOR_GENERIC_H__
#define	__DISSECTOR_GENERIC_H__

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <netinet/in.h>

#include <netcore-ng/macros.h>
#include <netcore-ng/ether_types.h>

#define DISSECTOR_MAX	100

enum display_type
{
	DISPLAY_NORMAL,
	DISPLAY_LESS,
	DISPLAY_HEX,
	DISPLAY_C_STYLE,
	DISPLAY_NONE,
};

struct protocol_dissector
{
	size_t (*display)(const uint8_t * const pkt, const size_t len, const size_t off);
	size_t (*get_offset)(void);
	uint16_t (*get_next_key)(const uint8_t * const pkt, const size_t len, const size_t off);
	void (*display_set)(const enum display_type dtype);
	const uint16_t key;
};

#endif	/* __DISSECTOR_GENERIC_H__ */
