/* __LICENSE_HEADER_BEGIN__ */

/*
 * Copyright (C) 2009, 2011  Daniel Borkmann <daniel@netsniff-ng.org> and
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
