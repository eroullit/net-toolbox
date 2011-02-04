/* __LICENSE_HEADER_BEGIN__ */

/*
 * Copyright (C) 2009, 2010  Daniel Borkmann <daniel@netsniff-ng.org> and
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

#ifndef	__ETHERNET_DISSECTOR_ETHERNET_H__
#define	__ETHERNET_DISSECTOR_ETHERNET_H__

#include <netcore-ng/dissector/ethernet/dissector.h>

#define ETHERNET_HDR_DEFAULT_KEY	0

int dissector_ethernet_insert(void);
int dissector_ethernet_print_set(const enum display_type);

#endif	/* __ETHERNET_DISSECTOR_ETHERNET_H__ */
