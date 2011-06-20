/* __LICENSE_HEADER_BEGIN__ */

/*
 * Copyright (C) 2009-2011	Emmanuel Roullit <emmanuel@netsniff-ng.org>
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

#ifndef	__ETHERNET_DISSECTOR_H__
#define	__ETHERNET_DISSECTOR_H__

#include <libhashish.h>

#include <netcore-ng/ether_types.h>
#include <netcore-ng/oui.h>
#include <netcore-ng/ports_tcp.h>
#include <netcore-ng/ports_udp.h>

#include <netcore-ng/dissector/dissector_generic.h>
#include <netcore-ng/dissector/raw.h>
#include <netcore-ng/dissector/ethernet/ethernet.h>
#include <netcore-ng/dissector/ethernet/arp.h>
#include <netcore-ng/dissector/ethernet/ip.h>
#include <netcore-ng/dissector/ethernet/tcp.h>
#include <netcore-ng/dissector/ethernet/icmp.h>

int ethernet_dissector_insert(const struct protocol_dissector * const dis);
ssize_t ethernet_dissector_run(uint8_t * pkt, size_t len);
int ethernet_dissector_init(const enum display_type dtype);
void ethernet_dissector_destroy(void);

#endif	/* __ETHERNET_DISSECTOR_H__ */
