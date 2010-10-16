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
 */

#ifndef _DUMP_H_
#define	_DUMP_H_

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>

extern int pcap_write_header(int fd, int linktype, int thiszone, int snaplen);
extern void pcap_write_payload(int fd, struct tpacket_hdr *tp_h, const struct ethhdr const *sp);
extern int prepare_pcap(const char * pcap_path);
extern void remove_pcap(int pcap_fd, const char * pcap_path);

#endif				/* _DUMP_H_ */
