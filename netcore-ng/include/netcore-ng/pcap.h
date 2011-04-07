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


#ifndef _PCAP_H_
#define	_PCAP_H_

#include <stdint.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>

#include <netcore-ng/packet.h>

#define TCPDUMP_MAGIC               0xa1b2c3d4
#define PCAP_VERSION_MAJOR          2
#define PCAP_VERSION_MINOR          4
#define PCAP_DEFAULT_SNAPSHOT_LEN   65535

/**	\brief	Enum regrouping all possible PCAP link types */
enum pcap_linktype
{
	LINKTYPE_NULL = 0,	/**< BSD loopback encapsulation */
	LINKTYPE_EN10MB = 1,	/**< Ethernet (10Mb) */
	LINKTYPE_EN3MB = 2,	/**< Experimental Ethernet (3Mb) */
	LINKTYPE_AX25 = 3,	/**< Amateur Radio AX.25 */
	LINKTYPE_PRONET = 4,	/**< Proteon ProNET Token Ring */
	LINKTYPE_CHAOS = 5,	/**< Chaos */
	LINKTYPE_IEEE802 = 6,	/**< 802.5 Token Ring */
	LINKTYPE_ARCNET = 7,	/**< ARCNET, with BSD-style header */
	LINKTYPE_SLIP = 8,	/**< Serial Line IP */
	LINKTYPE_PPP = 9,	/**< Point-to-point Protocol */
	LINKTYPE_FDDI = 10	/**< FDDI */
};

/**	\brief	Enum regrouping all possible PCAP link types */
struct pcap_file_header {
	uint32_t magic;		/**< Magic is 0xa1b2c3d4, if swapped all fields must be swapped */
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;	/**< GMT to local correction leave it zero */
	uint32_t sigfigs;	/**< accuracy of timestamps. Set on 0 */
	uint32_t snaplen;	/**< max length saved portion of each pkt. normally 65535, can be more */
	uint32_t linktype;	/**< data link type (LINKTYPE_*) */
};

/**
 * 	\brief	Timestamp structure used in a PCAP file
 * 	
 * 	This is a timeval as stored in a savefile.
 * 	It has to use the same types everywhere, independent of the actual
 * 	`struct timeval'; `struct timeval' has 32-bit tv_sec values on some
 * 	platforms and 64-bit tv_sec values on other platforms, and writing
 * 	out native `struct timeval' values would mean files could only be
 * 	read on systems with the same tv_sec size as the system on which
 * 	the file was written.
 */

struct pcap_timeval {
	int32_t tv_sec;		/**< seconds */
	int32_t tv_usec;	/**< microseconds */
};

/**
 * 	\brief	Structure describing a PCAP packet header
 * 
 * 	Generic per-packet information, as supplied by libpcap.
 *
 * 	The time stamp can and should be a "struct timeval", regardless of
 * 	whether your system supports 32-bit tv_sec in "struct timeval",
 * 	64-bit tv_sec in "struct timeval", or both if it supports both 32-bit
 * 	and 64-bit applications.  The on-disk format of savefiles uses 32-bit
 * 	tv_sec (and tv_usec); this structure is irrelevant to that.  32-bit
 * 	and 64-bit versions of libpcap, even if they're on the same platform,
 * 	should supply the appropriate version of "struct timeval", even if
 * 	that's not what the underlying packet capture mechanism supplies.
 */

struct pcap_sf_pkthdr {
	struct pcap_timeval ts;	/**< timestamp */
	uint32_t caplen;	/**< length of portion present */
	int32_t len;		/**< length this packet (off wire) */
};

int pcap_get_link_type(int arp_type, enum pcap_linktype * pcap_link_type);
int pcap_has_packets(const int fd);
int pcap_validate_header(const int fd);
size_t pcap_fetch_next_packet(const int fd, struct packet_ctx * pkt_ctx);
int pcap_write_header(const int fd, const int linktype, const int thiszone, const int snaplen);
ssize_t pcap_write_payload(const int fd, const struct packet_ctx * const pkt_ctx);
void pcap_destroy(const int pcap_fd, const char * const pcap_path);
int pcap_create(const char * const pcap_path, const enum pcap_linktype linktype);
int pcap_open(const char * const pcap_path, const int flags);
int pcap_close(const int fd);

#endif				/* _PCAP_H_ */
