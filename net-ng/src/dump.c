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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "pcap.h"
#include "dump.h"
#include "macros.h"

int pcap_write_header(int fd, int linktype, int thiszone, int snaplen)
{
	struct pcap_file_header hdr = { 0 };

	assert(fd != -1);

	hdr.magic = TCPDUMP_MAGIC;
	hdr.version_major = PCAP_VERSION_MAJOR;
	hdr.version_minor = PCAP_VERSION_MINOR;

	hdr.thiszone = thiszone;
	hdr.snaplen = snaplen;
	hdr.sigfigs = 0;
	hdr.linktype = linktype;

	if (write(fd, (char *)&hdr, sizeof(hdr)) != sizeof(hdr)) {
		err("Failed to write pcap header");
		return (-1);
	}

	return (0);
}

void pcap_write_payload(int fd, struct tpacket_hdr *tp_h, const struct ethhdr const *sp)
{
	struct pcap_sf_pkthdr sf_hdr;
	size_t written = 0;

	memset(&sf_hdr, 0, sizeof(sf_hdr));
	sf_hdr.ts.tv_sec = tp_h->tp_sec;
	sf_hdr.ts.tv_usec = tp_h->tp_usec;
	sf_hdr.caplen = tp_h->tp_snaplen;
	sf_hdr.len = tp_h->tp_len;

	/*
	 * XXX we should check the return status
	 * but then do what just inform the user
	 * or exit gracefully ?
	 */

	if ((written = write(fd, &sf_hdr, sizeof(sf_hdr))) != sizeof(sf_hdr)) {
		err("Cannot write pcap header wrote %zu/%zu bytes", written, sizeof(sf_hdr));
		close(fd);
		exit(EXIT_FAILURE);
	}

	if ((written = write(fd, sp, sf_hdr.len)) != sf_hdr.len)
	{
		err("Cannot write pcap payload wrote %zu/%u bytes %i", written, sf_hdr.len, errno);
		close(fd);
		exit(EXIT_FAILURE);
	}
}

int prepare_pcap(const char * pcap_path)
{
	assert(pcap_path);

	int fd;

	fd = creat(pcap_path, DEFFILEMODE);
		
	if (fd != -1) {
		/* TODO make it configurable instead of using default values */
		if (pcap_write_header(fd, LINKTYPE_EN10MB, 0, PCAP_DEFAULT_SNAPSHOT_LEN))
		{
			/* When the PCAP header cannot be written the file
			 * must be closed and then deleted
			 */

			remove_pcap(fd, pcap_path);
			fd = -1;
		}
	}
	
	return (fd);
}

void remove_pcap(int pcap_fd, const char * pcap_path)
{
	assert(pcap_path);
	assert(pcap_fd > 0);

	close(pcap_fd);
	unlink(pcap_path);
}
