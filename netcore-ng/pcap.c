/**
 * \file pcap.c
 * \author written by Emmanuel Roullit emmanuel@netsniff-ng.org (c) 2009-2011
 * \date 2011
 */

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


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/stat.h>

#include <netcore-ng/job.h>
#include <netcore-ng/pcap.h>
#include <netcore-ng/packet_vector.h>
#include <netcore-ng/macros.h>

/**
 * \brief Get PCAP link type from NIC ARP type
 * \param[in] arp_type ARP type value
 * \param[out] pcap_link_type Pointer to the PCAP link type
 * \return 0 on sucess, \c EINVAL when the ARP type is not supported
 */

int pcap_link_type_get(int arp_type, enum pcap_linktype * pcap_link_type)
{
	int rc = 0;

	assert(pcap_link_type);

	switch(arp_type)
	{
		case ARPHRD_ETHER:
		case ARPHRD_LOOPBACK:
			*pcap_link_type = LINKTYPE_EN10MB;
			break;
		default:
			warn("Unsupported ARP type\n");
			rc = EINVAL;
			break;
	}

	return (rc);
}

/**
 * \brief Test if a PCAP still has packets
 * \param[in] fd PCAP file descriptor
 * \return 	-1 if file descriptor is invalid \n
 * 		0 if it is the end of the PCAP	\n
 * 		1 if there are packets left
 */

int pcap_has_packets(const int fd)
{
	off_t pos;
	struct pcap_sf_pkthdr sf_hdr;

	if (fd < 0) {
		warn("Invalid file descriptor.\n");
		return (-1);
	}

	if ((pos = lseek(fd, (off_t) 0, SEEK_CUR)) < 0) {
		err("Cannot seek offset of pcap file");
		return (-1);
	}

	/* Test pcap header */
	if (read(fd, (char *)&sf_hdr, sizeof(sf_hdr)) != sizeof(sf_hdr)) {
		return (0);	/* EOF */
	}

	/* Test payload */
	if (lseek(fd, pos + sf_hdr.len, SEEK_SET) < 0) {
		return (0);	/* EOF */
	}

	/* Rewind the offset */
	if (lseek(fd, pos, SEEK_SET) < 0) {
		err("Cannot rewind pcap file");
		return (-1);
	}

	return (1);
}

/**
 * \brief Validate PCAP file header
 * Every PCAP file has a file header which contains:
 * 	- the PCAP magic (\c 0xa1b2c3d4)
 * 	- the PCAP version major/minor
 * 	- the PCAP linktype
 * 	- the timezone
 * 	- the maxumum packet length
 * \param[in] fd PCAP file descriptor
 * \return	0 if the PCAP file header is not valid \n
 * 		1 if it is. \n
 * 		If PCAP file header is invalid, errno is set to \n
 * 		\c EINVAL if PCAP file descriptor or file header is invalid \n
 * 		\c EIO if PCAP file header could not be read
 */

int pcap_is_valid(const int fd)
{
	struct pcap_file_header hdr;

	if (fd < 0) {
		warn("Invalid file descriptor.\n");
		errno = EINVAL;
		return (0);
	}

	if (read(fd, (char *)&hdr, sizeof(hdr)) != sizeof(hdr)) {
		err("Error reading dump file");
		errno = EIO;
		return (0);
	}

	if (hdr.magic != TCPDUMP_MAGIC
	    || hdr.version_major != PCAP_VERSION_MAJOR
	    || hdr.version_minor != PCAP_VERSION_MINOR || hdr.linktype != LINKTYPE_EN10MB) {
		errno = EINVAL;
		err("This file is certainly not a valid pcap");
		return (0);
	}

	return (1);
}

/**
 * \brief Write the PCAP file header on a file descriptor
 * \param[in] fd PCAP file descriptor
 * \param[in] linktype PCAP link type
 * \param[in] thiszone Timezone where the PCAP is created
 * \param[in] snaplen Maximum length of a captured packet
 * \return 0 on success, -1 if PCAP file header could not be written
 */

int pcap_file_header_write(const int fd, const int linktype, const int thiszone, const int snaplen)
{
	struct pcap_file_header hdr;

	assert(fd > 0);

	memset(&hdr, 0, sizeof(hdr));

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

void pcap_packet_header_set(struct pcap_sf_pkthdr * pcap_pkt_hdr, const struct timeval * ts, const size_t len)
{
	assert(pcap_pkt_hdr);
	assert(ts);

	pcap_pkt_hdr->ts.tv_sec = ts->tv_sec;
	pcap_pkt_hdr->ts.tv_usec = ts->tv_usec;
	pcap_pkt_hdr->len = len;
	pcap_pkt_hdr->caplen = len;
}

ssize_t pcap_writev(const int fd, const struct packet_iovec * const pkt_vec)
{
	assert(fd > 0);
	assert(pkt_vec);

	return (writev(fd, pkt_vec->pkt_io_vec, pkt_vec->used));
}

/**
 * \brief Destroy a PCAP file
 * \param[in] fd PCAP file descriptor
 * \param[in] pcap_path	PCAP file path
 */

void pcap_destroy(const int fd, const char * const pcap_path)
{
	assert(pcap_path);
	assert(fd > 0);

	close(fd);

	if (unlink(pcap_path))
	{
		err("Cannot remove pcap");
	}
}

/**
 * \brief Create a PCAP file
 * \param[in] pcap_path	PCAP file path
 * \param[in] linktype PCAP link type
 * \return PCAP file descriptor on sucess, -1 on failure
 * \note It creates a PCAP file with default permissions
 * \note A created PCAP will have by default a snapshot length of 65535 bytes.
 */

int pcap_create(const char * const pcap_path, const enum pcap_linktype linktype)
{
	assert(pcap_path);

	int fd;

	if ((fd = creat(pcap_path, DEFFILEMODE)) < 0)
	{
		err("Cannot create pcap %s\n", pcap_path);
		return (-1);
	}
	
	/* TODO make it configurable instead of using default values */
	if (pcap_file_header_write(fd, linktype, 0, PCAP_DEFAULT_SNAPSHOT_LEN))
	{
		/* When the PCAP header cannot be written the file
		 * must be closed and then deleted
		 */
		pcap_destroy(fd, pcap_path);
		fd = -1;
	}
	
	return (fd);
}

/**
 * \brief Open a PCAP file
 * \param[in] pcap_path	PCAP file path
 * \param[in] flags flags for \c open(2)
 * \return PCAP file descriptor on sucess, -1 on failure
 * \note The flags given as parameter are directly given to \c open(2)
 */

int pcap_open(const char * const pcap_path, int flags)
{
	int append = 0;
	int fd;

	assert(pcap_path);

	/* Deactivate append to be able to check pcap validity */
	if ((flags & O_APPEND) == O_APPEND)
	{
		append = 1;
		flags &= ~O_APPEND;
	}

	if ((fd = open(pcap_path, flags)) < 0)
	{
		err("Could not open pcap file");
		return (-1);
	}

	if (pcap_is_valid(fd) == 0)
	{
		err("Failed to validate PCAP");
		close(fd);
		return (-1);
	}

	if (append)
	{
		/* Go to EOF */
		if (lseek(fd, 0, SEEK_END) < 0) {
			err("Cannot seek end of pcap file");
			close(fd);
			return (-1);
		}
	}

	return (fd);
}

/**
 * \brief Close a PCAP file
 * \param[in] fd PCAP file descriptor
 * \return same error values as \c close(2)
 */

int pcap_close(const int fd)
{
	return (close(fd));
}

