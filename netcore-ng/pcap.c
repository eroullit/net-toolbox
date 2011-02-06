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


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/stat.h>

/* BEGIN TODO reorganize things that pcap function does know much about private types */
#include <netcore-ng/types.h>
#include <netcore-ng/rx_ring.h>
/* END TODO */
#include <netcore-ng/rx_job.h>
#include <netcore-ng/pcap.h>
#include <netcore-ng/macros.h>

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

int pcap_validate_header(const int fd)
{
	struct pcap_file_header hdr;

	if (fd < 0) {
		warn("Invalid file descriptor.\n");
		return (0);
	}

	if (read(fd, (char *)&hdr, sizeof(hdr)) != sizeof(hdr)) {
		err("Error reading dump file");
		return (EIO);
	}

	if (hdr.magic != TCPDUMP_MAGIC
	    || hdr.version_major != PCAP_VERSION_MAJOR
	    || hdr.version_minor != PCAP_VERSION_MINOR || hdr.linktype != LINKTYPE_EN10MB) {
		errno = EINVAL;
		err("This file is certainly not a valid pcap");
		return (EIO);
	}

	return (0);
}

size_t pcap_fetch_next_packet(const int fd, struct tpacket_hdr * tp_h, struct ethhdr * sp)
{
	struct pcap_sf_pkthdr sf_hdr;

	assert(fd > 0);

	if (tp_h == NULL || sp == NULL) {
		errno = EINVAL;
		err("Can't access packet header");
		return (0);
	}

	if (read(fd, (char *)&sf_hdr, sizeof(sf_hdr)) != sizeof(sf_hdr)) {
		return (0);
	}
	
	/* TODO Need to set the other structure element ? */
	tp_h->tp_sec = sf_hdr.ts.tv_sec;
	tp_h->tp_usec = sf_hdr.ts.tv_usec;
	tp_h->tp_snaplen = sf_hdr.caplen;
	tp_h->tp_len = sf_hdr.len;

	if (read(fd, (char *)sp, sf_hdr.len) != sf_hdr.len) {
		return (0);
	}

	return (sf_hdr.len);
}

int pcap_write_header(const int fd, const int linktype, const int thiszone, const int snaplen)
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

ssize_t pcap_write_payload(const int fd, const struct tpacket_hdr * const tp_h, const struct ethhdr const *sp)
{
	struct pcap_sf_pkthdr sf_hdr;
	ssize_t written = 0;

	assert(tp_h);
	assert(sp);

	/* 
	 *  XXX keep in mind that timestamps in tp_h are unsigned int
	 * whereas they are int32_t in pcap_sf_pkthdr
	 */

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
		err("Cannot write pcap header wrote %zi/%zi bytes", written, sizeof(sf_hdr));
		return(-1);
	}

	if ((written = write(fd, sp, sf_hdr.len)) != sf_hdr.len)
	{
		err("Cannot write pcap payload wrote %zi/%u bytes", written, sf_hdr.len);
		return(-1);
	}

	return (written);
}

ssize_t pcap_write_accessor(const struct netsniff_ng_rx_thread_context * const ctx, const struct frame_map * const fm)
{
	return(pcap_write_payload(ctx->nic_ctx.pcap_fd, &fm->tp_h, (struct ethhdr *)frame_map_pkt_buf_get(fm)));
}

void pcap_destroy(const int pcap_fd, const char * const pcap_path)
{
	assert(pcap_path);
	assert(pcap_fd > 0);

	close(pcap_fd);

	if (unlink(pcap_path))
	{
		err("Cannot remove pcap");
	}
}

int pcap_create(const char * const pcap_path)
{
	assert(pcap_path);

	int fd;

	if ((fd = creat(pcap_path, DEFFILEMODE)) < 0)
	{
		err("Cannot create pcap %s\n", pcap_path);
		return (-1);
	}
	
	/* TODO make it configurable instead of using default values */
	if (pcap_write_header(fd, LINKTYPE_EN10MB, 0, PCAP_DEFAULT_SNAPSHOT_LEN))
	{
		/* When the PCAP header cannot be written the file
		 * must be closed and then deleted
		 */
		pcap_destroy(fd, pcap_path);
		fd = -1;
	}
	
	return (fd);
}

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

	if (pcap_validate_header(fd))
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

int pcap_close(const int fd)
{
	return (close(fd));
}

int pcap_write_job_register(struct rx_job_list * job_list)
{
	return (rx_job_list_insert(job_list, pcap_write_accessor));
}

