/**
 * \file nic.c
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

#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>

#include <linux/if_packet.h>

#include <netcore-ng/strlcpy.h>
#include <netcore-ng/nic.h>
#include <netcore-ng/packet_mmap.h>

/**
 * \internal
 * \brief Get NIC status flags from the kernel
 * \param[in] dev Name of the device
 * \return current NIC flags on sucess, -1 on failure
 */

short nic_flags_get(const char * const dev)
{
	int ret;
	int sock;
	struct ifreq ethreq;

	assert(dev);

	sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (sock < 0) {
		return (-1);
	}
	
	memset(&ethreq, 0, sizeof(ethreq));
	strlcpy(ethreq.ifr_name, dev, sizeof(ethreq.ifr_name));

	ret = ioctl(sock, SIOCGIFFLAGS, &ethreq);

	close(sock);

	if (ret < 0) {
		return (ret);
	}

	return (ethreq.ifr_flags);
}

/**
 * \brief Get NIC ARP type from the kernel
 * \param[in] dev Name of the device
 * \param[out] arp_type NIC ARP type
 * \return 0 on success, \c EINVAL on ioctl failure or socket(2) error code
 */

int nic_arp_type_get(const char * const dev, int * arp_type)
{
	int ret;
	int sock;
	struct ifreq ifr;

	assert(dev);
	assert(arp_type);

	sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (sock < 0) {
		return (errno);
	}

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));

	ret = ioctl(sock, SIOCGIFHWADDR, &ifr);

	close(sock);

	if (ret < 0) {
		return (EINVAL);
	}

	*arp_type = ifr.ifr_hwaddr.sa_family;
	
	return (0);
}

/**
 * \brief Tell if NIC if currently up
 * \param[in] dev Name of the device
 * \return 0 if NIC is down, 1 if NIC is up
 */

int is_nic_up(const char * const dev)
{
	int up = 0;
	short nic_flags;

	assert(dev);

	nic_flags = nic_flags_get(dev);

	if (nic_flags > 0 && (nic_flags & IFF_UP) == IFF_UP) {
		up = 1;
	}

	return (up);
}

/**
 * \brief Tell if NIC if currently running
 * \param[in] dev Name of the device
 * \return 0 if NIC is not running, 1 if NIC currently running
 */

int is_nic_running(const char * const dev)
{
	int running = 0;
	short nic_flags;
	
	assert(dev);

	nic_flags = nic_flags_get(dev);
	
	if (nic_flags > 0 && (nic_flags & IFF_RUNNING) == IFF_RUNNING) {
		running = 1;
	}
	
	return (running);
}

void nic_destroy(struct nic_ctx * nic)
{
	assert(nic);

	close(nic->dev_fd);
}

int nic_init(struct nic_ctx * nic, const char * const dev_name)
{
	struct tpacket_req layout;
	int dev_arp_type;
	int rc = 0;

	assert(nic);
	assert(dev_name);

	memset(&layout, 0, sizeof(layout));

	/* TODO Handle Super Jumbo Frames */
	layout.tp_frame_size = TPACKET_ALIGNMENT << 7;
	layout.tp_block_size = getpagesize() << 2;
	layout.tp_block_nr = ((128 * 1024) / layout.tp_block_size); /* 128kB mmap */
	layout.tp_frame_nr = layout.tp_block_size / layout.tp_frame_size * layout.tp_block_nr;

	if (!is_nic_up(dev_name) || !is_nic_running(dev_name))
	{
		return (EAGAIN);
	}

	strlcpy(nic->dev_name, dev_name, IFNAMSIZ);
	
	if ((rc = nic_arp_type_get(nic->dev_name, &dev_arp_type)) != 0)
	{
		goto error;
	}

	nic->dev_fd = socket(PF_PACKET, SOCK_RAW, 0);
	
	if (nic->dev_fd < 0)
	{
		rc = errno;
		goto error;
	}

	return(0);

error:
	nic_destroy(nic);
	return (rc);
}

