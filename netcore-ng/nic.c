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

#include <linux/if_packet.h>

#include <netcore-ng/nic.h>
#include <netcore-ng/packet_mmap.h>

static void nic_destroy(struct nic_ctx * nic)
{
	assert(nic);

	close(nic->dev_fd);
}

static int nic_init(struct nic_ctx * nic, const char * dev_name)
{
	struct tpacket_req layout;
	int dev_arp_type;
	int rc = 0;

	assert(nic);
	assert(dev_name);

	memset(&layout, 0, sizeof(layout));

	/* tp_frame_size should be carefully chosen to fit closely to snapshot len */
	/* TODO Handle Super Jumbo Frames */
	layout.tp_frame_size = TPACKET_ALIGNMENT << 7;
	layout.tp_block_size = getpagesize() << 2;
	layout.tp_block_nr = ((128 * 1024) / layout.tp_block_size); /* 128kB mmap */
	layout.tp_frame_nr = layout.tp_block_size / layout.tp_frame_size * layout.tp_block_nr;

	if (!is_device_ready(dev_name))
	{
		return (EAGAIN);
	}

	strlcpy(nic->dev_name, dev_name, IFNAMSIZ);
	
	if ((rc = get_arp_type(nic->dev_name, &dev_arp_type)) != 0)
	{
		goto error;
	}

	nic->dev_fd = get_pf_socket();
	
	if (nic->dev_fd < 0)
	{
		rc = EPERM;
		goto error;
	}

	return(0);

error:
	nic_destroy(nic);
	return (rc);
}

