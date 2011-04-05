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

#ifndef __NET_GENERIC_H__
#define __NET_GENERIC_H__

#include <net/if.h>

#include <netcore-ng/job.h>
#include <netcore-ng/packet.h>
#include <netcore-ng/bpf.h>
#include <netcore-ng/pcap.h>

struct generic_nic_context
{
	/* Structure which describe a nic instead? */
	char 					dev_name[IFNAMSIZ];
	int					dev_fd;
	int 					pcap_fd;
	enum pcap_linktype			linktype;
	struct sock_fprog 			bpf;
	struct job_list				job_list;
	struct packet_ctx			pkt_ctx;
};

#endif /* __NET_GENERIC_H__ */
