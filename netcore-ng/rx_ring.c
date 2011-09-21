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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <poll.h>

#include <netcore-ng/rx_ring.h>
#include <netcore-ng/packet_mmap.h>
#include <netcore-ng/nic.h>

int rx_thread_listen(struct rx_thread_ctx * thread)
{
	struct packet_mmap_ctx * pkt_mmap = NULL;
	struct pollfd pfd;
	struct timeval pkt_ts;
	int rc;

	assert(thread);

	memset(&pfd, 0, sizeof(pfd));
	pfd.events = POLLIN|POLLRDNORM|POLLERR;
	pfd.fd = thread->nic.dev_fd;

	for(;;)
	{
		for(packet_mmap_ctx_reset(pkt_mmap); !packet_mmap_ctx_end(pkt_mmap); packet_mmap_ctx_next(pkt_mmap))
		{
			if ((packet_mmap_ctx_status_get(pkt_mmap) & TP_STATUS_KERNEL) == TP_STATUS_KERNEL)
			{
				/* Force sleep here when the user wants */
				if ((rc = poll(&pfd, 1, -1)) < 0)
				{
					continue;
				}
			}

			/* TODO Add support for TP_STATUS_COPY */
			if ((packet_mmap_ctx_status_get(pkt_mmap) & TP_STATUS_USER) == TP_STATUS_USER)
			{
				pkt_ts = packet_mmap_ctx_ts_get(pkt_mmap);
				printf("RCV packet ts:%ld.%06ld s len:%zu\n", pkt_ts.tv_sec, pkt_ts.tv_usec, packet_mmap_ctx_payload_len_get(pkt_mmap));
			}
		}
	}
}

struct rx_thread_ctx * rx_thread_create(const char * const dev_name)
{
	int rc;
	struct rx_thread_ctx * thread_config = NULL;

	if ((thread_config = calloc(1, sizeof(*thread_config))) == NULL)
	{
		return (NULL);
	}

	if ((rc = nic_init(&thread_config->nic, dev_name)) != 0)
	{
		goto error;
	}

	return (thread_config);

error:
	rx_thread_destroy(thread_config);
	return (NULL);
}

void rx_thread_destroy(struct rx_thread_ctx * thread_config)
{
	assert(thread_config);

	nic_destroy(&thread_config->nic);
	free(thread_config);
}
