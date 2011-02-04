/* __LICENSE_HEADER_BEGIN__ */

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
 *
 */

 /* __LICENSE_HEADER_END__ */


#ifndef _NET_RXTX_COMMON_H_
#define _NET_RXTX_COMMON_H_

#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include <sys/poll.h>

#include <netcore-ng/macros.h>
#include <netcore-ng/types.h>
#include <netcore-ng/xmalloc.h>

#ifndef POLLRDNORM
# define POLLRDNORM      0x0040
#endif
#ifndef POLLWRNORM
# define POLLWRNORM      0x0100
#endif

/* Inline stuff */

/**
 * alloc_frame_buffer - Allocates frame buffer
 * @rb:                ring buff struct
 */
static inline int frame_buffer_create(struct ring_buff * rb, struct tpacket_req req)
{
	uint32_t i = 0;

	assert(rb);

	rb->frames = malloc(req.tp_frame_nr * sizeof(*rb->frames));
	if (!rb->frames) {
		err("No mem left");
		return (ENOMEM);
	}

	memset(rb->frames, 0, req.tp_frame_nr * sizeof(*rb->frames));

	for (i = 0; i < req.tp_frame_nr; ++i) {
		rb->frames[i].iov_base = (uint8_t *) ((long)rb->buffer) + (i * req.tp_frame_size);
		rb->frames[i].iov_len = req.tp_frame_size;
	}

	return (0);
}

static inline void frame_buffer_destroy(struct ring_buff * rb)
{
	assert(rb);

	free(rb->frames);
}

#endif				/* _NET_RXTX_COMMON_H_ */
