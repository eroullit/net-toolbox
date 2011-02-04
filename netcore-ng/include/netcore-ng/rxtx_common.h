
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
