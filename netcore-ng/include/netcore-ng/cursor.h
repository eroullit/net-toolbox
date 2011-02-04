
#ifndef _CURSOR_H_
#define _CURSOR_H_

#include <stdint.h>

#define MAX_MESSAGE_SIZE	64

struct spinner_thread_context {
	pthread_t thread;
	uint8_t active;
	char msg[MAX_MESSAGE_SIZE];
	uint64_t events;
};

/* Function signatures */

extern void spinner_trigger_event(struct spinner_thread_context *ctx);
extern void spinner_set_msg(struct spinner_thread_context *ctx, const char *msg);
extern void spinner_cancel(struct spinner_thread_context *ctx);
extern int spinner_create(struct spinner_thread_context *ctx);

#endif				/* _CURSOR_H_ */
