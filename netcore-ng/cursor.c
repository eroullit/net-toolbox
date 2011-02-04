
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

#include <netcore-ng/cursor.h>
#include <netcore-ng/macros.h>
#include <netcore-ng/strlcpy.h>

#define SPINNER_SLEEP_TIME	250000

static const char spinning_chars[] = { '|', '/', '-', '\\' };

void spinner_trigger_event(struct spinner_thread_context *ctx)
{
	ctx->events++;
}

void spinner_set_msg(struct spinner_thread_context *ctx, const char *msg)
{
	assert(ctx);
	assert(msg);

	strlcpy(ctx->msg, msg, sizeof(ctx->msg));
}

void spinner_cancel(struct spinner_thread_context *ctx)
{
	if (ctx->active)
		pthread_cancel(ctx->thread);
}

void *spinner_print_progress(void *arg)
{
	uint8_t spin_count = 0;
	uint64_t prev_events = 0;
	struct spinner_thread_context *ctx = (struct spinner_thread_context *)arg;

	ctx->active = 1;

	info("%s", ctx->msg);

	while (1) {
		info("\b%c", spinning_chars[spin_count]);
		fflush(stdout);
		usleep(SPINNER_SLEEP_TIME);

		if (prev_events != ctx->events) {
			spin_count++;
			spin_count %= sizeof(spinning_chars);
			prev_events = ctx->events;
		}
	}
}

int spinner_create(struct spinner_thread_context *ctx)
{
	int rc;

	rc = pthread_create(&ctx->thread, NULL, spinner_print_progress, ctx);

	if (rc != 0)
		return (rc);

	rc = pthread_detach(ctx->thread);

	return (rc);
}

