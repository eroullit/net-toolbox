
#ifndef _NET_SYSTEM_H_
#define _NET_SYSTEM_H_

#include <stdio.h>
#include <string.h>
#include <sched.h>

#include <sys/ioctl.h>

#define DEFAULT_SCHED_POLICY	SCHED_FIFO
#define DEFAULT_SCHED_PRIO	sched_get_priority_max(DEFAULT_SCHED_POLICY)

#define DEFAULT_TERM_SIZE	(80)

/* Function signatures */

extern int cpu_set_parse(const char * str, cpu_set_t * res);
extern void check_for_root(void);

/* Inline stuff */

/**
 * get_tty_length - Returns the current TTY len
 */
static inline int get_tty_length(void)
{
	int ret;

#ifdef TIOCGSIZE
	struct ttysize ts;
	memset(&ts, 0, sizeof(ts));
	ret = ioctl(0, TIOCGSIZE, &ts);
	return ((ret == 0) ? ts.ts_cols : DEFAULT_TERM_SIZE);
#elif defined(TIOCGWINSZ)
	struct winsize ts;
	memset(&ts, 0, sizeof(ts));
	ret = ioctl(0, TIOCGWINSZ, &ts);
	return ((ret == 0) ? ts.ws_col : DEFAULT_TERM_SIZE);
#else
	return DEFAULT_TERM_SIZE;
#endif				/* TIOCGSIZE */
}

#endif				/* _NET_SYSTEM_H_ */
