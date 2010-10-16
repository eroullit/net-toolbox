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
 */

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

extern int parse_cpu_set(const char *str, cpu_set_t * res);
extern void check_for_root(void);

/* Inline stuff */

/**
 * get_tty_length - Returns the current TTY len
 */
static inline int get_tty_length(void)
{
	int ret;

#ifdef TIOCGSIZE
	struct ttysize ts = { 0 };
	ret = ioctl(0, TIOCGSIZE, &ts);
	return ((ret == 0) ? ts.ts_cols : DEFAULT_TERM_SIZE);
#elif defined(TIOCGWINSZ)
	struct winsize ts = { 0 };
	ret = ioctl(0, TIOCGWINSZ, &ts);
	return ((ret == 0) ? ts.ws_col : DEFAULT_TERM_SIZE);
#else
	return DEFAULT_TERM_SIZE;
#endif				/* TIOCGSIZE */
}

#endif				/* _NET_SYSTEM_H_ */
