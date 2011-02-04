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


#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <assert.h>

#include <netcore-ng/macros.h>
#include <netcore-ng/system.h>

/**
 * nexttoken - Fetches next param token
 * @q:        string
 * @sep:      token separator
 */
static inline const char *nexttoken(const char *q, int sep)
{
	if (q) {
		q = strchr(q, sep);
	}
	if (q) {
		q++;
	}

	return (q);
}

int cpu_set_parse(const char *str, cpu_set_t * res)
{
	const char *p, *q;

	assert(str);
	assert(res);

	q = str;

	CPU_ZERO(res);

	while (p = q, q = nexttoken(q, ','), p) {
		unsigned int a;	/* Beginning of range */
		unsigned int b;	/* End of range */
		unsigned int s;	/* Stride */

		const char *c1, *c2;

		if (sscanf(p, "%u", &a) < 1) {
			return 1;
		}

		b = a;
		s = 1;

		c1 = nexttoken(p, '-');
		c2 = nexttoken(p, ',');

		if (c1 != NULL && (c2 == NULL || c1 < c2)) {
			if (sscanf(c1, "%u", &b) < 1) {
				return 1;
			}

			c1 = nexttoken(c1, ':');
			if (c1 != NULL && (c2 == NULL || c1 < c2)) {
				if (sscanf(c1, "%u", &s) < 1) {
					return (1);
				}
			}
		}

		if (!(a <= b)) {
			return (1);
		}

		while (a <= b) {
			CPU_SET(a, res);
			a += s;
		}
	}

	return (0);
}

/**
 * check_for_root - Checks user ID for root
 */
void check_for_root(void)
{
	if (geteuid() != 0) {
		warn("Not root?! You shall not pass!\n");
		exit(EXIT_FAILURE);
	}
}
