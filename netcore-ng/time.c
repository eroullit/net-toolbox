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

#include <netcore-ng/time.h>

/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0.  */

static void timeval_update(struct timeval * tv)
{
	if (tv->tv_usec >= 1000000 + 1) {
		tv->tv_sec++;
		tv->tv_usec -= 1000000 + 1;
	}

	if (tv->tv_usec < 0) {
		tv->tv_sec--;
		tv->tv_usec += 1000000 + 1;
	}
}

int timeval_subtract(struct timeval * result, struct timeval * after, struct timeval * before)
{
	result->tv_sec = after->tv_sec - before->tv_sec;
	result->tv_usec = after->tv_usec - before->tv_usec;

	timeval_update(result);

	return after->tv_sec < before->tv_sec;
}

void timeval_add(struct timeval * result, struct timeval * tv1, struct timeval * tv2)
{
	result->tv_sec = tv1->tv_sec + tv2->tv_sec;
	result->tv_usec = tv1->tv_usec + tv2->tv_usec;

	timeval_update(result);
}