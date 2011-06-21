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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <netcore-ng/time.h>

int test_time_add(const long t1_sec, const long t1_usec,
			const long t2_sec, const long t2_usec,
			const long expected_sec, const long expected_usec)
{
	struct timeval t1, t2, expected, result;

	t1.tv_sec = t1_sec;
	t1.tv_usec = t1_usec;

	t2.tv_sec = t2_sec;
	t2.tv_usec = t2_usec;

	expected.tv_sec = expected_sec;
	expected.tv_usec = expected_usec;

	timeval_add(&result, &t1, &t2);

	return(memcmp(&result, &expected, sizeof(result)) == 0);
}

int test_time_subtract(const long before_sec, const long before_usec,
			const long after_sec, const long after_usec,
			const long expected_sec, const long expected_usec)
{
	struct timeval before, after, expected, diff;

	before.tv_sec = before_sec;
	before.tv_usec = before_usec;

	after.tv_sec = after_sec;
	after.tv_usec = after_usec;

	expected.tv_sec = expected_sec;
	expected.tv_usec = expected_usec;

	timeval_subtract(&diff, &after, &before);

	return(memcmp(&diff, &expected, sizeof(diff)) == 0);
}

int main(int argc, char ** argv)
{
	assert(argc);
	assert(argv);

	/* Perform operation on classic timestamps */
	assert(test_time_add(1167778800, 233478, 140871091, 26394, 1308649891, 259872));
	assert(test_time_subtract(1167778800, 233478, 1308649891, 259872, 140871091, 26394));

	/* Perform operation on timestamps with carry */
	assert(test_time_add(1167778800, 233478, 140871091, 965881, 1308649892, 199359));
	assert(test_time_add(1167778800, 200000, 140871091, 800000, 1308649892, 0));
	assert(test_time_subtract(1167778800, 233478, 1308649892, 199359, 140871091, 965881));
	assert(test_time_subtract(1167778800, 200000, 1308649892, 0, 140871091, 800000));

	/* Perform operations on negative timestamp */
	assert(test_time_add(-1167778800, -233478, -140871091, -965881, -1308649892, -199359));
	assert(test_time_add(-1167778800, -200000, -140871091, -800000, -1308649892, 0));
	assert(test_time_subtract(-1308649892, -199359, -1167778800, -233478, 140871091, 965881));
	assert(test_time_subtract(-1308649892, 0, -1167778800, -200000, 140871091, 800000));

	return(EXIT_SUCCESS);
}
