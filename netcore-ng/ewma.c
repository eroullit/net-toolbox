/**
 * \file ewma.c
 * \author written by Bruno Randolf <br1@einfach.org> (c)
 * \date 2011
 */

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

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <netcore-ng/ewma.h>

/**
 * DOC: Exponentially Weighted Moving Average (EWMA)
 *
 * These are generic functions for calculating Exponentially Weighted Moving
 * Averages (EWMA). We keep a structure with the EWMA parameters and a scaled
 * up internal representation of the average value to prevent rounding errors.
 * The factor for scaling up and the exponential weight (or decay rate) have to
 * be specified thru the init fuction. The structure should not be accessed
 * directly but only thru the helper functions.
 */

/**
 * \brief Tell if a integer is a power of 2
 * \param[in] n Integer to test
 * \return 1 if true, 0 otherwise
 */

static inline int is_power_of_2 (uint64_t n)
{
	return (n != 0 && ((n & (n - 1)) == 0));
}

/**
 * \brief Initialize EWMA parameters
 * \param[in,out] avg Average structure
 * \param[in] factor Factor to use for the scaled up internal value. 
 *	The maximum value of averages can be ULONG_MAX/(factor*weight).
 *	For performance reasons factor has to be a power of 2.
 * \param[in] weight Exponential weight, or decay rate.
 *	This defines how fast the influence of older values decreases.
 *	For performance reasons weight has to be a power of 2.
 */

int ewma_init(struct ewma *avg, const uint64_t factor, const uint64_t weight)
{
	assert(avg);

	memset(avg, 0, sizeof(*avg));

	if (!is_power_of_2(weight) || !is_power_of_2(factor))
		return EINVAL;

	avg->weight = log2(weight);
	avg->factor = log2(factor);
	avg->internal = 0;

	return 0;
}

/**
 * \brief Exponentially weighted moving average (EWMA)
 * \param[in,out] avg Average structure
 * \param[in] val Current value
 */
struct ewma *ewma_add(struct ewma *avg, uint64_t val)
{
	avg->internal = avg->internal  ?
		(((avg->internal << avg->weight) - avg->internal) +
			(val << avg->factor)) >> avg->weight :
		(val << avg->factor);
	
	return avg;
}