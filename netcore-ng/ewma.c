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

/**
 * \page ewma Exponentially Weighted Moving Average (EWMA)
 *
 * Exponentially Weighted Moving Averages (EWMA) are manipulated by generic
 * functions. We keep a structure with the EWMA parameters and a scaled
 * up internal representation of the average value to prevent rounding errors.
 * The factor for scaling up and the exponential weight (or decay rate) have to
 * be specified through the init fuction. The structure should not be accessed
 * directly but only through the helper functions.
 *
 * The formula to calculate a new EWMA value can be written as:
 * \f[EWMA_{t} = \lambda value_{t} + (1 - \lambda)EWMA_{t-1}\f]
 * for \f[ t = 1, 2, ..., n\f]
 *
 * Where:
 *	- \f$EWMA_{0}\f$ is the average of historical data
 *	- \f$value_{t}\f$ is the current value
 *	- \f$n\f$ is the number of samples, \f$EWMA_{0}\f$ included
 *	- \f$0 < \lambda \le 1\f$ is the depth of memory of the EWMA
 *
 * To avoid loss of precision due to floating point operations, we set
 * \f$\lambda = 1/weight\f$, therefore the equation can be written:
 * \f[EWMA_{t} = \frac{value_{t}}{weight} + EWMA_{t-1} - \frac{EWMA_{t-1}}{weight}\f]
 *
 * The factor parameter is here to upscale all the samples to avoid rounding
 * errors.
 *
 * For performance reasons, division and multiplication are done via a left or
 * right arithmetic shifts. This restricts the values of \f$factor\f$ and
 * \f$weight\f$ to power of two unsigned intergers.
 *
 * Resource:\n
 * NIST/SEMATECH e-Handbook of Statistical Methods. 2011.
 * Chap.6.3.2.4 EWMA Control Charts
 * http://www.itl.nist.gov/div898/handbook/
 */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <netcore-ng/ewma.h>

/**
 * \brief Tell if a integer is a power of 2
 * \param[in] n Integer to test
 * \return 1 if true, 0 otherwise
 */

static inline int is_power_of_2 (const uint64_t n)
{
	return (n != 0 && ((n & (n - 1)) == 0));
}

/**
 * \brief Initialize EWMA parameters
 * \param[in,out] avg Average structure
 * \param[in] factor Factor to use for the scaled up internal value.
 *	For performance reasons, factor has to be a power of 2.
 * \param[in] weight Exponential weight, or decay rate.
 *	This defines how fast the influence of older values decreases.
 *	For performance reasons weight has to be a power of 2.
 */

int ewma_init(struct ewma * const avg, const uint64_t factor, const uint64_t weight)
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
 * \param[in] avg Average structure
 * \param[in] val Current value
 * \return Updated average structure
 */
struct ewma * ewma_add(struct ewma * const avg, const uint64_t val)
{
	avg->internal = avg->internal  ?
		(((avg->internal << avg->weight) - avg->internal) +
			(val << avg->factor)) >> avg->weight :
		(val << avg->factor);
	
	return avg;
}