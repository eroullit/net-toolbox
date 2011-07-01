/**
 * \file test_ewma.c
 * \author written by Emmanuel Roullit emmanuel@netsniff-ng.org (c) 2009-2011
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

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <errno.h>
#include <time.h>

#include <netcore-ng/ewma.h>

#define ARRAY_SIZE(X) (sizeof(X) / sizeof((X)[0]))

/**
 * \brief Calculate expected new Exponentially Weighted Moving Average (EWMA)
 * \param[in] ewma Previous upscaled EWMA value
 * \param[in] factor Upscale factor
 * \param[in] weight Depth of memory of the EWMA
 * \param[in] val Value to add to EWMA
 * \return new upscaled EWMA value
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
 * The factor parameter is here to upscale all the samples to avoid loss of
 * precision on small values.
 * Result EWMA needs then to be divided by factor before being interpreted.
 *
 * Resource:\n
 * NIST/SEMATECH e-Handbook of Statistical Methods. 2011.
 * Chap.6.3.2.4 EWMA Control Charts
 * http://www.itl.nist.gov/div898/handbook/
 */

static uint64_t expected_ewma_calculate(const uint64_t ewma, const uint64_t factor, const uint64_t weight, const uint64_t val)
{
	uint64_t new_avg;

	if (ewma != 0)
		new_avg = (((ewma * weight) - ewma) + (val * factor)) / weight;
	else
		new_avg = val * factor;

	return (new_avg);
}

static void valid_init_test(void)
{
	struct ewma avg;
	uint64_t weight, factor, a, i;
	
	/* factor and weight parameter must be power of two.
	 * This is a limitation of the ewma* functions.
	 */

	for (a = 0, factor = 1; a < sizeof(factor) * 8 - 1; a++)
	{
		for (i = 0, weight = 1; i < sizeof(weight) * 8 - 1; i++)
		{
			assert(ewma_init(&avg, factor, weight) == 0);
			
			weight <<= 1;
		}
		
		factor <<= 1;
	}
}

static void invalid_init_test(void)
{
	struct ewma avg;

	/* factor and weight parameter must be power of two.
	 * This is a limitation of the ewma* functions.
	 */

	assert(ewma_init(&avg, 24, 32) != 0);
	assert(ewma_init(&avg, 16, 333) != 0);
	assert(ewma_init(&avg, 123, 241) != 0);
	assert(ewma_init(&avg, 0, 32) != 0);
	assert(ewma_init(&avg, 16, 0) != 0);
	assert(ewma_init(&avg, 0, 0) != 0);
}

static int ewma_test(const uint64_t * const samples, const size_t samples_nr, const uint64_t factor, const uint64_t weight)
{
	uint64_t expected_avg = 0;
	uint64_t result_avg = 0;
	struct ewma avg;
	size_t a;

	assert(samples != NULL);
	assert(samples_nr > 0);
	assert(ewma_init(&avg, factor, weight) == 0);

	for (a = 0; a < samples_nr; a++)
	{
		expected_avg = expected_ewma_calculate(expected_avg, factor, weight, samples[a]);

		ewma_add(&avg, samples[a]);
		result_avg = ewma_read(&avg);

		if((expected_avg / factor) != result_avg)
		{
			printf("On sample %zu: factor:%"PRIu64" weight:%"PRIu64" EWMA expected %"PRIu64" result %"PRIu64"\n", a, factor, weight, expected_avg/factor, result_avg);
			return EINVAL;
		}
	}

	return 0;
}

static int known_sample_test(void)
{
	static const uint64_t known_samples[] = {
		1476, 1482, 1488, 1483, 1523,
		1495, 1491, 1509, 1499, 1513,
		1450, 1505, 1509, 1472, 1497,
		1491, 1487, 1546, 1501, 1499,
		1473, 1536, 1487, 1491, 1525,
		1509, 1519, 1507, 1530, 1498,
		1534, 1539, 1482, 1532, 1523,
		1480, 1494, 1515, 1469, 1493,
		1467, 1508, 1488, 1514, 1478,
		1527, 1461, 1500, 1484, 1494,
		1534, 1484, 1532, 1481, 1517,
		1484, 1500, 1513, 1468, 1491,
		1540, 1503, 1505, 1503, 1518,
		1450, 1477, 1522, 1470, 1480,
		1481, 1501, 1465, 1513, 1512,
		1482, 1501, 1482, 1483, 1500,
		1489, 1490, 1460, 1440, 1488,
		1490, 1529, 1514, 1520, 1470,
		1477, 1460, 1445, 1478, 1491,
		1480, 1458, 1469, 1502, 1485
	};

	uint64_t weight, factor, a, i;
	int rc = 0;

	for (a = 0, factor = 1; a < sizeof(factor) * 8 - 1; a++)
	{
		for (i = 0, weight = 1; i < sizeof(weight) * 8 - 1; i++)
		{
			rc = ewma_test(known_samples, ARRAY_SIZE(known_samples), factor, weight);

			if (rc)
				break;

			weight <<= 1;
		}

		factor <<= 1;
	}

	return rc;
}

static int random_sample_test(const size_t samples_nr)
{
	uint64_t * random_samples = NULL;
	uint64_t weight, factor, a, i;
	int rc = 0;

	assert(samples_nr > 0);

	random_samples = calloc(samples_nr, sizeof(*random_samples));

	if (!random_samples)
		return ENOMEM;

	for (a = 0; a < samples_nr; a++)
	{
		random_samples[a] = abs(rand());
	}

	for (a = 0, factor = 1; a < sizeof(factor) * 8 - 1; a++)
	{
		for (i = 0, weight = 1; i < sizeof(weight) * 8 - 1; i++)
		{
			rc = ewma_test(random_samples, samples_nr, factor, weight);

			if (rc)
				break;

			weight <<= 1;
		}

		factor <<= 1;
	}

	free(random_samples);

	return rc;
}

int main(int argc, char ** argv)
{
	assert(argc);
	assert(argv);

	srand(time(NULL));

	valid_init_test();
	invalid_init_test();

	known_sample_test();

	random_sample_test(100000);

	return(EXIT_SUCCESS);
}
