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
#include <assert.h>
#include <netcore-ng/ewma.h>

#define ARRAY_SIZE(X) (sizeof(X) / sizeof((X)[0]))

static const uint64_t samples[] = {
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

uint64_t expected_ewma_calculate(const uint64_t ewma, const uint64_t factor, const uint64_t weight, const uint64_t val)
{
	uint64_t new_avg;

	if (ewma != 0)
		new_avg = (((ewma * weight) - ewma) + (val * factor)) / factor;
	else
		new_avg = val * factor;

	return (new_avg);
}

int main(int argc, char ** argv)
{
	uint64_t weight, factor, a, i;
	uint64_t expected_avg = 0;
	uint64_t result_avg = 0;
	struct ewma avg;
	
	assert(argc);
	assert(argv);
	
	/* factor and weight parameter must be power of two */
	for (a = 0, factor = 1; a < sizeof(factor) * 8 - 1; a++)
	{
		for (i = 0, weight = 1; i < sizeof(weight) * 8 - 1; i++)
		{
			assert(ewma_init(&avg, factor, weight) == 0);
			
			weight <<= 1;
		}
		
		factor <<= 1;
	}
	
	assert(ewma_init(&avg, 24, 32) != 0);
	assert(ewma_init(&avg, 16, 333) != 0);
	assert(ewma_init(&avg, 123, 241) != 0);
	assert(ewma_init(&avg, 0, 32) != 0);
	assert(ewma_init(&avg, 16, 0) != 0);
	assert(ewma_init(&avg, 0, 0) != 0);

	assert(ewma_init(&avg, 1024, 8) == 0);

	for (a = 0; a < ARRAY_SIZE(samples); a++)
	{
		expected_avg = expected_ewma_calculate(expected_avg, 1024, 8, samples[a]);

		ewma_add(&avg, samples[a]);
		result_avg = ewma_read(&avg);
	}

	return(EXIT_SUCCESS);
}

