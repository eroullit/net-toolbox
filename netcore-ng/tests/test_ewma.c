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

int main(int argc, char ** argv)
{
	uint64_t weight, factor, a, i;
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
	
	return(EXIT_SUCCESS);
}

