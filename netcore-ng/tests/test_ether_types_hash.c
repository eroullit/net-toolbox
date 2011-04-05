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
#include <unistd.h>
#include <assert.h>

#include <netcore-ng/macros.h>
#include <netcore-ng/ether_types.h>

int match_ether_types_array(const uint32_t key, const char ** port)
{
	int ret = 0;
	uint32_t a;

	for (a = 0; a < ARRAY_SIZE(ether_types); a++)
	{
		if (key == ether_types[a].id)
		{
			*port = ether_types[a].type;
			ret++;
			break;
		}
	}

	return (ret);
}

int main (void)
{
	const char * type_array = NULL;
	const char * type_hash = NULL;
	uint32_t key;
	
	assert(ether_types_hash_init() == 0);

	/* XXX Can speed up the test by only testing used ports */
	for (key = 0; key < ether_types[ARRAY_SIZE(ether_types) - 1].id; key++)
	{
		if (match_ether_types_array(key, &type_array))
		{
			if (ether_types_hash_search(key, &type_hash))
			{
				info("Testing Ethertype %x. Expected %s got %s\n", key, type_array, type_hash);
				assert (strcmp(type_array, type_hash) == 0);
			}
		}
	}

	ether_types_hash_destroy();

	return (EXIT_SUCCESS);
}
