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

#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libhashish.h>

#include <net-ng/ether_types.h>
#include <net-ng/macros.h>

static hi_handle_t * ether_types_hash_handle;

void ether_types_hash_destroy(void)
{
	hi_fini(ether_types_hash_handle);
}

int ether_types_hash_init(void)
{
	uint32_t a;
	int rc;

	if ((rc = hi_init_uint16_t(&ether_types_hash_handle, ARRAY_SIZE(ether_types))) != 0)
	{
		return (rc);
	}

	for (a = 0; a < ARRAY_SIZE(ether_types); a++)
	{
		if ((rc = hi_insert_uint32_t(ether_types_hash_handle, ether_types[a].id, ether_types[a].type)) != 0)
		{
			ether_types_hash_destroy();
			err("Could not create ethernet types hash table");
			return (rc);
		}
	}

	return(0);
}

const char * ether_types_hash_search(const uint16_t ether_type)
{
	const char * ether_type_name = NULL;

	if (hi_get_uint16_t(ether_types_hash_handle, ether_type, (void **)&ether_type_name) != 0)
	{
		ether_type_name = type_unknown;
	}

	return (ether_type_name);
}

