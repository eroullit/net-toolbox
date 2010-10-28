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

#include <net-ng/oui.h>
#include <net-ng/macros.h>

static hi_handle_t * oui_hash_handle;

void oui_hash_destroy(void)
{
	hi_fini(oui_hash_handle);
}

int oui_hash_init(void)
{
	uint32_t a;
	int rc;

	if ((rc = hi_init_uint32_t(&oui_hash_handle, ARRAY_SIZE(vendor_db))) != 0)
	{
		return (rc);
	}

	for (a = 0; a < ARRAY_SIZE(vendor_db); a++)
	{
		if ((rc = hi_insert_uint32_t(oui_hash_handle, vendor_db[a].id, vendor_db[a].vendor)) != 0)
		{
			oui_hash_destroy();
			err("Could not create OUI hash table");
			return (rc);
		}
	}

	return(0);
}

const char * oui_hash_search(const uint32_t oui)
{
	const char * vendor_id = NULL;

	if (hi_get_uint32_t(oui_hash_handle, oui, (void **)&vendor_id) != 0)
	{
		vendor_id = vendor_unknown;
	}

	return (vendor_id);
}

