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


#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libhashish.h>

#include <netcore-ng/oui.h>
#include <netcore-ng/macros.h>

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
		err("Could not initialize OUI hash table");
		return (rc);
	}

	for (a = 0; a < ARRAY_SIZE(vendor_db); a++)
	{
		if ((rc = hi_insert_uint32_t(oui_hash_handle, vendor_db[a].id, vendor_db[a].vendor)) != 0)
		{
			oui_hash_destroy();
			err("Could not insert OUI hash table");
			return (rc);
		}
	}

	return(0);
}

int oui_hash_search(const uint32_t oui, const char ** vendor_id)
{
	assert(vendor_id);

	if (hi_get_uint32_t(oui_hash_handle, oui, (void **)vendor_id) != 0)
	{
		*vendor_id = vendor_unknown;
		return (0);
	}

	return (1);
}

