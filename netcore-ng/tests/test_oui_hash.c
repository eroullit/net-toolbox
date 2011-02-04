/* __LICENSE_HEADER_BEGIN__ */

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
 *
 */

 /* __LICENSE_HEADER_END__ */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <netcore-ng/macros.h>
#include <netcore-ng/oui.h>

int match_oui_array(const uint32_t key, const char ** vendor)
{
	int ret = 0;
	uint32_t a;

	for (a = 0; a < ARRAY_SIZE(vendor_db); a++)
	{
		if (key == vendor_db[a].id)
		{
			*vendor = vendor_db[a].vendor;
			ret++;
			break;
		}
	}

	return (ret);
}

int main (void)
{
	const char * vendor_array = NULL;
	const char * vendor_hash = NULL;
	uint32_t key;
	
	assert(oui_hash_init() == 0);

	/* XXX Can speed up the test by only testing used OUI */
	for (key = 0; key < vendor_db[ARRAY_SIZE(vendor_db) - 1].id; key++)
	{
		if (match_oui_array(key, &vendor_array))
		{
			if (oui_hash_search(key, &vendor_hash))
			{
				info("Testing OUI 0x%X. Expected vendor %s got %s\n", key, vendor_array, vendor_hash);
				assert(strcmp(vendor_array, vendor_hash) == 0);
			}
		}
	}

	oui_hash_destroy();

	return (EXIT_SUCCESS);
}
