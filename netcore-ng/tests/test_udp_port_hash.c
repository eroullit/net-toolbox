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
#include <netcore-ng/ports_udp.h>

int match_udp_ports_array(const uint32_t key, const char ** port)
{
	int ret = 0;
	uint32_t a;

	for (a = 0; a < ARRAY_SIZE(ports_udp); a++)
	{
		if (key == ports_udp[a].id)
		{
			*port = ports_udp[a].port;
			ret++;
			break;
		}
	}

	return (ret);
}

int main (void)
{
	const char * port_array = NULL;
	const char * port_hash = NULL;
	uint32_t key;
	
	assert(udp_ports_hash_init() == 0);

	/* XXX Can speed up the test by only testing used ports */
	for (key = 0; key < ports_udp[ARRAY_SIZE(ports_udp) - 1].id; key++)
	{
		if (match_udp_ports_array(key, &port_array))
		{
			if (udp_ports_hash_search(key, &port_hash))
			{
				info("Testing UDP port %x. Expected %s got %s\n", key, port_array, port_hash);
				assert (strcmp(port_array, port_hash) == 0);
			}
		}
	}

	udp_ports_hash_destroy();

	return (EXIT_SUCCESS);
}
