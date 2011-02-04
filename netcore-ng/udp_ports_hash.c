
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libhashish.h>

#include <netcore-ng/ports_udp.h>
#include <netcore-ng/macros.h>

static hi_handle_t * udp_hash_handle;

void udp_ports_hash_destroy(void)
{
	hi_fini(udp_hash_handle);
}

int udp_ports_hash_init(void)
{
	uint32_t a;
	int rc;

	if ((rc = hi_init_uint16_t(&udp_hash_handle, ARRAY_SIZE(ports_udp))) != 0)
	{
		return (rc);
	}

	for (a = 0; a < ARRAY_SIZE(ports_udp); a++)
	{
		if ((rc = hi_insert_uint16_t(udp_hash_handle, ports_udp[a].id, ports_udp[a].port)) != 0)
		{
			udp_ports_hash_destroy();
			err("Could not create UDP port hash table");
			return (rc);
		}
	}

	return(0);
}

int udp_ports_hash_search(const uint16_t udp, const char ** port_name)
{
	assert(port_name);

	if (hi_get_uint16_t(udp_hash_handle, udp, (void **)port_name) != 0)
	{
		*port_name = port_udp_unknown;
		return (0);
	}

	return (1);
}

