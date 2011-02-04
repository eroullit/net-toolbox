
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libhashish.h>

#include <netcore-ng/ports_tcp.h>
#include <netcore-ng/macros.h>

static hi_handle_t * tcp_hash_handle;

void tcp_ports_hash_destroy(void)
{
	hi_fini(tcp_hash_handle);
}

int tcp_ports_hash_init(void)
{
	uint32_t a;
	int rc;

	if ((rc = hi_init_uint16_t(&tcp_hash_handle, ARRAY_SIZE(ports_tcp))) != 0)
	{
		return (rc);
	}

	for (a = 0; a < ARRAY_SIZE(ports_tcp); a++)
	{
		if ((rc = hi_insert_uint16_t(tcp_hash_handle, ports_tcp[a].id, ports_tcp[a].port)) != 0)
		{
			info("Could not insert key %u data %s\n", ports_tcp[a].id, ports_tcp[a].port);
			tcp_ports_hash_destroy();
			err("Could not create TCP port hash table");
			return (rc);
		}
	}

	return(0);
}

int tcp_ports_hash_search(const uint16_t tcp, const char ** port_name)
{
	assert(port_name);

	if (hi_get_uint16_t(tcp_hash_handle, tcp, (void **)port_name) != 0)
	{
		*port_name = port_tcp_unknown;
		return (0);
	}

	return (1);
}

