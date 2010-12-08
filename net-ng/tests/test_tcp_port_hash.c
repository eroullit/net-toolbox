#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <net-ng/macros.h>
#include <net-ng/ports_tcp.h>

int match_tcp_ports_array(const uint32_t key, const char ** port)
{
	int ret = 0;
	uint32_t a;

	for (a = 0; a < ARRAY_SIZE(ports_tcp); a++)
	{
		if (key == ports_tcp[a].id)
		{
			*port = ports_tcp[a].port;
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
	
	assert(tcp_ports_hash_init() == 0);

	/* XXX Can speed up the test by only testing used ports */
	for (key = 0; key < ports_tcp[ARRAY_SIZE(ports_tcp) - 1].id; key++)
	{
		if (match_tcp_ports_array(key, &port_array))
		{
			if (tcp_ports_hash_search(key, &port_hash))
			{
				info("Testing TCP port %x. Expected %s got %s\n", key, port_array, port_hash);
				assert (strcmp(port_array, port_hash) == 0);
			}
		}
	}

	tcp_ports_hash_destroy();

	return (EXIT_SUCCESS);
}
