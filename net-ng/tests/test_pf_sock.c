#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>
#include <net-ng/netdev.h>

int main (void)
{
	int sock = get_pf_socket();

	assert(sock > 0);
	
	close(sock);
	return (EXIT_SUCCESS);
}
