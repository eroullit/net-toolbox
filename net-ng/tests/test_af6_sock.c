#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>
#include <net-ng/netdev.h>

int main (void)
{
	int sock = get_af_socket(AF_INET6);

	assert(sock > 0);
	
	close(sock);
	return (EXIT_SUCCESS);
}
