#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netcore-ng/netdev.h>

int main (void)
{
	int sock = get_af_socket(AF_INET);

	assert(sock > 0);
	
	close(sock);
	return (EXIT_SUCCESS);
}
