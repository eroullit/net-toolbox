#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net-ng/netdev.h>

int main (void)
{
	int rc = EXIT_FAILURE;
	int sock = get_af_socket(AF_INET);

	if (sock > 0)
		rc = EXIT_SUCCESS;
	
	close(sock);
	return (rc);
}
