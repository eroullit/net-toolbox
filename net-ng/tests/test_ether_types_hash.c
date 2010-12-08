#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <net-ng/macros.h>
#include <net-ng/ether_types.h>

int match_ether_types_array(const uint32_t key, const char ** port)
{
	int ret = 0;
	uint32_t a;

	for (a = 0; a < ARRAY_SIZE(ether_types); a++)
	{
		if (key == ether_types[a].id)
		{
			*port = ether_types[a].type;
			ret++;
			break;
		}
	}

	return (ret);
}

int main (void)
{
	const char * type_array = NULL;
	const char * type_hash = NULL;
	uint32_t key;
	
	assert(ether_types_hash_init() == 0);

	/* XXX Can speed up the test by only testing used ports */
	for (key = 0; key < ether_types[ARRAY_SIZE(ether_types) - 1].id; key++)
	{
		if (match_ether_types_array(key, &type_array))
		{
			if (ether_types_hash_search(key, &type_hash))
			{
				info("Testing Ethertype %x. Expected %s got %s\n", key, type_array, type_hash);
				assert (strcmp(type_array, type_hash) == 0);
			}
		}
	}

	ether_types_hash_destroy();

	return (EXIT_SUCCESS);
}
