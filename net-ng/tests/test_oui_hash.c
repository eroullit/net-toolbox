#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <net-ng/macros.h>
#include <net-ng/oui.h>

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
	int ret;
	
	if ((ret = oui_hash_init()) != 0)
	{
		warn("Could not initialize OUI hash table: %i\n", ret);
		return (EXIT_FAILURE);
	}

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
