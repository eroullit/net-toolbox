
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libhashish.h>

#include <netcore-ng/oui.h>
#include <netcore-ng/macros.h>

static hi_handle_t * oui_hash_handle;

void oui_hash_destroy(void)
{
	hi_fini(oui_hash_handle);
}

int oui_hash_init(void)
{
	uint32_t a;
	int rc;

	if ((rc = hi_init_uint32_t(&oui_hash_handle, ARRAY_SIZE(vendor_db))) != 0)
	{
		err("Could not initialize OUI hash table");
		return (rc);
	}

	for (a = 0; a < ARRAY_SIZE(vendor_db); a++)
	{
		if ((rc = hi_insert_uint32_t(oui_hash_handle, vendor_db[a].id, vendor_db[a].vendor)) != 0)
		{
			oui_hash_destroy();
			err("Could not insert OUI hash table");
			return (rc);
		}
	}

	return(0);
}

int oui_hash_search(const uint32_t oui, const char ** vendor_id)
{
	assert(vendor_id);

	if (hi_get_uint32_t(oui_hash_handle, oui, (void **)vendor_id) != 0)
	{
		*vendor_id = vendor_unknown;
		return (0);
	}

	return (1);
}

