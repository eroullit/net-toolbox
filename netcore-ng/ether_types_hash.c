
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libhashish.h>

#include <netcore-ng/ether_types.h>
#include <netcore-ng/macros.h>

static hi_handle_t * ether_types_hash_handle;

void ether_types_hash_destroy(void)
{
	hi_fini(ether_types_hash_handle);
}

int ether_types_hash_init(void)
{
	uint32_t a;
	int rc;

	if ((rc = hi_init_uint16_t(&ether_types_hash_handle, ARRAY_SIZE(ether_types))) != 0)
	{
		return (rc);
	}

	for (a = 0; a < ARRAY_SIZE(ether_types); a++)
	{
		if ((rc = hi_insert_uint16_t(ether_types_hash_handle, ether_types[a].id, ether_types[a].type)) != 0)
		{
			ether_types_hash_destroy();
			err("Could not create ethernet types hash table");
			return (rc);
		}
	}

	return(0);
}

int ether_types_hash_search(const uint16_t type, const char ** type_name)
{
	assert(type_name);

	if (hi_get_uint16_t(ether_types_hash_handle, type, (void **)type_name) != 0)
	{
		*type_name = type_unknown;
		return (0);
	}

	return (1);
}

