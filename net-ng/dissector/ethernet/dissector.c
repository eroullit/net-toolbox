#include <assert.h>
#include <net-ng/macros.h>
#include <net-ng/dissector/ethernet/dissector.h>

static hi_handle_t * ethernet_dissector_hash;

int ethernet_dissector_display_set(const enum display_type dtype)
{
	void *key_ptr = NULL;
	hi_iterator_t * it = NULL;
	struct protocol_dissector * dis = NULL;
	uint32_t keylen = 0;
	int rc;

	if ((rc = hi_iterator_create(ethernet_dissector_hash, &it)) != 0)
	{
		err("Could not create iterator\n");
		return (EAGAIN);
	}

	while (hi_iterator_getnext(it, (void **) &dis, &key_ptr, &keylen) == 0 && dis != NULL)
	{
		dis->display_set(dtype);
	}

	hi_iterator_fini(it);

	return (0);
}

int ethernet_dissector_insert(const uint16_t key, const struct protocol_dissector * const dis)
{
	int rc = 0;
	assert(dis);

	if ((rc = hi_insert_uint16_t(ethernet_dissector_hash, key, dis)) != 0)
	{
		return (rc);
	}

	info("Added dissector %p with key %x\n", (void *)dis, key);

	return (0);
}

int ethernet_dissector_run(uint8_t * pkt, size_t len)
{
	size_t off;
	uint16_t key;
	struct protocol_dissector * dis = NULL;

	assert(pkt);
	assert(len);

	for (key = 0, off = 0; hi_get_uint16_t(ethernet_dissector_hash, key, (void **)&dis) == 0; key = dis->get_next_key(pkt, len), off = dis->get_offset(pkt, len))
	{
		len -= off;
		pkt += off;

		//info("dis %p key %x pkt %p len %zu\n", (void *) dis, key, (void *) pkt, len);
		if (dis->display)
			dis->display(pkt, len);

		if (dis->get_next_key == NULL)
			break;
	}

	return (0);
}

void ethernet_dissector_destroy(void)
{
	oui_hash_destroy();
	ether_types_hash_destroy();
	udp_ports_hash_destroy();
	tcp_ports_hash_destroy();
	hi_fini(ethernet_dissector_hash);
}

int ethernet_dissector_init(void)
{
	int rc = 0;

	if ((rc = tcp_ports_hash_init()) != 0)
	{
		goto error;
	}

	if ((rc = udp_ports_hash_init()) != 0)
	{
		goto error;
	}

	if ((rc = ether_types_hash_init()) != 0)
	{
		goto error;
	}

	if ((rc = oui_hash_init()) != 0)
	{
		goto error;
	}

	if ((rc = hi_init_uint16_t(&ethernet_dissector_hash, DISSECTOR_MAX)) != 0)
	{
		goto error;
	}

	if ((rc = dissector_ethernet_insert()) != 0)
	{
		goto error;
	}

	if ((rc = dissector_arp_insert()) != 0)
	{
		goto error;
	}

	if ((rc = ethernet_dissector_display_set(DISPLAY_NORMAL)) != 0)
	{
		goto error;
	}

	return (0);
error:
	ethernet_dissector_destroy();
	return (rc);
}

