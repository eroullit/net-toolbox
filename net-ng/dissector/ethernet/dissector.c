#include <assert.h>
#include <net-ng/dissector/ethernet/dissector.h>

static hi_handle_t * ethernet_dissector_hash;

int ethernet_dissector_insert(const uint16_t key, const struct protocol_dissector * const dis)
{
	assert(dis);

	if (hi_insert_uint16_t(ethernet_dissector_hash, key, dis) != 0)
	{
		return (0);
	}

	return (1);
}

int ethernet_dissector_run(uint8_t * pkt, size_t len)
{
	size_t off;
	uint16_t key;
	struct protocol_dissector * dis = NULL;

	assert(pkt);
	assert(len);

	for (key = 0, off = 0; hi_get_uint16_t(ethernet_dissector_hash, key, (void **)dis) == 0; key = dis->get_next_key(pkt, len), off = dis->get_offset(pkt, len))
	{
		len -= off;
		pkt += off;

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

	return (0);
error:
	ethernet_dissector_destroy();
	return (rc);
}

