#ifndef	__ETHERNET_DISSECTOR_H__
#define	__ETHERNET_DISSECTOR_H__

#include <libhashish.h>

#include <net-ng/ether_types.h>
#include <net-ng/oui.h>
#include <net-ng/ports_tcp.h>
#include <net-ng/ports_udp.h>

#include <net-ng/dissector/dissector_generic.h>
#include <net-ng/dissector/ethernet/ethernet.h>

int ethernet_dissector_insert(const uint16_t key, const struct protocol_dissector * const dis);
int ethernet_dissector_run(uint8_t * pkt, size_t len);
int ethernet_dissector_init(void);

#endif	/* __ETHERNET_DISSECTOR_H__ */
