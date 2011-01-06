#ifndef	__ETHERNET_DISSECTOR_H__
#define	__ETHERNET_DISSECTOR_H__

#include <libhashish.h>

#include <netcore-ng/ether_types.h>
#include <netcore-ng/oui.h>
#include <netcore-ng/ports_tcp.h>
#include <netcore-ng/ports_udp.h>

#include <netcore-ng/dissector/dissector_generic.h>
#include <netcore-ng/dissector/ethernet/ethernet.h>
#include <netcore-ng/dissector/ethernet/arp.h>

int ethernet_dissector_insert(const uint16_t key, const struct protocol_dissector * const dis);
int ethernet_dissector_run(uint8_t * pkt, size_t len);
int ethernet_dissector_init(void);
void ethernet_dissector_destroy(void);

#endif	/* __ETHERNET_DISSECTOR_H__ */
