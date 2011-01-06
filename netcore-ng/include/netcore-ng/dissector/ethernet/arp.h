#ifndef	__DISSECTOR_ARP_H__
#define	__DISSECTOR_ARP_H__

#include <netcore-ng/dissector/ethernet/dissector.h>

int dissector_arp_insert(void);
int dissector_arp_print_set(const enum display_type);

#endif	/* __DISSECTOR_ARP_H__ */
