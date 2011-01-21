#ifndef	__ETHERNET_DISSECTOR_IP_H__
#define	__ETHERNET_DISSECTOR_IP_H__

#include <netcore-ng/dissector/ethernet/dissector.h>

int dissector_ip_insert(void);
int dissector_ip_print_set(const enum display_type);

#endif	/* __ETHERNET_DISSECTOR_IP_H__ */
