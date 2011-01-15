#ifndef	__DISSECTOR_ICMP_H__
#define	__DISSECTOR_ICMP_H__

#include <netcore-ng/dissector/ethernet/dissector.h>

int dissector_icmp_insert(void);
int dissector_icmp_print_set(const enum display_type);

#endif	/* __DISSECTOR_ICMP_H__ */
