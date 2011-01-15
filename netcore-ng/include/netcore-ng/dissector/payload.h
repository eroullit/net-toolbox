#ifndef	__DISSECTOR_PAYLOAD_H__
#define	__DISSECTOR_PAYLOAD_H__

#include <netcore-ng/dissector/dissector_generic.h>

#define PAYLOAD_DEFAULT_KEY	0xFFFF

int dissector_payload_insert(int (*dissector_insert)(const uint16_t key, const struct protocol_dissector * const dis));
int dissector_payload_print_set(const enum display_type);

#endif	/* __DISSECTOR_PAYLOAD_H__ */
