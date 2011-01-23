#ifndef	__DISSECTOR_RAW_H__
#define	__DISSECTOR_RAW_H__

#include <netcore-ng/dissector/dissector_generic.h>

#define RAW_DEFAULT_KEY	0xFFFF
#define RAW_CHUNK	10

int dissector_raw_insert(int (*dissector_insert)(const struct protocol_dissector * const dis));
int dissector_raw_print_set(const enum display_type);

#endif	/* __DISSECTOR_RAW_H__ */
