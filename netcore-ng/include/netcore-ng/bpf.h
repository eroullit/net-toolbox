
#ifndef _NET_BPF_H_
#define _NET_BPF_H_

#include <stdint.h>
#include <linux/filter.h>

extern void bpf_dump_all(const struct sock_fprog * const bpf);
extern int bpf_is_valid(const struct sock_fprog * const bpf);
extern uint32_t bpf_filter(const struct sock_fprog * const bpf, uint8_t * packet, size_t plen);
extern int bpf_parse(const char * const bpf_path, struct sock_fprog *bpf);

#endif				/* _NET_BPF_H_ */
