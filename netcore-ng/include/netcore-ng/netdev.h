
#ifndef _NET_NETDEV_H_
#define _NET_NETDEV_H_

#include <stdint.h>
#include <netinet/ip6.h>
#include <linux/filter.h>

struct in6_ifreq {
	struct in6_addr ifr6_addr;
	uint32_t ifr6_prefixlen;
	int ifr6_ifindex;
};

#define FAILSAFE_BITRATE	100	/* 100 Mbits (Chosen arbitrary) */
#define MAX_NUMBER_OF_NICS	15

/* Function signatures */

extern int get_device_bitrate_generic(const char *ifname);
extern int get_device_bitrate_generic_cable(const char *ifname);
extern int get_nic_irq_number(const char *dev);
extern int bind_nic_interrupts_to_cpu(int intr, int cpu);
extern short get_nic_flags(const char *dev);
extern void set_nic_flags(const char *dev, const short flag_to_set);
extern void unset_nic_flags(const char *dev, const short flag_to_set);
extern void print_device_info(void);
extern void put_dev_into_promisc_mode(const char *dev);
void bpf_kernel_inject(int sock, struct sock_fprog *bpf);
extern void bpf_kernel_reset(int sock);
extern int ethdev_to_ifindex(const char *dev);
extern void net_stat(int sock);
extern int get_pf_socket(void);
extern int get_mtu(const char *dev);
extern int is_device_ready(const char * dev);
extern int get_af_socket(int af);
extern int get_pf_socket(void);

#endif				/* _NET_NETDEV_H_ */
