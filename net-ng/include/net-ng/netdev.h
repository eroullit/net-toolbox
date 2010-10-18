/*
 * Copyright (C) 2009, 2010  Daniel Borkmann <daniel@netsniff-ng.org> and 
 *                           Emmanuel Roullit <emmanuel@netsniff-ng.org>
 *
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or (at 
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 */

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
void inject_kernel_bpf(int sock, struct sock_fprog *bpf);
extern void reset_kernel_bpf(int sock);
extern int ethdev_to_ifindex(const char *dev);
extern void net_stat(int sock);
extern int get_pf_socket(void);
extern int get_mtu(const char *dev);
extern int is_device_ready(const char * dev);
extern int get_af_socket(int af);
extern int get_pf_socket(void);

#endif				/* _NET_NETDEV_H_ */
