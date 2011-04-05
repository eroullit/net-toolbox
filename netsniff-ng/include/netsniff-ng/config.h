/* __LICENSE_HEADER_BEGIN__ */

/*
 * Copyright (C) 2009-2011	Emmanuel Roullit <emmanuel@netsniff-ng.org>
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
 *
 */

 /* __LICENSE_HEADER_END__ */


#ifndef	_NET_CONFIG_H_
#define	_NET_CONFIG_H_

#include <netcore-ng/thread.h>
#include <netcore-ng/dissector/dissector_generic.h>

/* Internals */
#define DEFAULT_INTERFACE "lo"
#define INTERVAL_COUNTER_REFR   1000	/* in ms */

#define POLL_WAIT_INF           -1	/* CPU friendly and appropriate for normal usage */
#define POLL_WAIT_NONE           0	/* This will pull CPU usage to 100 % */

#define PROMISC_MODE_NONE        1

#define BPF_BYPASS               1
#define BPF_NO_BYPASS            0

#define PROC_NO_HIGHPRIO         1
#define PROC_NO_TOUCHIRQ         1

#define PCAP_NO_DUMP            -1

#define SYSD_ENABLE              1

#define PACKET_DONT_CARE        -1

#define MODE_CAPTURE             1
#define MODE_REPLAY              2
#define MODE_READ                3

struct system_data {
	/* Some more or less boolean conf values */
	char * bpf_path;
	char * pcap_path;
	char * dev;
	char * cpu_set_str;
	enum display_type dtype;
	enum netsniff_ng_thread_type mode;
};

extern void init_configuration(struct system_data *config);
extern void set_configuration(int argc, char **argv, struct system_data *sd);
extern void check_config(struct system_data *sd);
extern void clean_config(struct system_data *sd);

#endif				/* _NET_CONFIG_H_ */
