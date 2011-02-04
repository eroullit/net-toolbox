
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
