
#ifndef _NET_RX_RING_H_
#define _NET_RX_RING_H_

#include <net/if.h>

#include <netcore-ng/types.h> 
#include <netcore-ng/thread.h> 
#include <netcore-ng/bpf.h> 
#include <netcore-ng/dissector/dissector_generic.h> 

/* Function signatures */
/* a rx ring must only belong to one entity */
struct netsniff_ng_rx_nic_context
{
	/* Structure which describe a nic instead? */
	char 					rx_dev[IFNAMSIZ];
	/* Maybe multiple ring buffer for one device */
	uint32_t				flags;
	int					dev_fd;
	int 					pcap_fd;
	struct sock_fprog 			bpf;
	struct ring_buff			nic_rb;
};

struct netsniff_ng_rx_thread_context
{
	struct netsniff_ng_thread_context	thread_ctx;
	struct netsniff_ng_rx_nic_context	nic_ctx;
};

/* Function signatures */
extern struct netsniff_ng_rx_thread_context * rx_thread_create(const cpu_set_t run_on, const int sched_prio, const int sched_policy, const char * const rx_dev, const char * const bpf_path, const char * const pcap_path, const enum display_type dtype);
extern void rx_thread_destroy(struct netsniff_ng_rx_thread_context * thread_config);


#define DEFAULT_RX_RING_SILENT_MESSAGE "Receive ring dumping ... |"

#endif				/* _NET_RX_RING_H_ */
