
#ifndef _NET_TX_RING_H_
#define _NET_TX_RING_H_

#include <stdlib.h>
#include <assert.h>
#include <net/if.h>
#include <sys/queue.h>

#include <netcore-ng/macros.h>
#include <netcore-ng/types.h>
#include <netcore-ng/thread.h>
#include <netcore-ng/rxtx_common.h>

/* Function signatures */
/* a tx ring must only belong to one entity */
struct netsniff_ng_tx_nic_context
{
	struct pollfd 				pfd;
	/* Structure which describe a nic instead? */
	char 					tx_dev[IFNAMSIZ];
	/* Maybe multiple ring buffer for one device */
	uint32_t				flags;
	int					dev_fd;
	int 					pcap_fd;
	struct sock_fprog 			bpf;
	struct ring_buff			nic_rb;
};

struct netsniff_ng_tx_thread_context
{
	struct netsniff_ng_thread_context	thread_ctx;
	struct netsniff_ng_tx_nic_context	nic_ctx;
};

/* Function signatures */
extern struct netsniff_ng_tx_thread_context * create_tx_thread(const cpu_set_t run_on, const int sched_prio, const int sched_policy, const char * tx_dev, const char * bpf_path, const char * pcap_path);
extern void destroy_tx_thread(struct netsniff_ng_tx_thread_context * thread_config);


#define DEFAULT_TX_RING_SILENT_MESSAGE "Transmitting ... |"

#endif				/* _NET_TX_RING_H_ */
