
#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/time.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>

#include <netcore-ng/bpf.h>
#include <netcore-ng/cursor.h>
#include <netcore-ng/pcap.h>
#include <netcore-ng/macros.h>
#include <netcore-ng/types.h>
#include <netcore-ng/rx_ring_compat.h>
#include <netcore-ng/netdev.h>
#include <netcore-ng/xmalloc.h>
#include <netcore-ng/strlcpy.h>

static int sock_dev_bind(const char * dev, int sock)
{
	struct sockaddr saddr;
        int rc;

	memset(&saddr, 0, sizeof(saddr));
        strlcpy(saddr.sa_data, dev, sizeof(saddr.sa_data));

        rc = bind(sock, &saddr, sizeof(saddr));

        if (rc == -1) {
                err("bind() failed");
                return (rc);
        }

        return (0);
}

void * rx_thread_compat_listen(void * arg)
{
	struct netsniff_ng_rx_thread_compat_context * thread_ctx = (struct netsniff_ng_rx_thread_compat_context *) arg;
	struct netsniff_ng_rx_nic_compat_context * nic_ctx = NULL;
	struct timeval          now;
	struct sockaddr_ll      from;
	struct tpacket_hdr 	tp_h;
        socklen_t               from_len = sizeof(from);
	ssize_t pkt_len;

	if (thread_ctx == NULL)
	{
		pthread_exit(NULL);
	}

	memset(&from, 0, sizeof(from));
	memset(&tp_h, 0, sizeof(tp_h));

	nic_ctx = &thread_ctx->nic_ctx;

	info("--- Listening (Compatibility mode)---\n\n");

	for(;;)
	{
		pkt_len = recvfrom(nic_ctx->dev_fd, nic_ctx->pkt_buf, nic_ctx->pkt_buf_len, MSG_TRUNC, (struct sockaddr *) &from, &from_len);

		if (errno == EINTR)
                        break;

		gettimeofday(&now, NULL);

                tp_h.tp_sec = now.tv_sec;
                tp_h.tp_usec = now.tv_usec;
                tp_h.tp_len = tp_h.tp_snaplen = pkt_len;

		if (nic_ctx->pcap_fd > 0)
		{
			pcap_write_payload(nic_ctx->pcap_fd, &tp_h, (struct ethhdr *) nic_ctx->pkt_buf);
		}
	}

	pthread_exit(NULL);
}

void rx_nic_compat_ctx_destroy(struct netsniff_ng_rx_nic_compat_context * nic_ctx)
{
	assert(nic_ctx);
	
	if (nic_ctx->bpf.filter)
	{
		bpf_kernel_reset(nic_ctx->dev_fd);
		free(nic_ctx->bpf.filter);
	}

	if (nic_ctx->pkt_buf)
		xfree(nic_ctx->pkt_buf);

	close(nic_ctx->dev_fd);
	close(nic_ctx->pcap_fd);
}

int rx_nic_compat_ctx_init(struct netsniff_ng_rx_thread_compat_context * thread_ctx, const char * rx_dev, const char * bpf_path, const char * pcap_path)
{
	struct netsniff_ng_rx_nic_compat_context * nic_ctx = NULL;
	int rc;

	assert(thread_ctx);
	assert(rx_dev);

	nic_ctx = &thread_ctx->nic_ctx;

	if (!is_device_ready(rx_dev))
	{
		warn("Device %s is not ready\n", rx_dev);
		return (EAGAIN);
	}

	strlcpy(nic_ctx->rx_dev, rx_dev, IFNAMSIZ);
	nic_ctx->pkt_buf_len = get_mtu(nic_ctx->rx_dev);

	nic_ctx->pkt_buf = xzmalloc(nic_ctx->pkt_buf_len);

	if ((nic_ctx->dev_fd = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0)
	{
		warn("Could not open socket for %s\n", nic_ctx->rx_dev);
		rc = EPERM;
		goto error;
	}

	if (sock_dev_bind(rx_dev, nic_ctx->dev_fd))
	{
		warn("Could not dev %s to socket\n", nic_ctx->rx_dev);
		rc = EAGAIN;
		goto error;
	}

	if (bpf_path)
	{
		if(bpf_parse(bpf_path, &nic_ctx->bpf) == 0)
		{
			warn("Could not parse BPF file %s\n", bpf_path);
			rc = EINVAL;
			goto error;
		}

		bpf_kernel_inject(nic_ctx->dev_fd, &nic_ctx->bpf);
	}

	if (pcap_path)
	{
		if ((nic_ctx->pcap_fd = pcap_create(pcap_path)) < 0)
		{
			warn("Failed to prepare pcap : %s\n", pcap_path);
			rc = EINVAL;
			goto error;
		}
	}

	return(0);
error:
	rx_nic_compat_ctx_destroy(nic_ctx);
	return(rc);
}

void rx_thread_compat_destroy(struct netsniff_ng_rx_thread_compat_context * thread_config)
{
	assert(thread_config);

	if (thread_config->thread_ctx.thread)
		pthread_cancel(thread_config->thread_ctx.thread);
	
	thread_context_destroy(&thread_config->thread_ctx);
	rx_nic_compat_ctx_destroy(&thread_config->nic_ctx);
	xfree(thread_config);
}

struct netsniff_ng_rx_thread_compat_context * rx_thread_compat_create(const cpu_set_t run_on, const int sched_prio, const int sched_policy, const char * rx_dev, const char * bpf_path, const char * pcap_path)
{
	int rc;
	struct netsniff_ng_rx_thread_compat_context * thread_config = NULL;

	thread_config = xzmalloc(sizeof(*thread_config));

	memset(thread_config, 0, sizeof(*thread_config));

	if ((rc = thread_context_init(&thread_config->thread_ctx, run_on, sched_prio, sched_policy, RX_THREAD_COMPAT)) != 0)
	{
		warn("Cannot initialize thread\n");
		goto error;
	}

	if ((rc = rx_nic_compat_ctx_init(thread_config, rx_dev, bpf_path, pcap_path)) != 0)
	{
		warn("Cannot initialize RX NIC context\n");
		goto error;
	}

	pthread_create(&thread_config->thread_ctx.thread, &thread_config->thread_ctx.thread_attr, rx_thread_compat_listen, thread_config);

	return (thread_config);
error:
	rx_thread_compat_destroy(thread_config);
	return (NULL);
}

