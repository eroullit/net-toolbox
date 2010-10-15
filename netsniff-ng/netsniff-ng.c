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

#define	_GNU_SOURCE

/* XXX Only temporary here */
#include <sched.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <signal.h>

#include <net-ng/types.h>
#include <net-ng/rx_ring.h>
#include <net-ng/rx_ring_compat.h>
#include <net-ng/tx_ring.h>
#include <net-ng/netdev.h>
#include <netsniff-ng/config.h>
#include <netsniff-ng/system.h>

/* XXX HACK this is unused */
volatile sig_atomic_t sigint = 0;

void start_single_rx_thread(struct system_data * sd)
{
	cpu_set_t cpu_bitmask;
	short nic_flags;
	union
	{
		struct netsniff_ng_rx_thread_context * 		rx;
		struct netsniff_ng_rx_thread_compat_context * 	rx_compat;
	}thread_ctx;
	
	if (sd->cpu_set_str)
	{
		if (parse_cpu_set(sd->cpu_set_str, &cpu_bitmask))
		{
			err("Cpu set string is malformed\n");
			exit(EXIT_FAILURE);
		}
	}
	else
	{
		/* When no CPU affinity is specified take it from the parent process */
		sched_getaffinity(getpid(), sizeof(cpu_bitmask), &cpu_bitmask);
	}

	nic_flags = get_nic_flags(sd->dev);
	/* Put device in promisc mode */
	set_nic_flags(sd->dev, nic_flags | IFF_PROMISC);

	switch(sd->mode)
	{
		case RX_THREAD:
			thread_ctx.rx = create_rx_thread(cpu_bitmask, 0, SCHED_FIFO, sd->dev, sd->bpf_path, sd->pcap_path);

			if (thread_ctx.rx == NULL)
				goto out;
		break;

		case RX_THREAD_COMPAT:
			thread_ctx.rx_compat = create_rx_thread_compat(cpu_bitmask, 0, SCHED_FIFO, sd->dev, sd->bpf_path, sd->pcap_path);
			
			if (thread_ctx.rx_compat == NULL)
				goto out;
		break;

		default:
			err("This mode is not supported yet\n");
		break;
	}

	getchar();

	switch(sd->mode)
	{
		case RX_THREAD:
			pthread_cancel(thread_ctx.rx->thread_ctx.thread);
			net_stat(thread_ctx.rx->nic_ctx.dev_fd);
			destroy_rx_thread(thread_ctx.rx);
		break;

		case RX_THREAD_COMPAT:
			pthread_cancel(thread_ctx.rx_compat->thread_ctx.thread);
			destroy_rx_thread_compat(thread_ctx.rx_compat);
		break;

		default:
			err("This mode is not supported yet\n");
		break;
	}
	
out:
	/* Restore previous NIC mode */
	set_nic_flags(sd->dev, nic_flags);
}



/**
 * main  - Main routine
 * @argc: number of args
 * @argv: arguments passed from tty
 */
int main(int argc, char **argv)
{
	struct system_data sd = { 0 };
	
	init_configuration(&sd);
	set_configuration(argc, argv, &sd);
	check_config(&sd);
	start_single_rx_thread(&sd);
	clean_config(&sd);

	return 0;
}
