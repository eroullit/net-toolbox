
#ifndef	_NET_THREAD_H_
#define	_NET_THREAD_H_

#include <pthread.h>

enum netsniff_ng_thread_type
{
	RX_THREAD,
	RX_THREAD_COMPAT,
	TX_THREAD,
	SPINNER_THREAD,
};

enum netsniff_ng_thread_status
{
	RUNNING,
	SLEEPING,
	SHOULD_STOP,
	STOPPED,
};

struct netsniff_ng_thread_context
{
	pthread_t			thread;
	pthread_attr_t			thread_attr;
	pthread_mutex_t			wait_mutex;
	pthread_cond_t			wait_cond;
	pthread_spinlock_t		config_lock;
	cpu_set_t			run_on;
	enum netsniff_ng_thread_type 	type;
	enum netsniff_ng_thread_status	status;
};

int thread_context_init(struct netsniff_ng_thread_context * thread_ctx, const cpu_set_t run_on, const int sched_prio, const int sched_policy, const enum netsniff_ng_thread_type thread_type);
void thread_context_destroy(struct netsniff_ng_thread_context * thread_ctx);

enum netsniff_ng_thread_status thread_status_get(struct netsniff_ng_thread_context * thread_ctx);
void thread_status_set(struct netsniff_ng_thread_context * thread_ctx, enum netsniff_ng_thread_status new_status);

int thread_should_stop(struct netsniff_ng_thread_context * thread_ctx);
void thread_stop(struct netsniff_ng_thread_context * thread_ctx);

#endif	/* _NET_THREAD_H_ */
