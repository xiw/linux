#ifndef _LINUX_SECCOMP_H
#define _LINUX_SECCOMP_H

#include <uapi/linux/filter.h>
#include <uapi/linux/seccomp.h>

#ifdef CONFIG_SECCOMP

#include <linux/thread_info.h>
#include <asm/seccomp.h>

struct sk_buff;

struct seccomp_filter;
/**
 * struct seccomp - the state of a seccomp'ed process
 *
 * @mode:  indicates one of the valid values above for controlled
 *         system calls available to a process.
 * @filter: The metadata and ruleset for determining what system calls
 *          are allowed for a task.
 *
 *          @filter must only be accessed from the context of current as there
 *          is no locking.
 */
struct seccomp {
	int mode;
	struct seccomp_filter *filter;
};

/**
 * struct seccomp_filter - container for seccomp BPF programs
 *
 * @usage: reference count to manage the object lifetime.
 *         get/put helpers should be used when accessing an instance
 *         outside of a lifetime-guarded section.  In general, this
 *         is only needed for handling filters shared across tasks.
 * @prev: points to a previously installed, or inherited, filter
 * @len: the number of instructions in the program
 * @bpf_func: points to either sk_run_filter or the code generated
 *            by the BPF JIT.
 * @insns: the BPF program instructions to evaluate
 *
 * seccomp_filter objects are organized in a tree linked via the @prev
 * pointer.  For any task, it appears to be a singly-linked list starting
 * with current->seccomp.filter, the most recently attached or inherited filter.
 * However, multiple filters may share a @prev node, by way of fork(), which
 * results in a unidirectional tree existing in memory.  This is similar to
 * how namespaces work.
 *
 * seccomp_filter objects should never be modified after being attached
 * to a task_struct (other than @usage).
 */
struct seccomp_filter {
	atomic_t usage;
	struct seccomp_filter *prev;
	unsigned short len;  /* Instruction count */
	unsigned int (*bpf_func)(const struct sk_buff *skb,
				 const struct sock_filter *filter);
	struct sock_filter insns[];
};

extern int __secure_computing(int);
static inline int secure_computing(int this_syscall)
{
	if (unlikely(test_thread_flag(TIF_SECCOMP)))
		return  __secure_computing(this_syscall);
	return 0;
}

/* A wrapper for architectures supporting only SECCOMP_MODE_STRICT. */
static inline void secure_computing_strict(int this_syscall)
{
	BUG_ON(secure_computing(this_syscall) != 0);
}

extern long prctl_get_seccomp(void);
extern long prctl_set_seccomp(unsigned long, char __user *);

static inline int seccomp_mode(struct seccomp *s)
{
	return s->mode;
}

#else /* CONFIG_SECCOMP */

#include <linux/errno.h>

struct seccomp { };
struct seccomp_filter { };

static inline int secure_computing(int this_syscall) { return 0; }
static inline void secure_computing_strict(int this_syscall) { return; }

static inline long prctl_get_seccomp(void)
{
	return -EINVAL;
}

static inline long prctl_set_seccomp(unsigned long arg2, char __user *arg3)
{
	return -EINVAL;
}

static inline int seccomp_mode(struct seccomp *s)
{
	return 0;
}
#endif /* CONFIG_SECCOMP */

#ifdef CONFIG_SECCOMP_FILTER
extern void put_seccomp_filter(struct task_struct *tsk);
extern void get_seccomp_filter(struct task_struct *tsk);
extern u32 seccomp_bpf_load(int off);
#else  /* CONFIG_SECCOMP_FILTER */
static inline void put_seccomp_filter(struct task_struct *tsk)
{
	return;
}
static inline void get_seccomp_filter(struct task_struct *tsk)
{
	return;
}
#endif /* CONFIG_SECCOMP_FILTER */

#ifdef CONFIG_SECCOMP_FILTER_JIT
extern void seccomp_jit_compile(struct seccomp_filter *fp);
extern void seccomp_jit_free(struct seccomp_filter *fp);
#define SECCOMP_RUN_FILTER(FILTER) (*FILTER->bpf_func)(NULL, FILTER->insns)
#else  /* CONFIG_SECCOMP_FILTER_JIT */
static inline void seccomp_jit_compile(struct seccomp_filter *fp)
{
	return;
}
static inline void seccomp_jit_free(struct seccomp_filter *fp)
{
	return;
}
#define SECCOMP_RUN_FILTER(FILTER) sk_run_filter(NULL, FILTER->insns)
#endif /* CONFIG_SECCOMP_FILTER_JIT */

#endif /* _LINUX_SECCOMP_H */
