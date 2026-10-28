// SPDX-License-Identifier: GPL-2.0
/*
 * pktgate - the /dev/pktgate character device and the event log
 *
 * The device has two jobs:
 *
 *   ioctl()  configures the filter: add/delete rules, policy, log mode, stats.
 *   read()   streams logged packets as struct pktgate_event records.
 *
 * Events are produced by the netfilter hooks (softirq context) and consumed
 * by read() (process context), so they go through a kfifo ring buffer. A
 * reader that finds the buffer empty sleeps on a wait queue until a hook
 * wakes it up; poll() lets a program wait on the device together with
 * other file descriptors. When the buffer is full, new events are dropped
 * and counted rather than blocking the network stack.
 */
#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/kfifo.h>
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include "pktgate.h"

/* Events copied out per read() call. */
#define PKTGATE_READ_BATCH 64

/* Per-open state: a staging buffer so events are not copied out on the stack. */
struct pktgate_reader {
	struct pktgate_event batch[PKTGATE_READ_BATCH];
};

static DECLARE_KFIFO_PTR(event_fifo, struct pktgate_event);
static DEFINE_SPINLOCK(event_lock);
static DECLARE_WAIT_QUEUE_HEAD(event_wq);
static atomic64_t events_logged;
static atomic64_t events_lost;

/* Called from the hooks, possibly in softirq context: must not sleep. */
void pktgate_log_event(const struct pktgate_pkt *pkt, const struct pktgate_verdict *v)
{
	struct pktgate_event ev = {
		.ts_ns   = ktime_get_real_ns(),
		.src     = pkt->src,
		.dst     = pkt->dst,
		.len     = pkt->len,
		.ifindex = pkt->ifindex,
		.sport   = pkt->sport,
		.dport   = pkt->dport,
		.proto   = pkt->proto,
		.dir     = pkt->dir,
		.action  = v->action,
		.rule    = v->rule,
	};

	/* kfifo_in_spinlocked() returns 0 when there is no room. */
	if (kfifo_in_spinlocked(&event_fifo, &ev, 1, &event_lock) == 0) {
		atomic64_inc(&events_lost);
		return;
	}
	atomic64_inc(&events_logged);
	wake_up_interruptible(&event_wq);
}

u64 pktgate_events_lost(void)
{
	return atomic64_read(&events_lost);
}

u64 pktgate_events_logged(void)
{
	return atomic64_read(&events_logged);
}

void pktgate_events_reset_counters(void)
{
	atomic64_set(&events_logged, 0);
	atomic64_set(&events_lost, 0);
}

static int pktgate_open(struct inode *inode, struct file *file)
{
	struct pktgate_reader *rd;

	rd = kzalloc(sizeof(*rd), GFP_KERNEL);
	if (!rd)
		return -ENOMEM;
	file->private_data = rd;

	/* A stream of events has no meaningful file position. */
	return stream_open(inode, file);
}

static int pktgate_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}

static ssize_t pktgate_read(struct file *file, char __user *buf, size_t count,
			    loff_t *ppos)
{
	struct pktgate_reader *rd = file->private_data;
	struct pktgate_event *tmp = rd->batch;
	unsigned int want, got;
	int ret;

	if (count < sizeof(tmp[0]))
		return -EINVAL;	/* reads must be in whole events */

	for (;;) {
		while (kfifo_is_empty(&event_fifo)) {
			if (file->f_flags & O_NONBLOCK)
				return -EAGAIN;
			/*
			 * Sleep until a hook adds an event. A signal (for example
			 * Ctrl-C in the reader) wakes us with -ERESTARTSYS.
			 */
			ret = wait_event_interruptible(event_wq,
						       !kfifo_is_empty(&event_fifo));
			if (ret)
				return ret;
		}

		want = min_t(size_t, count / sizeof(tmp[0]), PKTGATE_READ_BATCH);
		got = kfifo_out_spinlocked(&event_fifo, tmp, want, &event_lock);
		if (got)
			break;
		/* Another reader took the events between our check and the copy. */
	}

	/* Never hold a spinlock across copy_to_user(): it may sleep on a page fault. */
	if (copy_to_user(buf, tmp, got * sizeof(tmp[0])))
		return -EFAULT;
	return got * sizeof(tmp[0]);
}

static __poll_t pktgate_poll(struct file *file, poll_table *wait)
{
	__poll_t mask = 0;

	poll_wait(file, &event_wq, wait);
	if (!kfifo_is_empty(&event_fifo))
		mask |= EPOLLIN | EPOLLRDNORM;
	return mask;
}

static long pktgate_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct pktgate_rule_req req;
	struct pktgate_stats stats;
	struct pktgate_rule rule;
	u32 value;
	int ret;

	if (_IOC_TYPE(cmd) != PKTGATE_IOC_MAGIC)
		return -ENOTTY;

	switch (cmd) {
	case PKTGATE_IOC_ADD_RULE:
		if (copy_from_user(&rule, argp, sizeof(rule)))
			return -EFAULT;
		return pktgate_rules_add(&rule);	/* new index, or -errno */

	case PKTGATE_IOC_DEL_RULE:
		if (get_user(value, (u32 __user *)argp))
			return -EFAULT;
		return pktgate_rules_del(value);

	case PKTGATE_IOC_GET_RULE:
		if (copy_from_user(&req, argp, sizeof(req)))
			return -EFAULT;
		ret = pktgate_rules_get(req.index, &req.rule);
		if (ret)
			return ret;
		if (copy_to_user(argp, &req, sizeof(req)))
			return -EFAULT;
		return 0;

	case PKTGATE_IOC_FLUSH:
		pktgate_rules_flush();
		return 0;

	case PKTGATE_IOC_SET_POLICY:
		if (get_user(value, (u32 __user *)argp))
			return -EFAULT;
		return pktgate_set_policy(value);

	case PKTGATE_IOC_SET_LOGMODE:
		if (get_user(value, (u32 __user *)argp))
			return -EFAULT;
		return pktgate_set_log_mode(value);

	case PKTGATE_IOC_GET_STATS:
		pktgate_get_stats(&stats);
		if (copy_to_user(argp, &stats, sizeof(stats)))
			return -EFAULT;
		return 0;

	case PKTGATE_IOC_RESET_STATS:
		pktgate_reset_stats();
		return 0;

	default:
		return -ENOTTY;
	}
}

static const struct file_operations pktgate_fops = {
	.owner          = THIS_MODULE,	/* rmmod fails while the device is open */
	.open           = pktgate_open,
	.release        = pktgate_release,
	.read           = pktgate_read,
	.poll           = pktgate_poll,
	.unlocked_ioctl = pktgate_ioctl,
};

static struct miscdevice pktgate_misc = {
	.minor = MISC_DYNAMIC_MINOR,	/* major 10, minor chosen by the kernel */
	.name  = PKTGATE_NAME,		/* udev/devtmpfs creates /dev/pktgate */
	.fops  = &pktgate_fops,
	.mode  = 0600,			/* root only: it controls the firewall */
};

int pktgate_dev_init(unsigned int event_capacity)
{
	int ret;

	/* kfifo_alloc() rounds the capacity up to a power of two. */
	ret = kfifo_alloc(&event_fifo, event_capacity, GFP_KERNEL);
	if (ret)
		return ret;

	ret = misc_register(&pktgate_misc);
	if (ret) {
		kfifo_free(&event_fifo);
		return ret;
	}
	return 0;
}

void pktgate_dev_exit(void)
{
	misc_deregister(&pktgate_misc);
	kfifo_free(&event_fifo);
}
