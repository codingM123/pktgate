// SPDX-License-Identifier: GPL-2.0
/*
 * pktgate - a small IPv4 packet filter for Linux
 *
 * Loads two netfilter hooks that match packets against a rule table and
 * drop, accept and log them; exposes the filter through the /dev/pktgate
 * character device (ioctl + a readable event stream) and /proc/net/pktgate.
 *
 * Module parameters:
 *   policy=accept|drop   verdict for packets that match no rule (default accept)
 *   event_capacity=N     size of the event ring buffer, rounded up to a power of two
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/string.h>

#include "pktgate.h"

static char *policy = "accept";
module_param(policy, charp, 0444);
MODULE_PARM_DESC(policy, "default verdict: accept (default) or drop");

static unsigned int event_capacity = 1024;
module_param(event_capacity, uint, 0444);
MODULE_PARM_DESC(event_capacity, "event log capacity in records (64..65536, default 1024)");

static int __init pktgate_init(void)
{
	int ret;

	if (strcmp(policy, "accept") == 0) {
		pktgate_set_policy(PKTGATE_ACCEPT);
	} else if (strcmp(policy, "drop") == 0) {
		pktgate_set_policy(PKTGATE_DROP);
	} else {
		pr_err(PKTGATE_NAME ": policy must be \"accept\" or \"drop\"\n");
		return -EINVAL;
	}
	if (event_capacity < 64 || event_capacity > 65536) {
		pr_err(PKTGATE_NAME ": event_capacity must be between 64 and 65536\n");
		return -EINVAL;
	}

	/* Order matters: the hooks must not run before the log exists. */
	ret = pktgate_dev_init(event_capacity);
	if (ret)
		goto err;
	ret = pktgate_proc_init();
	if (ret)
		goto err_dev;
	ret = pktgate_hooks_register();
	if (ret)
		goto err_proc;

	pr_info(PKTGATE_NAME ": loaded (policy=%s, event_capacity=%u)\n",
		policy, event_capacity);
	return 0;

err_proc:
	pktgate_proc_exit();
err_dev:
	pktgate_dev_exit();
err:
	pr_err(PKTGATE_NAME ": init failed (%d)\n", ret);
	return ret;
}

static void __exit pktgate_exit(void)
{
	/* Reverse order: stop producing events before freeing the log. */
	pktgate_hooks_unregister();
	pktgate_proc_exit();
	pktgate_dev_exit();
	pr_info(PKTGATE_NAME ": unloaded\n");
}

module_init(pktgate_init);
module_exit(pktgate_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arpita");
MODULE_DESCRIPTION("IPv4 packet filter with a character-device control interface and event log");
MODULE_VERSION(PKTGATE_VERSION);
