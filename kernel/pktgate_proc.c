// SPDX-License-Identifier: GPL-2.0
/*
 * pktgate - /proc/net/pktgate
 *
 * A read-only text view of the configuration and counters, so the state of
 * the filter can be checked with plain `cat`. It is generated with the
 * seq_file interface, which handles buffering and partial reads for us.
 */
#include <linux/bitops.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <net/net_namespace.h>

#include "pktgate.h"

static const char *dir_name(u8 dir)
{
	switch (dir) {
	case PKTGATE_DIR_IN:  return "in";
	case PKTGATE_DIR_OUT: return "out";
	default:              return "any";
	}
}

static const char *proto_name(u8 proto)
{
	switch (proto) {
	case IPPROTO_TCP:  return "tcp";
	case IPPROTO_UDP:  return "udp";
	case IPPROTO_ICMP: return "icmp";
	default:           return "any";
	}
}

static const char *action_name(u8 action)
{
	return action == PKTGATE_DROP ? "drop" : "accept";
}

static const char *log_mode_name(u8 mode)
{
	switch (mode) {
	case PKTGATE_LOG_OFF: return "off";
	case PKTGATE_LOG_ALL: return "all";
	default:              return "drops";
	}
}

/* Formats a network-order address and mask as "a.b.c.d/N", or "any". */
static const char *cidr(__be32 addr, __be32 mask, char *buf, size_t len)
{
	if (!mask)
		return "any";
	/* %pI4 prints a network-byte-order IPv4 address. */
	scnprintf(buf, len, "%pI4/%u", &addr, hweight32(ntohl(mask)));
	return buf;
}

static int pktgate_proc_show(struct seq_file *m, void *v)
{
	char src[24], dst[24];
	struct pktgate_rule *rules;
	struct pktgate_stats st;
	int n, i;

	rules = kmalloc_array(PKTGATE_MAX_RULES, sizeof(*rules), GFP_KERNEL);
	if (!rules)
		return -ENOMEM;

	pktgate_get_stats(&st);
	n = pktgate_rules_snapshot(rules, PKTGATE_MAX_RULES);

	seq_printf(m, "pktgate %s\n", PKTGATE_VERSION);
	seq_printf(m, "policy:      %s\n", action_name(st.policy));
	seq_printf(m, "log_mode:    %s\n", log_mode_name(st.log_mode));
	seq_printf(m, "packets:     %llu\n", st.packets);
	seq_printf(m, "accepted:    %llu\n", st.accepted);
	seq_printf(m, "dropped:     %llu\n", st.dropped);
	seq_printf(m, "logged:      %llu\n", st.logged);
	seq_printf(m, "events_lost: %llu\n", st.events_lost);
	seq_printf(m, "rules:       %d\n\n", n);
	seq_printf(m, "%-3s %-4s %-5s %-18s %-18s %-6s %-6s %-6s %-3s %s\n",
		   "idx", "dir", "proto", "src", "dst", "sport", "dport",
		   "action", "log", "hits");

	for (i = 0; i < n; i++) {
		const struct pktgate_rule *r = &rules[i];

		seq_printf(m, "%-3d %-4s %-5s %-18s %-18s %-6u %-6u %-6s %-3s %llu\n",
			   i, dir_name(r->dir), proto_name(r->proto),
			   cidr(r->src, r->src_mask, src, sizeof(src)),
			   cidr(r->dst, r->dst_mask, dst, sizeof(dst)),
			   r->sport, r->dport, action_name(r->action),
			   (r->flags & PKTGATE_RULE_LOG) ? "yes" : "no", r->hits);
	}

	kfree(rules);
	return 0;
}

int pktgate_proc_init(void)
{
	if (!proc_create_single(PKTGATE_NAME, 0444, init_net.proc_net, pktgate_proc_show))
		return -ENOMEM;
	return 0;
}

void pktgate_proc_exit(void)
{
	remove_proc_entry(PKTGATE_NAME, init_net.proc_net);
}
