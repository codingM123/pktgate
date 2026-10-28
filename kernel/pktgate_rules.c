// SPDX-License-Identifier: GPL-2.0
/*
 * pktgate - rule table, policy and counters
 *
 * The table is a fixed array protected by a spinlock. The netfilter hooks
 * read it from softirq context (incoming packets are processed in the
 * NET_RX softirq), while ioctl() modifies it from process context. Every
 * user of the lock therefore takes the _bh variant: a process-context
 * holder that was interrupted by the softirq on the same CPU would
 * otherwise deadlock.
 *
 * The global packet counters are atomics so the hot path can bump them
 * without holding the lock any longer than the lookup itself.
 */
#include <linux/atomic.h>
#include <linux/in.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include "pktgate.h"

static struct pktgate_rule rules[PKTGATE_MAX_RULES];
static u32 rule_count;
static u8 policy = PKTGATE_ACCEPT;
static u8 log_mode = PKTGATE_LOG_DROPS;
static DEFINE_SPINLOCK(rules_lock);

static atomic64_t stat_packets;
static atomic64_t stat_accepted;
static atomic64_t stat_dropped;

static bool rule_is_valid(const struct pktgate_rule *r)
{
	switch (r->proto) {
	case 0:
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
		break;
	default:
		return false;
	}
	if (r->dir > PKTGATE_DIR_OUT || r->action > PKTGATE_DROP)
		return false;
	if (r->flags & ~PKTGATE_RULE_LOG)
		return false;
	/* Ports only make sense for TCP and UDP. */
	if ((r->sport || r->dport) &&
	    r->proto != IPPROTO_TCP && r->proto != IPPROTO_UDP)
		return false;
	return true;
}

int pktgate_rules_add(const struct pktgate_rule *rule)
{
	int index;

	if (!rule_is_valid(rule))
		return -EINVAL;

	spin_lock_bh(&rules_lock);
	if (rule_count >= PKTGATE_MAX_RULES) {
		spin_unlock_bh(&rules_lock);
		return -ENOSPC;
	}
	index = rule_count++;
	rules[index] = *rule;
	rules[index].hits = 0;
	spin_unlock_bh(&rules_lock);
	return index;
}

int pktgate_rules_del(u32 index)
{
	spin_lock_bh(&rules_lock);
	if (index >= rule_count) {
		spin_unlock_bh(&rules_lock);
		return -ENOENT;
	}
	/* Close the gap so the order of the remaining rules is unchanged. */
	memmove(&rules[index], &rules[index + 1],
		(rule_count - index - 1) * sizeof(rules[0]));
	rule_count--;
	spin_unlock_bh(&rules_lock);
	return 0;
}

int pktgate_rules_get(u32 index, struct pktgate_rule *out)
{
	spin_lock_bh(&rules_lock);
	if (index >= rule_count) {
		spin_unlock_bh(&rules_lock);
		return -ENOENT;
	}
	*out = rules[index];
	spin_unlock_bh(&rules_lock);
	return 0;
}

void pktgate_rules_flush(void)
{
	spin_lock_bh(&rules_lock);
	rule_count = 0;
	spin_unlock_bh(&rules_lock);
}

int pktgate_set_policy(u32 new_policy)
{
	if (new_policy > PKTGATE_DROP)
		return -EINVAL;
	spin_lock_bh(&rules_lock);
	policy = new_policy;
	spin_unlock_bh(&rules_lock);
	return 0;
}

int pktgate_set_log_mode(u32 mode)
{
	if (mode > PKTGATE_LOG_ALL)
		return -EINVAL;
	spin_lock_bh(&rules_lock);
	log_mode = mode;
	spin_unlock_bh(&rules_lock);
	return 0;
}

u8 pktgate_policy(void)
{
	return READ_ONCE(policy);
}

u8 pktgate_log_mode(void)
{
	return READ_ONCE(log_mode);
}

static bool rule_matches(const struct pktgate_rule *r, const struct pktgate_pkt *pkt)
{
	if (r->dir != PKTGATE_DIR_ANY && r->dir != pkt->dir)
		return false;
	if (r->proto && r->proto != pkt->proto)
		return false;
	/* A mask of 0 means "any address": (x & 0) == (0 & 0) is always true. */
	if ((pkt->src & r->src_mask) != (r->src & r->src_mask))
		return false;
	if ((pkt->dst & r->dst_mask) != (r->dst & r->dst_mask))
		return false;
	if (r->sport || r->dport) {
		/* A rule that needs ports cannot match a packet whose ports are unknown. */
		if (!pkt->ports_known)
			return false;
		if (r->sport && r->sport != pkt->sport)
			return false;
		if (r->dport && r->dport != pkt->dport)
			return false;
	}
	return true;
}

/* First matching rule wins; no match means the default policy applies. */
void pktgate_rules_lookup(const struct pktgate_pkt *pkt, struct pktgate_verdict *v)
{
	u32 i;

	spin_lock_bh(&rules_lock);
	for (i = 0; i < rule_count; i++) {
		if (rule_matches(&rules[i], pkt)) {
			rules[i].hits++;
			v->action = rules[i].action;
			v->rule = (s8)i;
			v->log = rules[i].flags & PKTGATE_RULE_LOG;
			spin_unlock_bh(&rules_lock);
			return;
		}
	}
	v->action = policy;
	v->rule = -1;
	v->log = false;
	spin_unlock_bh(&rules_lock);
}

bool pktgate_should_log(const struct pktgate_verdict *v)
{
	u8 mode = READ_ONCE(log_mode);

	if (v->log)
		return true;
	if (mode == PKTGATE_LOG_ALL)
		return true;
	return mode == PKTGATE_LOG_DROPS && v->action == PKTGATE_DROP;
}

void pktgate_count_verdict(u8 action)
{
	atomic64_inc(&stat_packets);
	if (action == PKTGATE_DROP)
		atomic64_inc(&stat_dropped);
	else
		atomic64_inc(&stat_accepted);
}

void pktgate_get_stats(struct pktgate_stats *st)
{
	memset(st, 0, sizeof(*st));
	st->packets = atomic64_read(&stat_packets);
	st->accepted = atomic64_read(&stat_accepted);
	st->dropped = atomic64_read(&stat_dropped);
	st->logged = pktgate_events_logged();
	st->events_lost = pktgate_events_lost();

	spin_lock_bh(&rules_lock);
	st->rule_count = rule_count;
	st->policy = policy;
	st->log_mode = log_mode;
	spin_unlock_bh(&rules_lock);
}

void pktgate_reset_stats(void)
{
	u32 i;

	atomic64_set(&stat_packets, 0);
	atomic64_set(&stat_accepted, 0);
	atomic64_set(&stat_dropped, 0);
	pktgate_events_reset_counters();

	spin_lock_bh(&rules_lock);
	for (i = 0; i < rule_count; i++)
		rules[i].hits = 0;
	spin_unlock_bh(&rules_lock);
}

/* Copies up to max rules into buf (used by /proc/net/pktgate). Returns the count. */
int pktgate_rules_snapshot(struct pktgate_rule *buf, int max)
{
	int n;

	spin_lock_bh(&rules_lock);
	n = min_t(int, rule_count, max);
	memcpy(buf, rules, n * sizeof(rules[0]));
	spin_unlock_bh(&rules_lock);
	return n;
}
