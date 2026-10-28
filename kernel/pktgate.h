/* SPDX-License-Identifier: GPL-2.0 */
/* pktgate - declarations shared between the module's source files. */
#ifndef PKTGATE_H
#define PKTGATE_H

#include <linux/types.h>
#include <linux/skbuff.h>

#include "pktgate_uapi.h"

#define PKTGATE_NAME "pktgate"

/* What the hook extracted from one packet. */
struct pktgate_pkt {
	__be32 src;
	__be32 dst;
	u32 len;
	u32 ifindex;
	u16 sport;		/* host order; 0 when unknown (not TCP/UDP, or a later fragment) */
	u16 dport;
	u8 proto;
	u8 dir;
	bool ports_known;
};

/* Result of looking a packet up in the rule table. */
struct pktgate_verdict {
	u8 action;		/* enum pktgate_action */
	s8 rule;		/* matching rule index, -1 for the default policy */
	bool log;		/* the matching rule asked for logging */
};

/* pktgate_rules.c : the rule table, policy, log mode and counters */
int  pktgate_rules_add(const struct pktgate_rule *rule);
int  pktgate_rules_del(u32 index);
int  pktgate_rules_get(u32 index, struct pktgate_rule *out);
void pktgate_rules_flush(void);
int  pktgate_set_policy(u32 policy);
int  pktgate_set_log_mode(u32 mode);
void pktgate_rules_lookup(const struct pktgate_pkt *pkt, struct pktgate_verdict *v);
bool pktgate_should_log(const struct pktgate_verdict *v);
void pktgate_count_verdict(u8 action);
void pktgate_get_stats(struct pktgate_stats *st);
void pktgate_reset_stats(void);
int  pktgate_rules_snapshot(struct pktgate_rule *buf, int max);
u8   pktgate_policy(void);
u8   pktgate_log_mode(void);

/* pktgate_dev.c : /dev/pktgate and the event log */
int  pktgate_dev_init(unsigned int event_capacity);
void pktgate_dev_exit(void);
void pktgate_log_event(const struct pktgate_pkt *pkt, const struct pktgate_verdict *v);
u64  pktgate_events_lost(void);
u64  pktgate_events_logged(void);
void pktgate_events_reset_counters(void);

/* pktgate_hook.c : the netfilter hooks */
int  pktgate_hooks_register(void);
void pktgate_hooks_unregister(void);

/* pktgate_proc.c : /proc/net/pktgate */
int  pktgate_proc_init(void);
void pktgate_proc_exit(void);

#endif /* PKTGATE_H */
