/* SPDX-License-Identifier: GPL-2.0 */
/*
 * pktgate - user/kernel interface
 *
 * This header is shared by the kernel module and by user-space programs.
 * It defines the rule format, the event record and the ioctl commands of
 * /dev/pktgate. Everything uses fixed-width types so the layout is the same
 * on both sides of the boundary.
 */
#ifndef PKTGATE_UAPI_H
#define PKTGATE_UAPI_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define PKTGATE_DEVICE      "/dev/pktgate"
#define PKTGATE_MAX_RULES   64
#define PKTGATE_VERSION     "1.0"

/* Direction of a packet relative to this host. */
enum pktgate_dir {
	PKTGATE_DIR_ANY = 0,
	PKTGATE_DIR_IN  = 1,	/* NF_INET_LOCAL_IN  : arriving at a local socket */
	PKTGATE_DIR_OUT = 2,	/* NF_INET_LOCAL_OUT : leaving from a local socket */
};

/* Verdict of a rule, or the default policy. */
enum pktgate_action {
	PKTGATE_ACCEPT = 0,
	PKTGATE_DROP   = 1,
};

/* Which packets produce an event in the log. */
enum pktgate_log_mode {
	PKTGATE_LOG_OFF   = 0,
	PKTGATE_LOG_DROPS = 1,	/* default: every dropped packet */
	PKTGATE_LOG_ALL   = 2,	/* every packet seen by the hooks */
};

/* Rule flag: log the packet whenever this rule matches, whatever the log mode. */
#define PKTGATE_RULE_LOG	0x01

/*
 * A filter rule. Rules are checked in order and the first match wins.
 * A field set to 0 means "any". Addresses and masks are in network byte
 * order (as returned by inet_pton); ports are in host byte order.
 */
struct pktgate_rule {
	__u64 hits;		/* filled in by the kernel on GET_RULE */
	__u32 src;		/* source address, masked with src_mask */
	__u32 src_mask;
	__u32 dst;
	__u32 dst_mask;
	__u16 sport;		/* TCP/UDP source port, 0 = any */
	__u16 dport;		/* TCP/UDP destination port, 0 = any */
	__u8  proto;		/* 0 = any, otherwise IPPROTO_TCP/UDP/ICMP */
	__u8  dir;		/* enum pktgate_dir */
	__u8  action;		/* enum pktgate_action */
	__u8  flags;		/* PKTGATE_RULE_* */
};

/* One logged packet, as read() from /dev/pktgate. */
struct pktgate_event {
	__u64 ts_ns;		/* CLOCK_REALTIME nanoseconds */
	__u32 src;		/* network byte order */
	__u32 dst;
	__u32 len;		/* IP packet length in bytes */
	__u32 ifindex;		/* interface the packet arrived on / leaves by */
	__u16 sport;		/* host byte order, 0 if not TCP/UDP */
	__u16 dport;
	__u8  proto;
	__u8  dir;		/* PKTGATE_DIR_IN or PKTGATE_DIR_OUT */
	__u8  action;		/* verdict */
	__s8  rule;		/* matching rule index, -1 = default policy */
};

struct pktgate_stats {
	__u64 packets;		/* seen by the hooks */
	__u64 accepted;
	__u64 dropped;
	__u64 logged;		/* events written to the log */
	__u64 events_lost;	/* events discarded because the log was full */
	__u32 rule_count;
	__u8  policy;		/* enum pktgate_action */
	__u8  log_mode;		/* enum pktgate_log_mode */
	__u8  reserved[2];
};

struct pktgate_rule_req {
	__u32 index;
	__u32 reserved;
	struct pktgate_rule rule;
};

#define PKTGATE_IOC_MAGIC	'G'

/* Add a rule at the end of the table. Returns the new rule's index. */
#define PKTGATE_IOC_ADD_RULE	_IOW(PKTGATE_IOC_MAGIC, 1, struct pktgate_rule)
/* Delete the rule at this index; later rules move up. */
#define PKTGATE_IOC_DEL_RULE	_IOW(PKTGATE_IOC_MAGIC, 2, __u32)
/* Read back one rule, including its hit counter. */
#define PKTGATE_IOC_GET_RULE	_IOWR(PKTGATE_IOC_MAGIC, 3, struct pktgate_rule_req)
/* Delete every rule. */
#define PKTGATE_IOC_FLUSH	_IO(PKTGATE_IOC_MAGIC, 4)
/* Verdict for packets that match no rule (enum pktgate_action). */
#define PKTGATE_IOC_SET_POLICY	_IOW(PKTGATE_IOC_MAGIC, 5, __u32)
/* enum pktgate_log_mode */
#define PKTGATE_IOC_SET_LOGMODE	_IOW(PKTGATE_IOC_MAGIC, 6, __u32)
#define PKTGATE_IOC_GET_STATS	_IOR(PKTGATE_IOC_MAGIC, 7, struct pktgate_stats)
/* Zero the counters (global and per rule). */
#define PKTGATE_IOC_RESET_STATS	_IO(PKTGATE_IOC_MAGIC, 8)

#endif /* PKTGATE_UAPI_H */
