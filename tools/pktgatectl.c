// SPDX-License-Identifier: GPL-2.0
/*
 * pktgatectl - command-line control for the pktgate kernel module
 *
 * Talks to /dev/pktgate with ioctl() to manage rules and read counters, and
 * with read()/poll() to stream logged packets ("watch").
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include "pktgate_uapi.h"

static const char *device_path(void)
{
	const char *env = getenv("PKTGATE_DEV");
	return env ? env : PKTGATE_DEVICE;
}

static int open_device(int flags)
{
	int fd = open(device_path(), flags);
	if (fd < 0) {
		fprintf(stderr, "pktgatectl: cannot open %s: %s\n", device_path(), strerror(errno));
		if (errno == ENOENT)
			fprintf(stderr, "  is the module loaded? (sudo insmod kernel/pktgate.ko)\n");
		else if (errno == EACCES)
			fprintf(stderr, "  the device is root-only: run with sudo\n");
		exit(1);
	}
	return fd;
}

static void usage(FILE *out)
{
	fprintf(out,
		"Usage: pktgatectl <command> [options]\n"
		"\n"
		"Commands:\n"
		"  add [--in|--out] [--proto tcp|udp|icmp] [--src A.B.C.D[/N]] [--dst A.B.C.D[/N]]\n"
		"      [--sport PORT] [--dport PORT] [--log] accept|drop\n"
		"                        append a rule (first matching rule wins)\n"
		"  del INDEX             delete a rule\n"
		"  list                  show the rules with their hit counters\n"
		"  flush                 delete every rule\n"
		"  policy accept|drop    verdict for packets that match no rule\n"
		"  log off|drops|all     which packets are written to the event log\n"
		"  stats                 show the counters\n"
		"  reset                 zero the counters\n"
		"  watch [--max N] [--timeout SEC]\n"
		"                        print logged packets as they happen (Ctrl-C to stop)\n"
		"  version\n"
		"\n"
		"The device is %s (override with the PKTGATE_DEV environment variable).\n",
		PKTGATE_DEVICE);
}

static const char *dir_name(unsigned int dir)
{
	switch (dir) {
	case PKTGATE_DIR_IN:  return "in";
	case PKTGATE_DIR_OUT: return "out";
	default:              return "any";
	}
}

static const char *proto_name(unsigned int proto)
{
	switch (proto) {
	case IPPROTO_TCP:  return "tcp";
	case IPPROTO_UDP:  return "udp";
	case IPPROTO_ICMP: return "icmp";
	case 0:            return "any";
	default:           return "?";
	}
}

static const char *action_name(unsigned int action)
{
	return action == PKTGATE_DROP ? "drop" : "accept";
}

static const char *log_mode_name(unsigned int mode)
{
	switch (mode) {
	case PKTGATE_LOG_OFF: return "off";
	case PKTGATE_LOG_ALL: return "all";
	default:              return "drops";
	}
}

/* Formats a network-order address and mask as "a.b.c.d/N" (or "any"). */
static const char *cidr(__u32 addr, __u32 mask, char *buf, size_t len)
{
	struct in_addr in = { .s_addr = addr };
	char ip[INET_ADDRSTRLEN];

	if (mask == 0)
		return "any";
	inet_ntop(AF_INET, &in, ip, sizeof(ip));
	snprintf(buf, len, "%s/%d", ip, __builtin_popcount(mask));
	return buf;
}

static int prefix_to_mask(int prefix, __u32 *mask)
{
	if (prefix < 0 || prefix > 32)
		return -1;
	*mask = prefix == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - prefix));
	return 0;
}

/* Parses "A.B.C.D" or "A.B.C.D/N" into a network-order address and mask. */
static int parse_cidr(const char *text, __u32 *addr, __u32 *mask)
{
	char buf[64];
	char *slash;
	struct in_addr in;
	int prefix = 32;

	if (strlen(text) >= sizeof(buf))
		return -1;
	strcpy(buf, text);
	slash = strchr(buf, '/');
	if (slash) {
		char *end;
		*slash = '\0';
		prefix = (int)strtol(slash + 1, &end, 10);
		if (*end != '\0')
			return -1;
	}
	if (inet_pton(AF_INET, buf, &in) != 1)
		return -1;
	if (prefix_to_mask(prefix, mask))
		return -1;
	*addr = in.s_addr & *mask;
	return 0;
}

static int parse_port(const char *text, __u16 *port)
{
	char *end;
	long v = strtol(text, &end, 10);
	if (*end != '\0' || v < 1 || v > 65535)
		return -1;
	*port = (__u16)v;
	return 0;
}

static int cmd_add(int argc, char **argv)
{
	struct pktgate_rule rule = {0};
	int have_action = 0;
	int fd, ret, i;

	for (i = 0; i < argc; i++) {
		const char *a = argv[i];
		const char *val = (i + 1 < argc) ? argv[i + 1] : NULL;

		if (!strcmp(a, "--in")) {
			rule.dir = PKTGATE_DIR_IN;
		} else if (!strcmp(a, "--out")) {
			rule.dir = PKTGATE_DIR_OUT;
		} else if (!strcmp(a, "--log")) {
			rule.flags |= PKTGATE_RULE_LOG;
		} else if (!strcmp(a, "--proto") && val) {
			if (!strcmp(val, "tcp"))       rule.proto = IPPROTO_TCP;
			else if (!strcmp(val, "udp"))  rule.proto = IPPROTO_UDP;
			else if (!strcmp(val, "icmp")) rule.proto = IPPROTO_ICMP;
			else if (!strcmp(val, "any"))  rule.proto = 0;
			else goto bad;
			i++;
		} else if (!strcmp(a, "--src") && val) {
			if (parse_cidr(val, &rule.src, &rule.src_mask))
				goto bad;
			i++;
		} else if (!strcmp(a, "--dst") && val) {
			if (parse_cidr(val, &rule.dst, &rule.dst_mask))
				goto bad;
			i++;
		} else if (!strcmp(a, "--sport") && val) {
			if (parse_port(val, &rule.sport))
				goto bad;
			i++;
		} else if (!strcmp(a, "--dport") && val) {
			if (parse_port(val, &rule.dport))
				goto bad;
			i++;
		} else if (!strcmp(a, "accept")) {
			rule.action = PKTGATE_ACCEPT;
			have_action = 1;
		} else if (!strcmp(a, "drop")) {
			rule.action = PKTGATE_DROP;
			have_action = 1;
		} else {
			goto bad;
		}
	}
	if (!have_action) {
		fprintf(stderr, "pktgatectl add: an action (accept or drop) is required\n");
		return 2;
	}
	if ((rule.sport || rule.dport) && rule.proto != IPPROTO_TCP && rule.proto != IPPROTO_UDP) {
		fprintf(stderr, "pktgatectl add: ports need --proto tcp or --proto udp\n");
		return 2;
	}

	fd = open_device(O_RDWR);
	ret = ioctl(fd, PKTGATE_IOC_ADD_RULE, &rule);
	if (ret < 0) {
		fprintf(stderr, "pktgatectl add: %s\n",
			errno == ENOSPC ? "rule table is full" : strerror(errno));
		close(fd);
		return 1;
	}
	printf("added rule %d\n", ret);
	close(fd);
	return 0;

bad:
	fprintf(stderr, "pktgatectl add: bad argument near '%s'\n", argv[i]);
	return 2;
}

static int simple_ioctl(unsigned long req, __u32 *value, const char *what)
{
	int fd = open_device(O_RDWR);
	int ret = ioctl(fd, req, value);
	if (ret < 0)
		fprintf(stderr, "pktgatectl %s: %s\n", what,
			errno == ENOENT ? "no such rule" : strerror(errno));
	close(fd);
	return ret < 0 ? 1 : 0;
}

static int cmd_del(int argc, char **argv)
{
	__u32 index;
	char *end;

	if (argc != 1) {
		fprintf(stderr, "Usage: pktgatectl del INDEX\n");
		return 2;
	}
	index = (__u32)strtoul(argv[0], &end, 10);
	if (*end != '\0') {
		fprintf(stderr, "pktgatectl del: '%s' is not a rule index\n", argv[0]);
		return 2;
	}
	return simple_ioctl(PKTGATE_IOC_DEL_RULE, &index, "del");
}

static int cmd_policy(int argc, char **argv)
{
	__u32 value;

	if (argc == 1 && !strcmp(argv[0], "accept"))
		value = PKTGATE_ACCEPT;
	else if (argc == 1 && !strcmp(argv[0], "drop"))
		value = PKTGATE_DROP;
	else {
		fprintf(stderr, "Usage: pktgatectl policy accept|drop\n");
		return 2;
	}
	return simple_ioctl(PKTGATE_IOC_SET_POLICY, &value, "policy");
}

static int cmd_log(int argc, char **argv)
{
	__u32 value;

	if (argc == 1 && !strcmp(argv[0], "off"))
		value = PKTGATE_LOG_OFF;
	else if (argc == 1 && !strcmp(argv[0], "drops"))
		value = PKTGATE_LOG_DROPS;
	else if (argc == 1 && !strcmp(argv[0], "all"))
		value = PKTGATE_LOG_ALL;
	else {
		fprintf(stderr, "Usage: pktgatectl log off|drops|all\n");
		return 2;
	}
	return simple_ioctl(PKTGATE_IOC_SET_LOGMODE, &value, "log");
}

static int cmd_list(void)
{
	char src[48], dst[48];
	int fd = open_device(O_RDONLY);
	__u32 i;

	printf("%-3s %-4s %-5s %-20s %-20s %-6s %-6s %-6s %-3s %s\n",
	       "idx", "dir", "proto", "src", "dst", "sport", "dport", "action", "log", "hits");
	for (i = 0; i < PKTGATE_MAX_RULES; i++) {
		struct pktgate_rule_req req = { .index = i };
		const struct pktgate_rule *r = &req.rule;

		if (ioctl(fd, PKTGATE_IOC_GET_RULE, &req) < 0)
			break;	/* ENOENT: past the last rule */
		printf("%-3u %-4s %-5s %-20s %-20s %-6u %-6u %-6s %-3s %llu\n",
		       i, dir_name(r->dir), proto_name(r->proto),
		       cidr(r->src, r->src_mask, src, sizeof(src)),
		       cidr(r->dst, r->dst_mask, dst, sizeof(dst)),
		       r->sport, r->dport, action_name(r->action),
		       (r->flags & PKTGATE_RULE_LOG) ? "yes" : "no",
		       (unsigned long long)r->hits);
	}
	if (i == 0)
		printf("(no rules)\n");
	close(fd);
	return 0;
}

static int cmd_stats(void)
{
	struct pktgate_stats st;
	int fd = open_device(O_RDONLY);

	if (ioctl(fd, PKTGATE_IOC_GET_STATS, &st) < 0) {
		perror("pktgatectl stats");
		close(fd);
		return 1;
	}
	close(fd);
	printf("policy:      %s\n", action_name(st.policy));
	printf("log mode:    %s\n", log_mode_name(st.log_mode));
	printf("rules:       %u\n", st.rule_count);
	printf("packets:     %llu\n", (unsigned long long)st.packets);
	printf("accepted:    %llu\n", (unsigned long long)st.accepted);
	printf("dropped:     %llu\n", (unsigned long long)st.dropped);
	printf("logged:      %llu\n", (unsigned long long)st.logged);
	printf("events lost: %llu\n", (unsigned long long)st.events_lost);
	return 0;
}

static void print_event(const struct pktgate_event *ev)
{
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN], ifname[IF_NAMESIZE];
	char stamp[32], rule[16];
	struct in_addr in;
	time_t secs = (time_t)(ev->ts_ns / 1000000000ULL);
	struct tm tm;

	localtime_r(&secs, &tm);
	strftime(stamp, sizeof(stamp), "%H:%M:%S", &tm);

	in.s_addr = ev->src;
	inet_ntop(AF_INET, &in, src, sizeof(src));
	in.s_addr = ev->dst;
	inet_ntop(AF_INET, &in, dst, sizeof(dst));
	if (!if_indextoname(ev->ifindex, ifname))
		snprintf(ifname, sizeof(ifname), "if%u", ev->ifindex);
	if (ev->rule < 0)
		snprintf(rule, sizeof(rule), "policy");
	else
		snprintf(rule, sizeof(rule), "rule %d", ev->rule);

	if (ev->proto == IPPROTO_TCP || ev->proto == IPPROTO_UDP)
		printf("%s.%03u  %-3s %-4s %s:%u -> %s:%u  %u bytes  %-6s (%s) %s\n",
		       stamp, (unsigned int)(ev->ts_ns / 1000000ULL % 1000),
		       dir_name(ev->dir), proto_name(ev->proto), src, ev->sport, dst, ev->dport,
		       ev->len, action_name(ev->action), rule, ifname);
	else
		printf("%s.%03u  %-3s %-4s %s -> %s  %u bytes  %-6s (%s) %s\n",
		       stamp, (unsigned int)(ev->ts_ns / 1000000ULL % 1000),
		       dir_name(ev->dir), proto_name(ev->proto), src, dst,
		       ev->len, action_name(ev->action), rule, ifname);
	fflush(stdout);
}

static int cmd_watch(int argc, char **argv)
{
	struct pktgate_event events[64];
	long max_events = 0, timeout_s = 0, shown = 0;
	struct timespec start, now;
	int fd, i;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--max") && i + 1 < argc)
			max_events = strtol(argv[++i], NULL, 10);
		else if (!strcmp(argv[i], "--timeout") && i + 1 < argc)
			timeout_s = strtol(argv[++i], NULL, 10);
		else {
			fprintf(stderr, "Usage: pktgatectl watch [--max N] [--timeout SEC]\n");
			return 2;
		}
	}

	fd = open_device(O_RDONLY | O_NONBLOCK);
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (;;) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		int wait_ms = -1, ret;
		ssize_t n;

		if (timeout_s > 0) {
			clock_gettime(CLOCK_MONOTONIC, &now);
			long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 +
					  (now.tv_nsec - start.tv_nsec) / 1000000;
			wait_ms = (int)(timeout_s * 1000 - elapsed_ms);
			if (wait_ms <= 0)
				break;
		}

		/* poll() sleeps until the kernel has at least one event for us. */
		ret = poll(&pfd, 1, wait_ms);
		if (ret < 0) {
			if (errno == EINTR)
				break;	/* Ctrl-C */
			perror("pktgatectl watch: poll");
			close(fd);
			return 1;
		}
		if (ret == 0)
			break;	/* timed out */

		n = read(fd, events, sizeof(events));
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			perror("pktgatectl watch: read");
			close(fd);
			return 1;
		}
		for (i = 0; i < (int)(n / (ssize_t)sizeof(events[0])); i++) {
			print_event(&events[i]);
			shown++;
			if (max_events > 0 && shown >= max_events) {
				close(fd);
				return 0;
			}
		}
	}
	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	const char *cmd;
	__u32 dummy = 0;

	if (argc < 2 || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
		usage(argc < 2 ? stderr : stdout);
		return argc < 2 ? 2 : 0;
	}
	cmd = argv[1];
	argc -= 2;
	argv += 2;

	if (!strcmp(cmd, "add"))     return cmd_add(argc, argv);
	if (!strcmp(cmd, "del"))     return cmd_del(argc, argv);
	if (!strcmp(cmd, "list"))    return cmd_list();
	if (!strcmp(cmd, "flush"))   return simple_ioctl(PKTGATE_IOC_FLUSH, &dummy, "flush");
	if (!strcmp(cmd, "policy"))  return cmd_policy(argc, argv);
	if (!strcmp(cmd, "log"))     return cmd_log(argc, argv);
	if (!strcmp(cmd, "stats"))   return cmd_stats();
	if (!strcmp(cmd, "reset"))   return simple_ioctl(PKTGATE_IOC_RESET_STATS, &dummy, "reset");
	if (!strcmp(cmd, "watch"))   return cmd_watch(argc, argv);
	if (!strcmp(cmd, "version")) { printf("pktgatectl %s\n", PKTGATE_VERSION); return 0; }

	fprintf(stderr, "pktgatectl: unknown command '%s'\n\n", cmd);
	usage(stderr);
	return 2;
}
