// SPDX-License-Identifier: GPL-2.0
/*
 * pktgate - netfilter hooks
 *
 * Two hooks are registered on the IPv4 stack:
 *   NF_INET_LOCAL_IN  - packets addressed to this host, just before they are
 *                       delivered to a local socket;
 *   NF_INET_LOCAL_OUT - packets created by a local socket, just after routing.
 *
 * Both call pktgate_hook(), which pulls the fields the rules care about out
 * of the sk_buff, asks the rule table for a verdict, updates the counters,
 * logs the packet if required and returns NF_ACCEPT or NF_DROP.
 */
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <net/net_namespace.h>

#include "pktgate.h"

/*
 * Reads the two 16-bit port fields that start every TCP and UDP header.
 * skb_header_pointer() copies them out even when the packet data is not
 * stored in one contiguous buffer (a "non-linear" skb), so this is safe for
 * any packet the stack hands us.
 */
static void extract_ports(const struct sk_buff *skb, const struct iphdr *iph,
			  struct pktgate_pkt *pkt)
{
	struct {
		__be16 source;
		__be16 dest;
	} hdr, *ports;

	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return;
	/* Only the first fragment of a fragmented datagram carries the ports. */
	if (ip_is_fragment(iph) && (ntohs(iph->frag_off) & IP_OFFSET))
		return;

	ports = skb_header_pointer(skb, iph->ihl * 4, sizeof(hdr), &hdr);
	if (!ports)
		return;

	pkt->sport = ntohs(ports->source);
	pkt->dport = ntohs(ports->dest);
	pkt->ports_known = true;
}

static unsigned int pktgate_hook(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct pktgate_pkt pkt = {};
	struct pktgate_verdict v;

	if (!iph)
		return NF_ACCEPT;

	pkt.src = iph->saddr;
	pkt.dst = iph->daddr;
	pkt.len = ntohs(iph->tot_len);
	pkt.proto = iph->protocol;
	pkt.dir = (state->hook == NF_INET_LOCAL_IN) ? PKTGATE_DIR_IN : PKTGATE_DIR_OUT;
	if (state->in)
		pkt.ifindex = state->in->ifindex;
	else if (state->out)
		pkt.ifindex = state->out->ifindex;
	extract_ports(skb, iph, &pkt);

	pktgate_rules_lookup(&pkt, &v);
	pktgate_count_verdict(v.action);
	if (pktgate_should_log(&v))
		pktgate_log_event(&pkt, &v);

	/* NF_DROP frees the skb; a local sender sees EPERM ("Operation not permitted"). */
	return v.action == PKTGATE_DROP ? NF_DROP : NF_ACCEPT;
}

static struct nf_hook_ops pktgate_ops[] = {
	{
		.hook     = pktgate_hook,
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FILTER,	/* same stage as iptables' filter table */
	},
	{
		.hook     = pktgate_hook,
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_FILTER,
	},
};

int pktgate_hooks_register(void)
{
	/* init_net only: packets in other network namespaces (containers) are not seen. */
	return nf_register_net_hooks(&init_net, pktgate_ops, ARRAY_SIZE(pktgate_ops));
}

void pktgate_hooks_unregister(void)
{
	nf_unregister_net_hooks(&init_net, pktgate_ops, ARRAY_SIZE(pktgate_ops));
}
