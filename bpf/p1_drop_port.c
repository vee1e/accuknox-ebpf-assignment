// SPDX-License-Identifier: GPL-2.0-only
/* Problem 1: drop TCP packets whose destination port matches a
 * userspace-configured port (default 4040).
 *
 * Hook: TC ingress (attached via TCX from the Go loader).
 * Why TC and not XDP: XDP cannot attach to loopback and needs driver
 * support, which makes local/netns testing painful. TC ingress attaches
 * to lo, veth and physical NICs uniformly and still runs early in the
 * receive path, before the stack allocates sockets.
 *
 * Framing: most interfaces present a 14-byte Ethernet header (TC observes
 * one even on loopback, verified empirically). A single 802.1Q/802.1ad
 * tag (ethertypes 0x8100/0x88A8) shifts the L3 start by 4 bytes and is
 * handled. Anything else (double tags, non-Ethernet framing) is passed.
 *
 * Fragments: only the first fragment carries the TCP header, so only it
 * is matched; non-first fragments are passed.
 *
 * All header reads use bpf_skb_load_bytes, which bounds-checks at
 * runtime and keeps the verifier happy.
 *
 * IPv6 is supported for plain TCP (no extension headers). Packets with
 * IPv6 extension headers are passed (documented limitation).
 */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define IPPROTO_TCP 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define L2_LEN 14
#define VLAN_LEN 4

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32); /* blocked TCP dport, host byte order */
} p1_port SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2); /* [0]=passed [1]=dropped */
	__type(key, __u32);
	__type(value, __u64);
} p1_stats SEC(".maps");

static __always_inline void p1_count(__u32 idx) {
	__u64 *v = bpf_map_lookup_elem(&p1_stats, &idx);

	if (v)
		__sync_fetch_and_add(v, 1);
}

SEC("tc")
int tc_drop_port(struct __sk_buff *skb) {
	__u32 zero = 0;
	__u32 *port;
	__u32 l3 = L2_LEN;
	__u8 ver_ihl, proto, ihl;
	__u16 etype, frag;
	__u16 dport;

	port = bpf_map_lookup_elem(&p1_port, &zero);
	if (!port || *port == 0 || *port > 65535) {
		p1_count(0);
		return TC_ACT_OK;
	}

	/* Ethernet header, with one optional VLAN tag. */
	if (bpf_skb_load_bytes(skb, 12, &etype, sizeof(etype)))
		goto pass;
	etype = bpf_ntohs(etype);
	if (etype == ETH_P_8021Q || etype == ETH_P_8021AD) {
		l3 += VLAN_LEN;
		if (bpf_skb_load_bytes(skb, 12 + VLAN_LEN, &etype, sizeof(etype)))
			goto pass;
		etype = bpf_ntohs(etype);
	}
	if (etype != ETH_P_IP && etype != ETH_P_IPV6)
		goto pass;

	if (bpf_skb_load_bytes(skb, l3, &ver_ihl, sizeof(ver_ihl)))
		goto pass;

	if ((ver_ihl >> 4) == 4) {
		/* IPv4: IHL counts 4-byte words, frag field at +6,
		 * protocol at +9, TCP dport at end of IP header + 2. */
		ihl = ver_ihl & 0x0f;
		if (ihl < 5)
			goto pass;
		if (bpf_skb_load_bytes(skb, l3 + 6, &frag, sizeof(frag)))
			goto pass;
		if ((bpf_ntohs(frag) & 0x1fff) != 0)
			goto pass; /* non-first fragment: no TCP header */
		if (bpf_skb_load_bytes(skb, l3 + 9, &proto, sizeof(proto)))
			goto pass;
		if (proto != IPPROTO_TCP)
			goto pass;
		if (bpf_skb_load_bytes(skb, l3 + (__u32)ihl * 4 + 2, &dport, sizeof(dport)))
			goto pass;
		if (bpf_ntohs(dport) == (__u16)*port) {
			p1_count(1);
			return TC_ACT_SHOT;
		}
		goto pass;
	}

	if ((ver_ihl >> 4) == 6) {
		/* IPv6: next-header at +6, 40-byte fixed header, TCP dport
		 * at +42. Extension headers are not parsed: passed. */
		if (bpf_skb_load_bytes(skb, l3 + 6, &proto, sizeof(proto)))
			goto pass;
		if (proto != IPPROTO_TCP)
			goto pass;
		if (bpf_skb_load_bytes(skb, l3 + 42, &dport, sizeof(dport)))
			goto pass;
		if (bpf_ntohs(dport) == (__u16)*port) {
			p1_count(1);
			return TC_ACT_SHOT;
		}
		goto pass;
	}

pass:
	p1_count(0);
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
