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
 * Framing: TC ingress observes a 14-byte Ethernet header on every
 * supported interface, including loopback (verified empirically: with a
 * 0-byte offset nothing matches, with 14 the SYN is dropped). veth and
 * physical NICs are Ethernet anyway, so one fixed offset serves all.
 * Non-Ethernet interfaces (tun, sit) are out of scope.
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
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define L2_LEN 14

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
	__u8 ver_ihl, proto, ihl;
	__u16 dport;

	port = bpf_map_lookup_elem(&p1_port, &zero);
	if (!port || *port == 0 || *port > 65535) {
		p1_count(0);
		return TC_ACT_OK;
	}

	if (bpf_skb_load_bytes(skb, L2_LEN, &ver_ihl, sizeof(ver_ihl)))
		goto pass;

	if ((ver_ihl >> 4) == 4) {
		/* IPv4: IHL counts 4-byte words, protocol at +9,
		 * TCP dport at end of the IP header + 2. */
		ihl = ver_ihl & 0x0f;
		if (ihl < 5)
			goto pass;
		if (bpf_skb_load_bytes(skb, L2_LEN + 9, &proto, sizeof(proto)))
			goto pass;
		if (proto != IPPROTO_TCP)
			goto pass;
		if (bpf_skb_load_bytes(skb, L2_LEN + (__u32)ihl * 4 + 2, &dport, sizeof(dport)))
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
		if (bpf_skb_load_bytes(skb, L2_LEN + 6, &proto, sizeof(proto)))
			goto pass;
		if (proto != IPPROTO_TCP)
			goto pass;
		if (bpf_skb_load_bytes(skb, L2_LEN + 42, &dport, sizeof(dport)))
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
