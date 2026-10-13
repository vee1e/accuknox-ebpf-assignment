// SPDX-License-Identifier: GPL-2.0-only
/* Problem 2: allow a given process (matched by comm, e.g. "myprocess")
 * to use only one TCP port (default 4040). Connections/binds from that
 * process to any other port are denied. All other processes are unaffected.
 *
 * Hook: cgroup connect4/connect6 + bind4/bind6.
 * Why not XDP/TC: at XDP/TC ingress there is no reliable task context,
 * so the dropping side cannot tell which process a packet belongs to
 * (ingress runs in softirq, current is meaningless). cgroup connect/bind
 * hooks run in the process's own syscall context, so bpf_get_current_comm
 * identifies the caller exactly, and denying at connect/bind time stops
 * the traffic before any packet is sent. Both connect (outbound) and bind
 * (listeners) are filtered so "only that port" holds in
 * both directions of setup. Only TCP is filtered (`ctx->protocol` check);
 * other protocols are unaffected.
 *
 * A zero port is allowed: `bind(0)` asks the kernel for an ephemeral port,
 * which is not "using another port". (`connect` to port 0 is invalid and
 * fails later regardless.)
 *
 * An empty or zeroed config fails open (allows everything). The loader
 * always writes both maps before attaching, so this only triggers if the
 * maps are tampered with; failing closed there would risk a self-imposed
 * outage that is harder to debug than an explicit misconfiguration.
 *
 * Matching is by `comm`, which a process can change for itself: this
 * filter is process-convenience scoping, not a security boundary. For hard
 * isolation use cgroup membership or LSM labels instead.
 *
 * IPv4 and IPv6 are both covered. Return value: 1 = allow, 0 = deny.
 */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define IPPROTO_TCP 6

struct p2_target {
	char comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct p2_target);
} p2_target SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32); /* allowed TCP port, host byte order */
} p2_port SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2); /* [0]=allowed [1]=denied */
	__type(key, __u32);
	__type(value, __u64);
} p2_stats SEC(".maps");

static __always_inline void p2_count(__u32 idx) {
	__u64 *v = bpf_map_lookup_elem(&p2_stats, &idx);

	if (v)
		__sync_fetch_and_add(v, 1);
}

/* True when current comm equals the configured target (both NUL-padded). */
static __always_inline int p2_is_target(void) {
	__u32 zero = 0;
	struct p2_target *t;
	char comm[TASK_COMM_LEN];
	int i;

	t = bpf_map_lookup_elem(&p2_target, &zero);
	if (!t)
		return 0;
	if (bpf_get_current_comm(comm, sizeof(comm)) != 0)
		return 0;
	for (i = 0; i < TASK_COMM_LEN; i++) {
		if (comm[i] != t->comm[i])
			return 0;
	}
	return 1;
}

/* user_port is a u32 holding the network-order port in the low 16 bits. */
static __always_inline __u16 p2_nport(__u32 user_port) {
	__u16 p = (__u16)(user_port & 0xffff);

	return bpf_ntohs(p);
}

static __always_inline int p2_filter(struct bpf_sock_addr *ctx) {
	__u32 zero = 0;
	__u32 *allowed;

	if (ctx->protocol != IPPROTO_TCP) {
		p2_count(0);
		return 1;
	}
	if ((ctx->user_port & 0xffff) == 0) {
		p2_count(0);
		return 1; /* bind(0): ephemeral allocation, not a port choice */
	}
	if (!p2_is_target()) {
		p2_count(0);
		return 1;
	}
	allowed = bpf_map_lookup_elem(&p2_port, &zero);
	if (!allowed || *allowed == 0) {
		p2_count(0);
		return 1; /* unconfigured: fail open, see header comment */
	}
	if (p2_nport(ctx->user_port) == (__u16)*allowed) {
		p2_count(0);
		return 1;
	}
	p2_count(1);
	return 0;
}

SEC("cgroup/connect4")
int p2_connect4(struct bpf_sock_addr *ctx) { return p2_filter(ctx); }

SEC("cgroup/connect6")
int p2_connect6(struct bpf_sock_addr *ctx) { return p2_filter(ctx); }

SEC("cgroup/bind4")
int p2_bind4(struct bpf_sock_addr *ctx) { return p2_filter(ctx); }

SEC("cgroup/bind6")
int p2_bind6(struct bpf_sock_addr *ctx) { return p2_filter(ctx); }

char LICENSE[] SEC("license") = "GPL";
