/* Minimal vmlinux.h for this repo's BPF programs.
 *
 * A full BTF-derived vmlinux.h is unnecessary here: CO-RE relocations
 * resolve the named struct fields below against the running kernel's BTF
 * when the objects load, and the enum values are UAPI-stable. If broader
 * kernel-type coverage is ever needed, regenerate the full header with:
 *
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
 */
#ifndef AK_VMLINUX_H
#define AK_VMLINUX_H

typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef signed short __s16;
typedef unsigned int __u32;
typedef signed int __s32;
typedef unsigned long long __u64;
typedef signed long long __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;

/* Checksum types used by libbpf helper declarations. */
typedef __u32 __wsum;
typedef __u16 __sum16;

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
};

/* Opaque to our programs: only the pointer type is used. */
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
} __attribute__((preserve_access_index));

/* Only user_port is read; CO-RE resolves its offset at load time. */
struct bpf_sock_addr {
	__u32 user_family;
	__u32 user_ip4;
	__u32 user_ip6[4];
	__u32 user_port;
	__u32 family;
	__u32 type;
	__u32 protocol;
} __attribute__((preserve_access_index));

#endif /* AK_VMLINUX_H */
