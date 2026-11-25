/* SPDX-License-Identifier: BSD-2-Clause */
/* 基础类型与内核结构体精简定义。
 *
 * 本文件前两部分（基本类型、bpf_map_type 枚举、x86 pt_regs）改编自
 * cilium/ebpf examples/headers/common.h（BSD-2-Clause）：
 *   https://github.com/cilium/ebpf/tree/main/examples/headers
 *
 * 之后的结构体（sock_common 等）只声明本收集器用到的字段，且全部通过
 * bpf_core_read（CO-RE）访问：加载时由内核 BTF 按字段名重定位偏移，
 * 因此这里的布局不必与内核逐字节一致。struct pt_regs 例外——它由
 * bpf_tracing.h 的 PT_REGS_* 宏直接按字段名访问，必须与内核命名一致。
 */

#pragma once

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

typedef __u64 size_t;

#include "bpf_helpers.h"

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC                = 0,
	BPF_MAP_TYPE_HASH                  = 1,
	BPF_MAP_TYPE_ARRAY                 = 2,
	BPF_MAP_TYPE_PROG_ARRAY            = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY      = 4,
	BPF_MAP_TYPE_PERCPU_HASH           = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY          = 6,
	BPF_MAP_TYPE_STACK_TRACE           = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY          = 8,
	BPF_MAP_TYPE_LRU_HASH              = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH       = 10,
	BPF_MAP_TYPE_LPM_TRIE              = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS         = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS          = 13,
	BPF_MAP_TYPE_DEVMAP                = 14,
	BPF_MAP_TYPE_SOCKMAP               = 15,
	BPF_MAP_TYPE_CPUMAP                = 16,
	BPF_MAP_TYPE_XSKMAP                = 17,
	BPF_MAP_TYPE_SOCKHASH              = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE        = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY   = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE                 = 22,
	BPF_MAP_TYPE_STACK                 = 23,
	BPF_MAP_TYPE_SK_STORAGE            = 24,
	BPF_MAP_TYPE_DEVMAP_HASH           = 25,
	BPF_MAP_TYPE_STRUCT_OPS            = 26,
	BPF_MAP_TYPE_RINGBUF               = 27,
	BPF_MAP_TYPE_INODE_STORAGE         = 28,
};

enum {
	BPF_ANY     = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST   = 2,
	BPF_F_LOCK  = 4,
};

/* bpf_tracing.h 的 PT_REGS_* 宏按内核命名访问 pt_regs 字段。
 * x86_64 走 bpf_tracing.h 的非 __KERNEL__ 分支（rdi/rsi/... 命名）。 */
#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long orig_rax;
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
};
#endif /* __TARGET_ARCH_x86 */

#if defined(__TARGET_ARCH_arm64)
/* bpf_tracing.h: #define PT_REGS_ARM64 const volatile struct user_pt_regs */
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
#endif /* __TARGET_ARCH_arm64 */

#define AF_INET  2
#define AF_INET6 10
#define TASK_COMM_LEN 16

/* 内核 struct in6_addr 的缩写（只用到 in6_u 联合） */
struct in6_addr {
	union {
		__u8   u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};

/* 内核 struct sock_common 的字段子集（sock 的开头部分）。
 * 访问一律走 CO-RE，字段偏移由 BTF 重定位，布局不必与内核一致。 */
struct sock_common {
	union {
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
};

struct sock {
	struct sock_common __sk_common;
};

/* connect(2) 的用户态 sockaddr 参数：内核 ABI 稳定，按此布局读用户内存 */
struct sockaddr_in {
	__u16 sin_family;
	__be16 sin_port;
	__u32 sin_addr;
	__u8  sin_zero[8];
};

struct sockaddr_in6 {
	__u16 sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	struct in6_addr sin6_addr;
	__u32 sin6_scope_id;
};

/* 仅作为函数参数类型出现，本文件不使用其字段 */
struct sockaddr;
struct msghdr;
