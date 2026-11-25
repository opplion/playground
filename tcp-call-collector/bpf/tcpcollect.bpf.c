//go:build ignore

/* tcpcollect.bpf.c —— TCP 调用收集器（内核侧）
 *
 * 在 TCP 协议栈的关键函数上挂 kprobe / kretprobe，采集四类调用事件：
 *   建连（tcp_v4_connect / tcp_v6_connect）、接受（inet_csk_accept）、
 *   发送（tcp_sendmsg）、接收（tcp_recvmsg）。
 * 事件经 ringbuf（events map）提交给用户态程序打印。
 *
 * 依赖：Linux 5.8+（ringbuf + CO-RE）、内核开启 BTF。
 * 内核结构体字段一律通过 bpf_probe_read_kernel + __builtin_preserve_access_index
 * 读取（CO-RE）：加载时由内核 BTF 按字段名重定位偏移，不依赖本文件里
 * 的结构体与内核逐字节一致。
 */

#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "GPL";

/* 事件类型 */
enum tcp_call_kind {
	TCP_CONNECT = 1, /* 客户端发起建连 */
	TCP_ACCEPT  = 2, /* 服务端接受连接 */
	TCP_SEND    = 3, /* tcp_sendmsg 调用 */
	TCP_RECV    = 4, /* tcp_recvmsg 调用 */
};

/* 一次 TCP 调用事件（ringbuf 载荷，用户态 Go 代码按同一布局解析） */
struct tcp_event {
	__u64 ts_ns;               /* 事件时间戳（内核启动以来的纳秒） */
	__u32 pid;                 /* 触发调用的进程号 */
	__u32 len;                 /* send/recv 的请求字节数；建连/接受为 0 */
	__u8  comm[TASK_COMM_LEN]; /* 进程名 */
	__u8  kind;                /* enum tcp_call_kind */
	__u8  ipv4;                /* 1 表示 IPv4 */
	__u16 sport;               /* 源端口（主机字节序） */
	__u16 dport;               /* 目的端口（主机字节序） */
	__u32 saddr[4];            /* 源地址：IPv4 用第 1 个元素，IPv6 存满 4 个 */
	__u32 daddr[4];            /* 目的地址 */
};

/* 事件外送：ringbuf 型 map（内核 → 用户态的数据流） */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

/* CO-RE 内核内存读取：对字段访问打 preserve_access_index 标记，
 * 加载器据此生成按字段名的偏移重定位。 */
#define CORE_READ(dst, ptr, field)                                              \
	bpf_probe_read_kernel((dst), sizeof(*(dst)),                             \
		(const void *)__builtin_preserve_access_index(&(ptr)->field))

#define CORE_READ_BYTES(dst, len, ptr, field)                                  \
	bpf_probe_read_kernel((dst), (len),                                     \
		(const void *)__builtin_preserve_access_index(&(ptr)->field))

/* 把一次事件提交到 ringbuf */
static __always_inline void submit(struct tcp_event *e)
{
	struct tcp_event *rec = bpf_ringbuf_reserve(&events, sizeof(*rec), 0);
	if (!rec)
		return;
	*rec = *e;
	bpf_ringbuf_submit(rec, 0);
}

/* 填充 sock 上的五元组（本地/对端地址与端口） */
static __always_inline void fill_sock(struct tcp_event *e, struct sock *sk)
{
	__u16 family = 0;
	CORE_READ(&family, sk, __sk_common.skc_family);

	if (family == AF_INET) {
		e->ipv4 = 1;
		CORE_READ(&e->saddr[0], sk, __sk_common.skc_rcv_saddr);
		CORE_READ(&e->daddr[0], sk, __sk_common.skc_daddr);
	} else if (family == AF_INET6) {
		e->ipv4 = 0;
		CORE_READ_BYTES(e->saddr, 16, sk, __sk_common.skc_v6_rcv_saddr);
		CORE_READ_BYTES(e->daddr, 16, sk, __sk_common.skc_v6_daddr);
	} else {
		return; /* 非 INET 家族，本收集器不关心 */
	}

	/* skc_num 为主机字节序；skc_dport 为网络字节序 */
	__u16 sport = 0, dport = 0;
	CORE_READ(&sport, sk, __sk_common.skc_num);
	CORE_READ(&dport, sk, __sk_common.skc_dport);
	e->sport = sport;
	e->dport = bpf_ntohs(dport);
}

/* 建连：目的地址/端口在用户态 sockaddr 参数里（入口时尚未写到 sock 上），
 * 用 bpf_probe_read_user 读取；本地端口未 bind 时可能尚未分配。 */
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tp_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr,
	       int addr_len)
{
	struct tcp_event e = {};
	e.kind = TCP_CONNECT;
	e.ts_ns = bpf_ktime_get_ns();
	e.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e.comm, sizeof(e.comm));

	struct sockaddr_in sin;
	if (uaddr && bpf_probe_read_user(&sin, sizeof(sin), uaddr) == 0 &&
	    sin.sin_family == AF_INET) {
		e.ipv4 = 1;
		e.daddr[0] = sin.sin_addr;
		e.dport = bpf_ntohs(sin.sin_port);
	}
	__u16 sport = 0;
	CORE_READ(&sport, sk, __sk_common.skc_num);
	e.sport = sport;

	submit(&e);
	return 0;
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tp_tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr,
	       int addr_len)
{
	struct tcp_event e = {};
	e.kind = TCP_CONNECT;
	e.ts_ns = bpf_ktime_get_ns();
	e.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e.comm, sizeof(e.comm));

	struct sockaddr_in6 sin6;
	if (uaddr && bpf_probe_read_user(&sin6, sizeof(sin6), uaddr) == 0 &&
	    sin6.sin6_family == AF_INET6) {
		e.ipv4 = 0;
		e.daddr[0] = sin6.sin6_addr.in6_u.u6_addr32[0];
		e.daddr[1] = sin6.sin6_addr.in6_u.u6_addr32[1];
		e.daddr[2] = sin6.sin6_addr.in6_u.u6_addr32[2];
		e.daddr[3] = sin6.sin6_addr.in6_u.u6_addr32[3];
		e.dport = bpf_ntohs(sin6.sin6_port);
	}
	__u16 sport = 0;
	CORE_READ(&sport, sk, __sk_common.skc_num);
	e.sport = sport;

	submit(&e);
	return 0;
}

/* 接受连接：子 socket 是 inet_csk_accept 的返回值，用 kretprobe 拿 */
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(tp_inet_csk_accept, struct sock *child)
{
	if (!child)
		return 0;

	struct tcp_event e = {};
	e.kind = TCP_ACCEPT;
	e.ts_ns = bpf_ktime_get_ns();
	e.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e.comm, sizeof(e.comm));
	fill_sock(&e, child);

	submit(&e);
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tp_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	struct tcp_event e = {};
	e.kind = TCP_SEND;
	e.ts_ns = bpf_ktime_get_ns();
	e.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e.comm, sizeof(e.comm));
	e.len = size;
	fill_sock(&e, sk);

	submit(&e);
	return 0;
}

/* len 是应用请求接收的字节数，实际收到的可能更少 */
SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(tp_tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len,
	       int flags, int *addr_len)
{
	struct tcp_event e = {};
	e.kind = TCP_RECV;
	e.ts_ns = bpf_ktime_get_ns();
	e.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e.comm, sizeof(e.comm));
	e.len = len;
	fill_sock(&e, sk);

	submit(&e);
	return 0;
}
