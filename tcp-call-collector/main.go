//go:build linux

// tcp-call-collector 是一个 eBPF TCP 调用收集器示例：
// 在 TCP 协议栈的关键函数上挂 kprobe/kretprobe，把每一次
// 建连 / 接受 / 发送 / 接收调用记录成一条事件，经 ringbuf 交给
// 用户态程序打印。
//
// 运行（需要 Linux 5.8+、内核开启 BTF、root）：
//
//	go generate ./...   // 重新编译 eBPF 并生成 Go 绑定（需要 clang）
//	go build -o tcpcollect .
//	sudo ./tcpcollect
//
// 另开一个终端产生一些 TCP 流量即可看到事件：
//
//	curl -s https://example.com
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go tool bpf2go -tags linux -no-strip -target amd64,arm64 tcpcollect bpf/tcpcollect.bpf.c -- -I./bpf -O2 -g -Wall

func main() {
	// 加载 eBPF 需要提升内存锁定上限
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("提升内存上限失败: %v", err)
	}

	// 把嵌入的字节码装载进内核（含 CO-RE 重定位）
	objs := tcpcollectObjects{}
	if err := loadTcpcollectObjects(&objs, nil); err != nil {
		log.Fatalf("加载 eBPF 对象失败: %v", err)
	}
	defer objs.Close()

	// 普通 kprobe：建连（v4/v6）、发送、接收
	var links []link.Link
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()
	for _, a := range []struct {
		name string
		prog *ebpf.Program
	}{
		{"tcp_v4_connect", objs.TpTcpV4Connect},
		{"tcp_v6_connect", objs.TpTcpV6Connect},
		{"tcp_sendmsg", objs.TpTcpSendmsg},
		{"tcp_recvmsg", objs.TpTcpRecvmsg},
	} {
		l, err := link.Kprobe(a.name, a.prog, nil)
		if err != nil {
			log.Fatalf("挂 kprobe %s 失败: %v", a.name, err)
		}
		links = append(links, l)
		log.Printf("已挂 kprobe: %s", a.name)
	}

	// kretprobe：接受连接（拿返回值里的子 socket）
	l, err := link.Kretprobe("inet_csk_accept", objs.TpInetCskAccept, nil)
	if err != nil {
		log.Fatalf("挂 kretprobe inet_csk_accept 失败: %v", err)
	}
	links = append(links, l)
	log.Printf("已挂 kretprobe: inet_csk_accept")

	// 读取 ringbuf 里的内核事件
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("打开 ringbuf 失败: %v", err)
	}
	defer rd.Close()

	// Ctrl-C / SIGTERM 时关闭 reader，让读循环自然结束
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()

	fmt.Printf("%-9s %-16s %8s  %-42s -> %-42s\n", "KIND", "COMM", "PID", "SRC", "DST")
	var ev tcpcollectEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("读取事件失败: %v", err)
			continue
		}
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &ev); err != nil {
			log.Printf("解析事件失败: %v", err)
			continue
		}
		fmt.Printf("%-9s %-16s %8d  %-42s -> %-42s\n",
			kindName(ev.Kind), bytes.TrimRight(ev.Comm[:], "\x00"), ev.Pid,
			endpoint(&ev, false), endpoint(&ev, true))
	}
}

func kindName(k uint8) string {
	switch k {
	case 1:
		return "CONNECT"
	case 2:
		return "ACCEPT"
	case 3:
		return "SEND"
	case 4:
		return "RECV"
	default:
		return fmt.Sprintf("?%d", k)
	}
}

// tcpcollectEvent 对应内核侧 bpf/tcpcollect.bpf.c 里的 struct tcp_event。
// ringbuf 的载荷是原始字节流，bpf2go 不会为它生成 Go 类型，这里手工声明，
// 字段布局与 C 结构体一致（含对齐填充），配合 binary.NativeEndian 逐字段解析。
type tcpcollectEvent struct {
	TsNs  uint64
	Pid   uint32
	Len   uint32
	Comm  [16]uint8
	Kind  uint8
	Ipv4  uint8
	Sport uint16
	Dport uint16
	_     [2]byte // 对齐填充：C 里 dport 之后 u32 saddr 需要 4 字节对齐
	Saddr [4]uint32
	Daddr [4]uint32
}

// endpoint 返回 "地址:端口"，IPv4 用点分十进制、IPv6 用冒号分隔。
// saddr/daddr 在事件里按网络字节序存储（IPv4 时只有第 1 个元素有效）。
func endpoint(e *tcpcollectEvent, dst bool) string {
	addr := e.Saddr
	port := e.Sport
	if dst {
		addr = e.Daddr
		port = e.Dport
	}
	var ip net.IP
	if e.Ipv4 == 1 {
		v := addr[0]
		ip = net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	} else {
		ip = make(net.IP, 16)
		for i, u := range addr {
			binary.BigEndian.PutUint32(ip[i*4:], u)
		}
	}
	return fmt.Sprintf("%s:%d", ip, port)
}
