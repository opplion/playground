# tcp-call-collector

一个用 **eBPF** 实现的 TCP 调用收集器示例：在 TCP 协议栈的关键函数上挂 kprobe / kretprobe，
把每一次「建连 / 接受 / 发送 / 接收」调用记录成一条事件，经 **ringbuf** 交给用户态程序打印。

```
CONNECT  curl                88912  10.1.2.3:53412 -> 142.250.72.14:443
SEND     curl                88912  10.1.2.3:53412 -> 142.250.72.14:443
RECV     curl                88912  10.1.2.3:53412 -> 142.250.72.14:443
ACCEPT   myhttpd              2087  127.0.0.1:8080  <- 127.0.0.1:53472
```

对应到内核观测的四个插桩点：

| 事件 | 挂载点 | 说明 |
|------|--------|------|
| CONNECT | `kprobe/tcp_v4_connect`、`kprobe/tcp_v6_connect` | 客户端发起建连，目的地址从用户态 `sockaddr` 参数读取 |
| ACCEPT  | `kretprobe/inet_csk_accept` | 服务端接受连接，子 socket 是函数的返回值 |
| SEND    | `kprobe/tcp_sendmsg` | 应用请求发送的字节数 |
| RECV    | `kprobe/tcp_recvmsg` | 应用请求接收的字节数 |

## 技术要点

- **CO-RE（Compile Once, Run Everywhere）**：内核结构体字段一律通过
  `bpf_probe_read_kernel` + `__builtin_preserve_access_index` 读取，加载时由内核 BTF
  按字段名重定位偏移，所以 `bpf/common.h` 里的 `struct sock_common` 只需声明用到的字段，
  不必与内核逐字节一致。
- **ringbuf**：`BPF_MAP_TYPE_RINGBUF` 型 map 作为内核 → 用户态的数据流，替代老式
  perf event array，单生产者单消费者零拷贝。
- **CO-RE 读用户内存**：建连事件的目的地址在入口函数时还没写到 socket 上，用
  `bpf_probe_read_user` 直接从用户态 `sockaddr` 读取。
- **kretprobe 拿返回值**：`inet_csk_accept` 返回的 child socket 只有 kretprobe 能拿到。

## 环境要求

- Linux 5.8+（ringbuf）且内核开启 BTF（`/sys/kernel/btf/vmlinux` 存在）
- 编译期：clang（支持 bpf target，版本 >= 12）
- 运行期：root 权限

## 构建与运行

```bash
# 1. 重新编译 eBPF 字节码并生成 Go 绑定（需要 clang）
go generate ./...
```

> 生成绑定只需做一次，产物（`.go` 内嵌字节码）会提交进仓库，普通使用者跳过这步。
> 在 macOS 上重新生成时，Apple clang 不带 BPF 后端，需要先装带 BPF target 的 LLVM
> （如 `brew install llvm`）并把它加进 PATH；且由于 `main.go` 带 `linux` 构建标签，
> `go generate ./...` 在本机匹配不到包，需直接调用 bpf2go：
>
> ```bash
> GOPACKAGE=main go run github.com/cilium/ebpf/cmd/bpf2go \
>   -tags linux -no-strip -target amd64,arm64 tcpcollect bpf/tcpcollect.bpf.c \
>   -- -I./bpf -O2 -g -Wall
> ```

```bash
# 2. 构建（生成的绑定已把 .o 字节码内嵌进 Go 代码，无需 clang）
go build -o tcpcollect .

# 3. 运行（Ctrl-C 退出）
sudo ./tcpcollect
```

另开一个终端产生一些 TCP 流量，就能看到事件：

```bash
curl -s https://example.com > /dev/null
```

## 代码结构

```
tcp-call-collector/
├── main.go                 # 用户态：加载 eBPF、挂探针、读 ringbuf、格式化打印
├── go.mod                  # 依赖 cilium/ebpf；tool directive 声明 bpf2go
├── bpf/
│   ├── tcpcollect.bpf.c    # 内核侧程序（kprobe/kretprobe 集合）
│   ├── common.h            # 基础类型、pt_regs、最小 sock 结构体（CO-RE）
│   └── ...                 # cilium/ebpf 提供的 bpf_helpers/bpf_tracing 等头文件
```

生成的 `tcpcollect_x86_bpfel.go` / `tcpcollect_arm64_bpfel.go` 分别内嵌 x86_64 与 arm64
架构编译出的字节码，按 `GOARCH` 构建时自动选对应的那份（`-target amd64,arm64` 同时
定义了 `__TARGET_ARCH_x86` / `__TARGET_ARCH_arm64`，`bpf_tracing.h` 的 `PT_REGS_*` 宏
依赖它们才能按架构展开）。

## 许可

示例代码采用 BSD-2-Clause（与 cilium/ebpf examples 一致）。`bpf/common.h` 前两部分改编自
[cilium/ebpf examples/headers](https://github.com/cilium/ebpf/tree/main/examples/headers)。
