# khaos
A teeny-tiny program that allows you to drop network packets 
 for a specified process.

## Requirements
- Linux kernel version 6.10 or later
  - Calling `bpf_get_current_pid_tgid` in XDP programs was introduced, which makes it possible to drops packets on specified PIDs
- LLVM 11 or later (`clang` and `llvm-strip`)
- `libbpf` headers
- Linux kernel headers
- Go compiler version supported by `ebpf-go`'s Go module
- [bpf2go](https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go) (for bpf code gen)

## Building
To build and run, you can use following commands
```shell
# codegen/build
make build
# run the program
make run

# or both at the same time with
make
```

> P.S There are other make targets

## Usage
```shell
# You'll need root privileges in order to load BPF programs
sudo make run <ifname> <port> <drop_percent>

# or without make
sudo ./build/khaos <ifname> <port> <drop_percent>
```

>[!NOTE] About `<port>`
> Khaos uses an xdp ebpf program to drop packets. XDP only processes ingress packets, so the `<port>` argument basically
> filters anything that comes from the specified port.
> For example, if you provide `80`, it will result in filtering any HTTP traffic on the interface.