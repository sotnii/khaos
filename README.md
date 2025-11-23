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
sudo make run <dropped packets pct> --interface <ifname> --port <port>

# or without make
sudo ./build/khaos <dropped packets pct> --interface <ifname> --port <port>
```

### Available Flags
- `--interface, -i`: Interface to attach the program to directly
- `--docker, -d`: Use virtual interface for a specified docker container (the container should be running)
- `--ip`: Source IP address to block traffic from (where 0.0.0.0 means all destinations)
- `--port, -p`: Port number to block traffic from (default 0 - means all ports)

>[!NOTE] About the `<dropped packets pct>` argument
> Khaos uses an XDP eBPF program to drop packets. XDP only processes ingress packets, so the percentage value
> specifies what percentage of incoming packets to drop based on the filtering criteria.
> For example, providing `50` will result in dropping approximately 50% of matching traffic on the interface.