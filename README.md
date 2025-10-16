# khaos
A teeny-tiny program that allows you to drop network packets 
 for a specified process.

## Requirements
- Linux kernel version 5.7 or later, for `bpf_link` support
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
sudo make run <ifname> <pid> <drop_percent=50>

# or without make
sudo ./build/khaos <ifname> <pid> <drop_percent=50>
```

## TODO
- [ ] Allow to specify which PID to drop packets for. 
 Currently, it just drops half of the packets on the whole iface.
- [ ] Allow to specify dropped packets percentage