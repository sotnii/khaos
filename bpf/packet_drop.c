#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define TYPE_ENTER 1
#define TYPE_DROP 2
#define TYPE_PASS 3

struct perf_trace_event {
    __u8  type;
    __u32 src_ip;
    __u16 src_port;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
} output_map SEC(".maps");

volatile const __u32 target_src_ip;     // network byte order!
volatile const __u16 target_src_port;
volatile const __u32 drop_pct;

SEC("xdp")
int packet_drop(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)eth + sizeof(*eth);

    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u8 ihl = iph->ihl;
    if (ihl < 5)
        return XDP_PASS;

    __u32 ip_hdr_len = ihl * 4;
    if ((void *)iph + ip_hdr_len > data_end)
        return XDP_PASS;

    __u16 src_port = 0;
    __u16 dst_port = 0;

    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + ip_hdr_len;
        if ((void *)(udph + 1) > data_end)
            return XDP_PASS;
        src_port = bpf_ntohs(udph->source);
        dst_port = bpf_ntohs(udph->dest);

    } else if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + ip_hdr_len;
        if ((void *)(tcph + 1) > data_end)
            return XDP_PASS;
        src_port = bpf_ntohs(tcph->source);
        dst_port = bpf_ntohs(tcph->dest);

    } else {
        return XDP_PASS;
    }

    // Convert IPs into readable form (byte by byte)
    __u8 *s = (__u8 *)&iph->saddr;
    __u8 *d = (__u8 *)&iph->daddr;

    // Human-readable log
    bpf_printk("Traffic %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
        s[0], s[1], s[2], s[3], src_port,
        d[0], d[1], d[2], d[3], dst_port);

    // FILTER: if target_src_ip is 0, means we should match any daddr
    if (target_src_ip != 0 && iph->saddr != target_src_ip)
        return XDP_PASS;

    if (target_src_port != 0 && src_port != target_src_port) {
        return XDP_PASS;
    }

    bpf_printk("MATCH %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
        s[0], s[1], s[2], s[3], src_port,
        d[0], d[1], d[2], d[3], dst_port);

    struct perf_trace_event e = {};
    e.type = TYPE_ENTER;
    e.src_ip = iph->saddr;
    e.src_port = src_port;
    bpf_perf_event_output(ctx, &output_map, BPF_F_CURRENT_CPU, &e, sizeof(e));

    if (bpf_get_prandom_u32() % 100 < drop_pct) {
        e.type = TYPE_DROP;
        __u64 ts = bpf_ktime_get_ns();
        bpf_perf_event_output(ctx, &output_map, BPF_F_CURRENT_CPU, &e, sizeof(e));
        return XDP_DROP;
    }

    e.type = TYPE_PASS;
    bpf_perf_event_output(ctx, &output_map, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
