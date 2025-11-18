#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// I hate C. Period.
#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define TYPE_ENTER 1
#define TYPE_DROP 2
#define TYPE_PASS 3

struct perf_trace_event {
	__u64 timestamp; // time elapsed since boot, excluding suspend time. see https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html
	__u32 processing_time_ns;
	__u8 type;
	__u16 src_port;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1024);
} output_map SEC(".maps");

volatile const __u16 target_port;
volatile const __u32 drop_pct;

SEC("xdp")
int packet_drop(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    /* Verify ethernet header present */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 src_port = 0;
    __u16 h_proto = eth->h_proto;
    if (h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* IP header starts after ethernet header */
    unsigned char *ip_base = (unsigned char *)eth + sizeof(*eth);
    struct iphdr *iph = (struct iphdr *)ip_base;

    /* First check that minimum IP header fits */
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    /* Read IHL and validate (must be at least 5) */
    __u8 ihl = iph->ihl;
    if (ihl < 5)
        return XDP_PASS;

    __u32 ip_hdr_len = (__u32)ihl * 4u;

    /* Now make sure full IP header is within packet */
    if (ip_base + ip_hdr_len > (unsigned char *)data_end)
        return XDP_PASS;

    /* Now parse transport headers safely depending on protocol */
    if (iph->protocol == IPPROTO_UDP) {
        unsigned char *udp_base = ip_base + ip_hdr_len;
        /* Ensure UDP header fits */
        if (udp_base + sizeof(struct udphdr) > (unsigned char *)data_end)
            return XDP_PASS;

        struct udphdr *udph = (struct udphdr *)udp_base;
        src_port = bpf_ntohs(udph->source);
    } else if (iph->protocol == IPPROTO_TCP) {
        unsigned char *tcp_base = ip_base + ip_hdr_len;
        /* Need at least fixed TCP header to read source/dest ports */
        if (tcp_base + sizeof(struct tcphdr) > (unsigned char *)data_end)
            return XDP_PASS;

        struct tcphdr *tcph = (struct tcphdr *)tcp_base;
        src_port = bpf_ntohs(tcph->source);
    } else {
        return XDP_PASS;
    }

    /* Block/allow logic */
    if (src_port != target_port) {
        return XDP_PASS;
    }

    /* Logging and perf events — unchanged, but ensure proper types/initialization */
    bpf_printk("src_port=%d, match target_port=%d", src_port, (int)target_port);

    struct perf_trace_event e = {};
    e.timestamp = bpf_ktime_get_ns();
    e.type = TYPE_ENTER;
    e.processing_time_ns = 0;
    e.src_port = src_port;
    bpf_perf_event_output(ctx, &output_map, BPF_F_CURRENT_CPU, &e, sizeof(e));

    __u32 rnd = bpf_get_prandom_u32() % 100;
    if (rnd < drop_pct) {
        e.type = TYPE_DROP;
        __u64 ts = bpf_ktime_get_ns();
        e.processing_time_ns = ts - e.timestamp;
        e.timestamp = ts;
        bpf_perf_event_output(ctx, &output_map, BPF_F_CURRENT_CPU, &e, sizeof(e));
        return XDP_DROP;
    }

    e.type = TYPE_PASS;
    {
        __u64 ts = bpf_ktime_get_ns();
        e.processing_time_ns = ts - e.timestamp;
        e.timestamp = ts;
    }
    bpf_perf_event_output(ctx, &output_map, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
