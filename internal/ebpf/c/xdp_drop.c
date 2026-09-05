// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Shinkiro High-Performance eBPF/XDP Ingress Packet Drop Filter
// Intercepts and drops malicious attacker traffic at driver/NIC level before SKB allocation

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

#define SEC(NAME) __attribute__((section(NAME), used))

// BPF Map storing blacklisted IPv4 addresses (32-bit keys)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64); // packet drop counter
    __uint(max_entries, 65536);
} blacklist_map SEC(".maps");

SEC("xdp")
int xdp_shinkiro_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // Check if source IP exists in Shinkiro blacklist hash map
    __u64 *drop_count = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (drop_count) {
        __sync_fetch_and_add(drop_count, 1);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
