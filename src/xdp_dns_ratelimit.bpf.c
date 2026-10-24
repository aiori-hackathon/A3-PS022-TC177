/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A3-PS022-TC177: eBPF/XDP Rate Limiter for DNS Query Floods
 *
 * Implements bounded UDP/53 packet parsing and dual-tier rate limiting:
 * 1. Per-source IP token bucket via BPF_MAP_TYPE_LRU_HASH
 * 2. Contention-free global token bucket via BPF_MAP_TYPE_PERCPU_ARRAY
 * 3. Lockless datapath metrics via BPF_MAP_TYPE_PERCPU_ARRAY
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../include/common.h"
#include "../include/dns_packet.h"

#define ETH_P_8021Q_VAL  0x8100
#define ETH_P_8021AD_VAL 0x88A8

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

/* Map 1: Per-source token buckets (LRU hash map automatically evicts inactive IPs) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_SRC_ENTRIES);
    __type(key, __u32); /* Source IPv4 (network byte order) */
    __type(value, struct token_bucket);
} src_buckets SEC(".maps");

/* Map 2: Per-CPU global token bucket */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct token_bucket);
} global_bucket SEC(".maps");

/* Map 3: Telemetry counters */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct datapath_stats);
} stats_map SEC(".maps");

/* Map 4: Runtime configuration populated by userspace loader */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} cfg_map SEC(".maps");

static __always_inline void refill_bucket(struct token_bucket *b, __u64 now, __u64 rate, __u64 burst)
{
    if (now <= b->last_update_ns)
        return;

    __u64 elapsed = now - b->last_update_ns;

    /* Cap elapsed window to 1 second to avoid 64-bit multiplication overflow */
    if (elapsed >= 1000000000ULL) {
        b->tokens = burst;
        b->last_update_ns = now;
        return;
    }

    __u64 added = (elapsed * rate) / 1000000000ULL;
    if (added > 0) {
        __u64 new_tokens = b->tokens + added;
        if (new_tokens > burst)
            new_tokens = burst;
        b->tokens = new_tokens;
        b->last_update_ns = now;
    }
}

SEC("xdp")
int xdp_dns_ratelimit_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 zero = 0;

    /* 1. Retrieve telemetry pointer */
    struct datapath_stats *stats = bpf_map_lookup_elem(&stats_map, &zero);
    if (stats)
        stats->rx_packets++;

    /* 2. Parse Ethernet (+ optional single 802.1Q/802.1AD VLAN header) */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 proto = eth->h_proto;
    void *cursor = (void *)(eth + 1);

    if (proto == bpf_htons(ETH_P_8021Q_VAL) || proto == bpf_htons(ETH_P_8021AD_VAL)) {
        struct vlan_hdr *vlan = cursor;
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;
        proto = vlan->h_vlan_encapsulated_proto;
        cursor = (void *)(vlan + 1);
    }

    /* Only process IPv4 traffic; pass non-IPv4 transparently */
    if (proto != bpf_htons(ETH_P_IP)) {
        if (stats)
            stats->non_dns_pass++;
        return XDP_PASS;
    }

    /* 3. Parse IPv4 Header */
    struct iphdr *iph = cursor;
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->ihl < 5)
        return XDP_PASS;

    void *ip_end = cursor + (iph->ihl * 4);
    if (ip_end > data_end)
        return XDP_PASS;

    /* Pass fragmented IP packets untouched */
    if (iph->frag_off & bpf_htons(0x1FFF | 0x2000)) {
        if (stats)
            stats->non_dns_pass++;
        return XDP_PASS;
    }

    /* Only filter UDP */
    if (iph->protocol != IPPROTO_UDP) {
        if (stats)
            stats->non_dns_pass++;
        return XDP_PASS;
    }

    /* 4. Parse UDP Header */
    struct udphdr *udph = ip_end;
    if ((void *)(udph + 1) > data_end)
        return XDP_PASS;

    /* Pass traffic not targeting DNS port 53 */
    if (udph->dest != bpf_htons(DNS_PORT)) {
        if (stats)
            stats->non_dns_pass++;
        return XDP_PASS;
    }

    /* 5. Bounded DNS Header validation */
    __u16 udp_len = bpf_ntohs(udph->len);
    if (udp_len < sizeof(struct udphdr) + MIN_DNS_LEN ||
        udp_len > sizeof(struct udphdr) + MAX_DNS_LEN) {
        if (stats)
            stats->parse_drop++;
        return XDP_DROP;
    }

    struct dnshdr *dnsh = (void *)(udph + 1);
    if ((void *)(dnsh + 1) > data_end) {
        if (stats)
            stats->parse_drop++;
        return XDP_DROP;
    }

    /* If QR bit is 1, this is a response, not an incoming query. Pass it through. */
    if (dnsh->flags1 & DNS_QR_MASK) {
        if (stats)
            stats->pass++;
        return XDP_PASS;
    }

    /* 6. Fetch rate limiting configuration */
    struct config *cfg = bpf_map_lookup_elem(&cfg_map, &zero);
    __u64 src_rate = (cfg && cfg->src_rate) ? cfg->src_rate : DEFAULT_SRC_RATE;
    __u64 src_burst = (cfg && cfg->src_burst) ? cfg->src_burst : DEFAULT_SRC_BURST;
    __u64 glob_rate = (cfg && cfg->global_rate) ? cfg->global_rate : DEFAULT_GLOBAL_RATE;
    __u64 glob_burst = (cfg && cfg->global_burst) ? cfg->global_burst : DEFAULT_GLOBAL_BURST;
    __u32 cpus = (cfg && cfg->cpu_count) ? cfg->cpu_count : 1;

    __u64 glob_rate_cpu = glob_rate / cpus;
    if (glob_rate_cpu < 1)
        glob_rate_cpu = 1;

    __u64 glob_burst_cpu = glob_burst / cpus;
    if (glob_burst_cpu < 1)
        glob_burst_cpu = 1;

    __u64 now = bpf_ktime_get_ns();

    /* 7. Per-source rate check (LRU hash map) */
    __u32 src_ip = iph->saddr;
    struct token_bucket *sb = bpf_map_lookup_elem(&src_buckets, &src_ip);
    if (!sb) {
        struct token_bucket init_b = {
            .last_update_ns = now,
            .tokens = src_burst,
        };
        bpf_map_update_elem(&src_buckets, &src_ip, &init_b, BPF_ANY);
        sb = bpf_map_lookup_elem(&src_buckets, &src_ip);
    }

    if (sb) {
        refill_bucket(sb, now, src_rate, src_burst);
        if (sb->tokens < 1) {
            if (stats)
                stats->src_drop++;
            return XDP_DROP;
        }
    }

    /* 8. Global rate check (per-CPU array for zero core-contention) */
    struct token_bucket *gb = bpf_map_lookup_elem(&global_bucket, &zero);
    if (gb) {
        if (gb->last_update_ns == 0) {
            gb->last_update_ns = now;
            gb->tokens = glob_burst_cpu;
        } else {
            refill_bucket(gb, now, glob_rate_cpu, glob_burst_cpu);
        }

        if (gb->tokens < 1) {
            if (stats)
                stats->glob_drop++;
            return XDP_DROP;
        }
    }

    /* 9. Admitted: consume token from both buckets */
    if (sb && sb->tokens >= 1)
        sb->tokens--;
    if (gb && gb->tokens >= 1)
        gb->tokens--;

    if (stats)
        stats->pass++;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
