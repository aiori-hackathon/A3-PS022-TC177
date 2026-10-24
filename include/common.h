#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>

#define MAX_DNS_LEN 512
#define MIN_DNS_LEN 12
#define DNS_PORT 53

/* Map limits */
#define MAX_SRC_ENTRIES 65536

/* Rate limit defaults */
#define DEFAULT_SRC_RATE 100ULL        /* packets / second per source */
#define DEFAULT_SRC_BURST 50ULL        /* maximum burst tokens per source */
#define DEFAULT_GLOBAL_RATE 50000ULL   /* packets / second global aggregate */
#define DEFAULT_GLOBAL_BURST 10000ULL  /* maximum burst aggregate */

/* Token bucket state */
struct token_bucket {
    __u64 last_update_ns;
    __u64 tokens;
};

/* Runtime configuration pushed from userspace */
struct config {
    __u64 src_rate;         /* tokens per second */
    __u64 src_burst;        /* max tokens */
    __u64 global_rate;      /* tokens per second (total) */
    __u64 global_burst;     /* max tokens (total) */
    __u32 cpu_count;
    __u32 enabled;
};

/* Telemetry statistics (per-CPU) */
struct datapath_stats {
    __u64 rx_packets;
    __u64 non_dns_pass;
    __u64 pass;
    __u64 src_drop;
    __u64 glob_drop;
    __u64 parse_drop;
};

#endif /* __COMMON_H */
