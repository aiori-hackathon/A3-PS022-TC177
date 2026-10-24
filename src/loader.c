/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A3-PS022-TC177: Userspace Loader & Metrics Monitor
 *
 * Loads, configures, and monitors the XDP DNS rate limiting eBPF program.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../include/common.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "Options:\n"
        "  -i, --interface <ifname>  Network interface name (required)\n"
        "  -m, --mode <mode>         XDP mode: auto, drv, generic (default: auto)\n"
        "  -s, --src-rate <pps>      Per-source IP rate limit (default: %llu pps)\n"
        "  -b, --src-burst <tokens>  Per-source token burst (default: %llu)\n"
        "  -g, --global-rate <pps>   Global total rate limit (default: %llu pps)\n"
        "  -G, --global-burst <tok>  Global token burst (default: %llu)\n"
        "  -p, --poll <interval_sec> Telemetry poll interval in seconds (default: 1, 0 to exit after load)\n"
        "  -j, --json                Output metrics as JSON stream\n"
        "  -d, --detach              Detach existing XDP filter from interface and exit\n"
        "  -h, --help                Show this help message\n",
        prog,
        (unsigned long long)DEFAULT_SRC_RATE,
        (unsigned long long)DEFAULT_SRC_BURST,
        (unsigned long long)DEFAULT_GLOBAL_RATE,
        (unsigned long long)DEFAULT_GLOBAL_BURST);
}

int main(int argc, char **argv)
{
    char *ifname = NULL;
    char *mode_str = "auto";
    const char *bpf_obj_path = "src/xdp_dns_ratelimit.bpf.o";
    int detach_only = 0;
    int json_output = 0;
    int poll_interval = 1;

    struct config cfg = {
        .src_rate = DEFAULT_SRC_RATE,
        .src_burst = DEFAULT_SRC_BURST,
        .global_rate = DEFAULT_GLOBAL_RATE,
        .global_burst = DEFAULT_GLOBAL_BURST,
        .cpu_count = 1,
        .enabled = 1,
    };

    static struct option long_options[] = {
        {"interface",    required_argument, 0, 'i'},
        {"mode",         required_argument, 0, 'm'},
        {"src-rate",     required_argument, 0, 's'},
        {"src-burst",    required_argument, 0, 'b'},
        {"global-rate",  required_argument, 0, 'g'},
        {"global-burst", required_argument, 0, 'G'},
        {"poll",         required_argument, 0, 'p'},
        {"json",         no_argument,       0, 'j'},
        {"detach",       no_argument,       0, 'd'},
        {"help",         no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:m:s:b:g:G:p:jdh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            ifname = strdup(optarg);
            break;
        case 'm':
            mode_str = optarg;
            break;
        case 's':
            cfg.src_rate = strtoull(optarg, NULL, 10);
            break;
        case 'b':
            cfg.src_burst = strtoull(optarg, NULL, 10);
            break;
        case 'g':
            cfg.global_rate = strtoull(optarg, NULL, 10);
            break;
        case 'G':
            cfg.global_burst = strtoull(optarg, NULL, 10);
            break;
        case 'p':
            poll_interval = atoi(optarg);
            break;
        case 'j':
            json_output = 1;
            break;
        case 'd':
            detach_only = 1;
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    if (!ifname) {
        fprintf(stderr, "Error: Network interface (-i, --interface) is required.\n");
        print_usage(argv[0]);
        return 1;
    }

    unsigned int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Error: Interface '%s' not found (%s)\n", ifname, strerror(errno));
        free(ifname);
        return 1;
    }

    /* Handle Detach */
    if (detach_only) {
        int ret = bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
        if (ret < 0) {
            ret = bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
        }
        if (ret < 0) {
            fprintf(stderr, "Failed to detach XDP program from %s: %s\n", ifname, strerror(-ret));
            free(ifname);
            return 1;
        }
        printf("Successfully detached XDP program from %s (ifindex %u).\n", ifname, ifindex);
        free(ifname);
        return 0;
    }

    /* Open BPF Object */
    struct bpf_object *obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error opening BPF object '%s': %s\n", bpf_obj_path, strerror(errno));
        free(ifname);
        return 1;
    }

    /* Load into Kernel */
    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error loading BPF object: %s\n", strerror(-err));
        bpf_object__close(obj);
        free(ifname);
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_dns_ratelimit_prog");
    if (!prog) {
        fprintf(stderr, "Error finding program 'xdp_dns_ratelimit_prog'\n");
        bpf_object__close(obj);
        free(ifname);
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Error acquiring program file descriptor\n");
        bpf_object__close(obj);
        free(ifname);
        return 1;
    }

    /* Configure XDP Attach flags */
    __u32 xdp_flags = 0;
    int attached = 0;

    if (strcmp(mode_str, "drv") == 0) {
        xdp_flags = XDP_FLAGS_DRV_MODE;
        err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
        if (err < 0) {
            fprintf(stderr, "Error attaching native driver XDP: %s\n", strerror(-err));
            bpf_object__close(obj);
            free(ifname);
            return 1;
        }
        attached = 1;
        printf("Attached XDP filter to %s in NATIVE (drv) mode.\n", ifname);
    } else if (strcmp(mode_str, "generic") == 0) {
        xdp_flags = XDP_FLAGS_SKB_MODE;
        err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
        if (err < 0) {
            fprintf(stderr, "Error attaching generic XDP: %s\n", strerror(-err));
            bpf_object__close(obj);
            free(ifname);
            return 1;
        }
        attached = 1;
        printf("Attached XDP filter to %s in GENERIC (skb) mode.\n", ifname);
    } else {
        /* Auto mode: Try native first, fall back to generic */
        xdp_flags = XDP_FLAGS_DRV_MODE;
        err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
        if (err >= 0) {
            attached = 1;
            printf("Attached XDP filter to %s in NATIVE (drv) mode.\n", ifname);
        } else {
            xdp_flags = XDP_FLAGS_SKB_MODE;
            err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
            if (err >= 0) {
                attached = 1;
                printf("Native mode unsupported; attached XDP filter to %s in GENERIC (skb) mode.\n", ifname);
            } else {
                fprintf(stderr, "Failed to attach XDP to %s (drv and skb modes failed): %s\n", ifname, strerror(-err));
                bpf_object__close(obj);
                free(ifname);
                return 1;
            }
        }
    }

    /* Populate Configuration Map */
    int nr_cpus = libbpf_num_possible_cpus();
    if (nr_cpus <= 0)
        nr_cpus = 1;
    cfg.cpu_count = nr_cpus;

    struct bpf_map *cfg_map = bpf_object__find_map_by_name(obj, "cfg_map");
    if (cfg_map) {
        __u32 key = 0;
        int map_fd = bpf_map__fd(cfg_map);
        if (bpf_map_update_elem(map_fd, &key, &cfg, BPF_ANY) < 0) {
            fprintf(stderr, "Warning: Failed to update cfg_map: %s\n", strerror(errno));
        } else {
            printf("Config applied: src_rate=%llu/s (burst=%llu), global_rate=%llu/s (burst=%llu), cpus=%u\n",
                (unsigned long long)cfg.src_rate,
                (unsigned long long)cfg.src_burst,
                (unsigned long long)cfg.global_rate,
                (unsigned long long)cfg.global_burst,
                cfg.cpu_count);
        }
    }

    if (poll_interval <= 0) {
        printf("Filter active. Exiting loader (program remains attached).\n");
        free(ifname);
        return 0;
    }

    /* Setup Signal Handling */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct bpf_map *stats_map = bpf_object__find_map_by_name(obj, "stats_map");
    int stats_fd = stats_map ? bpf_map__fd(stats_map) : -1;
    if (stats_fd < 0) {
        fprintf(stderr, "Warning: Unable to open stats_map\n");
    }

    struct datapath_stats *cpu_stats = calloc(nr_cpus, sizeof(struct datapath_stats));
    if (!cpu_stats) {
        fprintf(stderr, "Memory allocation error for stats buffers\n");
        goto cleanup;
    }

    struct datapath_stats prev_total = {0};

    if (!json_output) {
        printf("\n%-10s %-12s %-12s %-14s %-14s %-12s %-12s\n",
               "Time", "RX (pps)", "Pass (pps)", "SrcDrop(pps)", "GlobDrop(pps)", "ParseDrop", "NonDNS");
        printf("----------------------------------------------------------------------------------------\n");
    }

    while (!exiting) {
        sleep(poll_interval);

        if (stats_fd >= 0) {
            __u32 key = 0;
            if (bpf_map_lookup_elem(stats_fd, &key, cpu_stats) == 0) {
                struct datapath_stats cur_total = {0};
                for (int c = 0; c < nr_cpus; c++) {
                    cur_total.rx_packets += cpu_stats[c].rx_packets;
                    cur_total.pass += cpu_stats[c].pass;
                    cur_total.src_drop += cpu_stats[c].src_drop;
                    cur_total.glob_drop += cpu_stats[c].glob_drop;
                    cur_total.parse_drop += cpu_stats[c].parse_drop;
                    cur_total.non_dns_pass += cpu_stats[c].non_dns_pass;
                }

                __u64 rx_pps = (cur_total.rx_packets - prev_total.rx_packets) / poll_interval;
                __u64 pass_pps = (cur_total.pass - prev_total.pass) / poll_interval;
                __u64 src_drop_pps = (cur_total.src_drop - prev_total.src_drop) / poll_interval;
                __u64 glob_drop_pps = (cur_total.glob_drop - prev_total.glob_drop) / poll_interval;
                __u64 parse_drop_pps = (cur_total.parse_drop - prev_total.parse_drop) / poll_interval;
                __u64 nondns_pps = (cur_total.non_dns_pass - prev_total.non_dns_pass) / poll_interval;

                if (json_output) {
                    printf("{\"rx_pps\":%llu,\"pass_pps\":%llu,\"src_drop_pps\":%llu,\"glob_drop_pps\":%llu,\"parse_drop_pps\":%llu,\"total_rx\":%llu,\"total_pass\":%llu,\"total_src_drop\":%llu,\"total_glob_drop\":%llu}\n",
                        (unsigned long long)rx_pps,
                        (unsigned long long)pass_pps,
                        (unsigned long long)src_drop_pps,
                        (unsigned long long)glob_drop_pps,
                        (unsigned long long)parse_drop_pps,
                        (unsigned long long)cur_total.rx_packets,
                        (unsigned long long)cur_total.pass,
                        (unsigned long long)cur_total.src_drop,
                        (unsigned long long)cur_total.glob_drop);
                    fflush(stdout);
                } else {
                    printf("%-10s %-12llu %-12llu %-14llu %-14llu %-12llu %-12llu\n",
                           "now",
                           (unsigned long long)rx_pps,
                           (unsigned long long)pass_pps,
                           (unsigned long long)src_drop_pps,
                           (unsigned long long)glob_drop_pps,
                           (unsigned long long)parse_drop_pps,
                           (unsigned long long)nondns_pps);
                    fflush(stdout);
                }

                prev_total = cur_total;
            }
        }
    }

    printf("\nReceived exit signal. Detaching XDP filter...\n");

cleanup:
    if (attached) {
        bpf_xdp_detach(ifindex, xdp_flags, NULL);
    }
    if (cpu_stats)
        free(cpu_stats);
    bpf_object__close(obj);
    free(ifname);
    printf("Detached cleanly. Done.\n");
    return 0;
}
