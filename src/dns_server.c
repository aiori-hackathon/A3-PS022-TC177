/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A3-PS022-TC177: High-Performance UDP DNS Test Server
 *
 * Listens on UDP port 53, parses standard queries, and responds with synthetic
 * A records. Logs real-time QPS for legitimate and benchmark evaluation.
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../include/dns_packet.h"

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "Options:\n"
        "  -l, --listen <ip>     Listen IP address (default: 0.0.0.0)\n"
        "  -p, --port <port>     UDP port (default: 53)\n"
        "  -r, --response <ip>   Resolved A record IP to reply with (default: 10.0.0.1)\n"
        "  -q, --quiet           Suppress periodic throughput logs\n"
        "  -h, --help            Show this help message\n",
        prog);
}

int main(int argc, char **argv)
{
    char listen_ip[64] = "0.0.0.0";
    char reply_ip_str[64] = "10.0.0.1";
    int port = 53;
    int quiet = 0;

    static struct option long_options[] = {
        {"listen",   required_argument, 0, 'l'},
        {"port",     required_argument, 0, 'p'},
        {"response", required_argument, 0, 'r'},
        {"quiet",    no_argument,       0, 'q'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "l:p:r:qh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'l':
            strncpy(listen_ip, optarg, sizeof(listen_ip) - 1);
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'r':
            strncpy(reply_ip_str, optarg, sizeof(reply_ip_str) - 1);
            break;
        case 'q':
            quiet = 1;
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    struct in_addr reply_addr;
    if (inet_pton(AF_INET, reply_ip_str, &reply_addr) != 1) {
        fprintf(stderr, "Invalid reply IP address: %s\n", reply_ip_str);
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    /* Expand socket receive buffer for high packet volume */
    int rcvbuf = 16 * 1024 * 1024;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    if (inet_pton(AF_INET, listen_ip, &servaddr.sin_addr) != 1) {
        fprintf(stderr, "Invalid listen IP address: %s\n", listen_ip);
        close(sockfd);
        return 1;
    }

    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind");
        close(sockfd);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("DNS Server listening on %s:%d (resolving queries to %s)\n", listen_ip, port, reply_ip_str);

    unsigned char buf[1024];
    unsigned char resp_buf[1024];
    struct sockaddr_in cliaddr;
    socklen_t clilen = sizeof(cliaddr);

    unsigned long long total_queries = 0;
    unsigned long long total_replies = 0;
    unsigned long long queries_last_sec = 0;
    time_t last_log = time(NULL);

    while (running) {
        ssize_t n = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&cliaddr, &clilen);
        if (n < 0) {
            if (errno == EINTR) break;
            perror("recvfrom");
            continue;
        }

        total_queries++;
        queries_last_sec++;

        if (n < (ssize_t)sizeof(struct dnshdr)) {
            continue; /* Ignore truncated packets */
        }

        memcpy(resp_buf, buf, n);
        struct dnshdr *resp_hdr = (struct dnshdr *)resp_buf;

        /* Set QR=1 (response), AA=1, RA=1, RCODE=0 */
        resp_hdr->flags1 = 0x81; /* QR=1, RD=1 */
        resp_hdr->flags2 = 0x80; /* RA=1, RCODE=0 */
        resp_hdr->ancount = htons(1);

        size_t resp_len = n;

        /* Append DNS Answer section: Pointer to QNAME at offset 0x0c (0xc00c) */
        resp_buf[resp_len++] = 0xc0;
        resp_buf[resp_len++] = 0x0c;

        /* Type A (1) */
        resp_buf[resp_len++] = 0x00;
        resp_buf[resp_len++] = 0x01;

        /* Class IN (1) */
        resp_buf[resp_len++] = 0x00;
        resp_buf[resp_len++] = 0x01;

        /* TTL (300 seconds) */
        resp_buf[resp_len++] = 0x00;
        resp_buf[resp_len++] = 0x00;
        resp_buf[resp_len++] = 0x01;
        resp_buf[resp_len++] = 0x2c;

        /* RDLENGTH (4 bytes for IPv4) */
        resp_buf[resp_len++] = 0x00;
        resp_buf[resp_len++] = 0x04;

        /* RDATA */
        memcpy(&resp_buf[resp_len], &reply_addr.s_addr, 4);
        resp_len += 4;

        sendto(sockfd, resp_buf, resp_len, 0, (struct sockaddr *)&cliaddr, clilen);
        total_replies++;

        time_t now = time(NULL);
        if (now != last_log) {
            if (!quiet) {
                printf("[dns_server] QPS: %llu | Total Queries: %llu | Replies: %llu\n",
                       queries_last_sec, total_queries, total_replies);
                fflush(stdout);
            }
            queries_last_sec = 0;
            last_log = now;
        }
    }

    printf("\nShutting down DNS server. Handled %llu queries, replied %llu.\n", total_queries, total_replies);
    close(sockfd);
    return 0;
}
