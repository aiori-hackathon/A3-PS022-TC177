#!/usr/bin/env python3
"""
A3-PS022-TC177: Legitimate DNS Query Prober
Sends DNS queries at a fixed legitimate rate (e.g. 20-50 QPS) to evaluate
service availability, response latency, and packet loss under flood conditions.
"""

import argparse
import json
import os
import random
import select
import socket
import struct
import sys
import time

def build_dns_query(domain: str, tx_id: int) -> bytes:
    # Header: ID, Flags (RD=1), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    
    # Question: QNAME (labels)
    qname = b""
    for part in domain.split("."):
        if part:
            b_part = part.encode("ascii")
            qname += struct.pack("!B", len(b_part)) + b_part
    qname += b"\x00"
    
    # QTYPE=1 (A), QCLASS=1 (IN)
    qtail = struct.pack("!HH", 1, 1)
    return header + qname + qtail

def parse_dns_response(data: bytes, expected_tx_id: int) -> bool:
    if len(data) < 12:
        return False
    tx_id, flags = struct.unpack("!HH", data[:4])
    if tx_id != expected_tx_id:
        return False
    is_response = (flags & 0x8000) != 0
    return is_response

def run_prober(target_ip: str, target_port: int, bind_ip: str, qps: float, duration: int, domain: str, json_path: str = None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    if bind_ip:
        try:
            sock.bind((bind_ip, 0))
        except Exception as e:
            print(f"[Prober] Warning: bind to {bind_ip} failed ({e}), using default route", file=sys.stderr)

    interval = 1.0 / max(1.0, qps)
    end_time = time.time() + duration if duration > 0 else float("inf")
    
    queries_sent = 0
    replies_received = 0
    timeouts = 0
    latencies_ms = []

    print(f"[Prober] Probing {target_ip}:{target_port} at {qps} QPS for {duration}s (querying '{domain}')...")

    try:
        while time.time() < end_time:
            loop_start = time.time()
            tx_id = random.randint(1, 65535)
            packet = build_dns_query(domain, tx_id)
            
            send_ts = time.time()
            try:
                sock.sendto(packet, (target_ip, target_port))
                queries_sent += 1
            except Exception as e:
                timeouts += 1

            # Wait for response within 500ms timeout
            timeout_sec = 0.5
            r, _, _ = select.select([sock], [], [], timeout_sec)
            if r:
                try:
                    data, _ = sock.recvfrom(1024)
                    recv_ts = time.time()
                    if parse_dns_response(data, tx_id):
                        replies_received += 1
                        rtt_ms = (recv_ts - send_ts) * 1000.0
                        latencies_ms.append(rtt_ms)
                    else:
                        timeouts += 1
                except Exception:
                    timeouts += 1
            else:
                timeouts += 1

            # Maintain constant pacing
            elapsed = time.time() - loop_start
            sleep_time = interval - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)

    except KeyboardInterrupt:
        print("\n[Prober] Interrupted by user.")
    finally:
        sock.close()

    success_rate = (replies_received / queries_sent * 100.0) if queries_sent > 0 else 0.0
    latencies_sorted = sorted(latencies_ms)
    
    def percentile(p):
        if not latencies_sorted:
            return 0.0
        idx = int(len(latencies_sorted) * p)
        return latencies_sorted[min(idx, len(latencies_sorted) - 1)]

    stats = {
        "queries_sent": queries_sent,
        "replies_received": replies_received,
        "timeouts": timeouts,
        "success_rate_pct": round(success_rate, 2),
        "latency_min_ms": round(latencies_sorted[0], 3) if latencies_sorted else 0.0,
        "latency_avg_ms": round(sum(latencies_sorted) / len(latencies_sorted), 3) if latencies_sorted else 0.0,
        "latency_p50_ms": round(percentile(0.50), 3),
        "latency_p95_ms": round(percentile(0.95), 3),
        "latency_p99_ms": round(percentile(0.99), 3),
        "latency_max_ms": round(latencies_sorted[-1], 3) if latencies_sorted else 0.0,
    }

    print("\n--- Legitimate Prober Summary ---")
    print(f"  Queries Sent:     {stats['queries_sent']}")
    print(f"  Replies Received: {stats['replies_received']}")
    print(f"  Timeouts/Drops:   {stats['timeouts']}")
    print(f"  Success Rate:     {stats['success_rate_pct']}%")
    if latencies_sorted:
        print(f"  Latency (ms):     min={stats['latency_min_ms']} | avg={stats['latency_avg_ms']} | p95={stats['latency_p95_ms']} | max={stats['latency_max_ms']}")
    print("---------------------------------")

    if json_path:
        with open(json_path, "w") as f:
            json.dump(stats, f, indent=2)
        print(f"[Prober] Metrics written to {json_path}")

    return stats

def main():
    parser = argparse.ArgumentParser(description="Legitimate DNS Query Prober")
    parser.add_argument("-t", "--target", default="10.0.0.1", help="Target DNS Server IP")
    parser.add_argument("-p", "--port", type=int, default=53, help="Target UDP port")
    parser.add_argument("-b", "--bind", default="", help="Client source IP to bind")
    parser.add_argument("-q", "--qps", type=float, default=20.0, help="Queries per second")
    parser.add_argument("-d", "--duration", type=int, default=10, help="Test duration in seconds")
    parser.add_argument("-n", "--domain", default="legit.lab.local", help="Domain to query")
    parser.add_argument("-j", "--json", default=None, help="Path to write JSON output")
    args = parser.parse_args()

    run_prober(args.target, args.port, args.bind, args.qps, args.duration, args.domain, args.json)

if __name__ == "__main__":
    main()
