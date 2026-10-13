# A3-PS022-TC177: eBPF/XDP Rate Limiting for DNS Query Floods in a Lab

**Hackathon:** AIORI Hackathon 3 (Category: Cybersecurity)

**Problem Statement:** PS-022

**Team:** TaskForce141

## Team

| Name | Email |
|------|-------|
| Naimish Pandey | naimishpandey82@gmail.com |
| Naitik Pandey | naitikpandey18@gmail.com |
| Dr. Atul Srivastava | asrivastava5@lko.amity.edu |

## Intro Video

https://youtu.be/khWHJyRnlII

## Overview

High-volume UDP DNS query floods saturate Linux servers because the kernel spends CPU allocating socket buffers before packets reach user space. This project builds an XDP (eXpress Data Path) filter that parses UDP/DNS packets in a bounded way and applies per-source and global rate limits at the network driver, before kernel memory allocation.

We benchmark it against **no-filter** and **nftables** baselines on one Linux host pair in a controlled lab, using three synthetic flood patterns, and measure throughput, CPU usage, packet drops and legitimate-query success.

## Approach

- **Bounded parsing:** Ethernet/IP/UDP headers, port 53, length checks and the 12-byte DNS header only; no full DNS parsing.
- **Per-source limit:** token bucket per source IP in an LRU hash map.
- **Global limit:** per-CPU token buckets.
- **Counters:** per-CPU pass / drop statistics.
- **Flood patterns:** (A) single-source, (B) multi-source, (C) pulsed with random synthetic labels.
- **Configurations compared:** no-filter, nftables, XDP.

## Repository Contents

| File | Description |
|------|-------------|
| `Proposed-structure-hackathon.pdf` | Presentation following the AIORI proposed structure |
| `README.md` | This file |

The XDP program, traffic-generation harness, baseline configs and results will be added here as the project progresses.

## Scope and Safety

Isolated lab only. No public flood testing, no full DNS semantic parsing, no universal PRSD detection, and no claim of eliminating reflection attacks.

## References

1. T. Hoiland-Jorgensen et al., "The eXpress Data Path: Fast Programmable Packet Processing in the Operating System Kernel," ACM CoNEXT 2018.
2. Linux kernel BPF documentation: https://docs.kernel.org/bpf/
3. RFC 1035, Domain Names - Implementation and Specification.
4. RFC 5358, Preventing Use of Recursive Nameservers in Reflector Attacks.
