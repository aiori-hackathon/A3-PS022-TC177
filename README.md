# A3-PS022-TC177: eBPF/XDP Rate Limiting for DNS Query Floods in a Lab

**Hackathon:** AIORI Hackathon 3 (Category: Cybersecurity)  
**Problem Statement:** PS-022  
**Team:** TaskForce141  

## Team

| Name | Email | Role |
|------|-------|------|
| Naimish Pandey | naimishpandey82@gmail.com | Systems & eBPF Engineering |
| Naitik Pandey | naitikpandey18@gmail.com | Traffic Generation & Benchmarking |
| Dr. Atul Srivastava | asrivastava5@lko.amity.edu | Faculty Mentor |

## Intro Video

https://youtu.be/khWHJyRnlII

---

## 1. Executive Summary

Volumetric UDP DNS query floods exhaust Linux servers because the operating system kernel spends excessive CPU cycles allocating `sk_buff` socket buffers and traversing the netfilter/IP/UDP stack before packets ever reach user space. At high packet rates (hundreds of thousands to millions of packets per second), CPU cores saturate in `softirq` context, starving legitimate DNS queries sharing the same receive queues and socket backlogs.

While firewall tools such as `nftables` can rate-limit traffic, their hooks execute **after** `sk_buff` allocation. They protect userspace applications from receiving excess packets, but fail to eliminate the per-packet kernel allocation overhead.

This project implements an **eBPF/XDP (eXpress Data Path)** DNS rate-limiting filter that executes at the network driver's earliest receive hook:
1. **Bounded Parsing:** Parses Ethernet, VLAN (802.1Q/802.1AD), IPv4, and UDP port 53 with strict length bounds (12..512 bytes) and inspects only the RFC 1035 12-byte DNS header (skipping response packets where `QR=1`).
2. **Dual-Tier Token Bucket Rate Limiting:**
   - **Per-Source IP Limiting:** Dynamic token bucket stored in a bounded `BPF_MAP_TYPE_LRU_HASH` map, evicting cold entries automatically.
   - **Global Aggregate Limiting:** Contention-free per-CPU token bucket stored in a `BPF_MAP_TYPE_PERCPU_ARRAY` map, preventing CPU cache-line bouncing.
3. **Lockless Telemetry:** Real-time datapath statistics tracking packets received, admitted, per-source drops, global drops, and malformed packet drops via per-CPU arrays.
4. **Lab Evaluation:** Benchmarked against **no-filter** and **nftables** baselines across three synthetic flood patterns:
   - **Pattern A:** Single-source flood.
   - **Pattern B:** Multi-source spoofed flood (100+ rotating sources).
   - **Pattern C:** Pulsed on/off flood with random synthetic domain labels (PRSD / Water Torture simulation).

---

## 2. Architecture & Data Flow

```
                      +-------------------------------------------------+
                      |              Client Host / ns_cli               |
                      |                                                 |
                      |   [Legitimate Prober]      [Flood Generator]    |
                      |    (20 QPS, legit IP)    (Patterns A / B / C)   |
                      +-------------------+-----------------+-----------+
                                          |                 |
                                          |   UDP Port 53   |
                                          +--------+--------+
                                                   |
                                                   v
                      +-------------------------------------------------+
                      |              Server Host / ns_srv               |
                      |                                                 |
                      |               +-----------------+               |
                      |               |   veth_srv RX   |               |
                      |               +--------+--------+               |
                      |                        |                        |
                      |                        v                        |
                      |             [ XDP Ingress Hook ]                |
                      |                        |                        |
                      |   +--------------------+--------------------+   |
                      |   | Step 1: Bounded Header Validation       |   |
                      |   |  - Eth -> IPv4 -> UDP (dport == 53)     |   |
                      |   |  - Payload length: 12..512 bytes        |   |
                      |   |  - DNS QR == 0 (Queries only)           |   |
                      |   +--------------------+--------------------+   |
                      |                        |                        |
                      |                        v                        |
                      |   +--------------------+--------------------+   |
                      |   | Step 2: Per-Source Rate Limiter         |   |
                      |   |  - Map: src_buckets (LRU_HASH)          |   |
                      |   |  - Refill tokens (Rate: r_src, Burst)   |   |
                      |   +-------+-------------------------+-------+   |
                      |      Over |                    Pass |           |
                      |           v                         v           |
                      |      [XDP_DROP]   +-----------------+-------+   |
                      |                   | Step 3: Global Limiter  |   |
                      |                   |  - Map: global_bucket   |   |
                      |                   |    (PERCPU_ARRAY)       |   |
                      |                   +-------+---------+-------+   |
                      |                      Over |    Pass |           |
                      |                           v         v           |
                      |                      [XDP_DROP] [XDP_PASS]      |
                      |                                     |           |
                      |                                     v           |
                      |                          +------------------+   |
                      |                          |  Kernel Network  |   |
                      |                          |      Stack       |   |
                      |                          +---------+--------+   |
                      |                                    |            |
                      |                                    v            |
                      |                          +------------------+   |
                      |                          |  DNS Server App  |   |
                      |                          | (src/dns_server) |   |
                      |                          +------------------+   |
                      +-------------------------------------------------+
```

---

## 3. Rate Limiting Algorithm & Optimization

| Aspect | Baseline: `nftables` | Proposed: `eBPF / XDP` |
|---|---|---|
| **Drop Point** | After `sk_buff` allocation and IP stack entry | Driver RX hook before `sk_buff` allocation (`XDP_DROP`) |
| **Parsing Overhead** | Full IP/UDP stack traversal | Bounded 12-byte header validation; verifier-guaranteed |
| **Per-Source State** | Unbounded netfilter table or dynamic set | Fixed-size LRU hash map (`BPF_MAP_TYPE_LRU_HASH`) |
| **Global Limit** | Shared atomic counter (cache contention) | Per-CPU token bucket (`BPF_MAP_TYPE_PERCPU_ARRAY`) |
| **Burst Tolerance** | Hard cap or basic hashlimit | Configurable dual-tier token buckets with burst allowance |
| **CPU Saturation** | High SoftIRQ load (50%–75%) | Minimal SoftIRQ load (8%–11%) |

### Token Bucket Invariant:
For an elapsed duration $\Delta t = t_{\text{now}} - t_{\text{last}}$:
$$\text{tokens}_{\text{new}} = \min\left(\text{burst}, \text{tokens}_{\text{prev}} + \frac{\Delta t \times \text{rate}}{10^9}\right)$$

Multiplication overflow is prevented by bounding $\Delta t \le 1.0\text{s}$, which immediately tops off tokens to the burst maximum upon idle periods without 64-bit integer wrapping.

---

## 4. Repository Structure

```
A3-PS022-TC177/
├── Makefile                          # Build automation for eBPF, loader, server, and flooder
├── README.md                         # Project documentation and reproduction guide
├── Proposed-structure-hackathon.pdf  # Project presentation deck
├── include/
│   ├── common.h                      # Shared structures, limits, and telemetry definitions
│   └── dns_packet.h                  # RFC 1035 wire-format header specifications
├── src/
│   ├── xdp_dns_ratelimit.bpf.c       # Kernel eBPF/XDP filter
│   ├── loader.c                      # Userspace C loader, configurator, and stats monitor (libbpf)
│   └── dns_server.c                  # Lightweight UDP DNS test responder
├── traffic/
│   ├── flood_generator.c             # Multi-threaded synthetic query flooder (Patterns A, B, C)
│   └── legitimate_prober.py          # Fixed-rate DNS prober (latency & success rate tracker)
├── configs/
│   └── nftables_baseline.nft         # Equivalent baseline ruleset for nftables
├── scripts/
│   ├── setup_lab.sh                  # Prepares isolated network namespaces (ns_srv <-> ns_cli)
│   └── teardown_lab.sh               # Namespace and process cleanup script
└── benchmark/
    ├── run_benchmarks.py             # Benchmark orchestrator
    ├── plot_results.py               # Generates comparative visual charts
    ├── results.json                  # Benchmark measurements
    ├── results.csv                   # Tabular benchmark metrics
    └── benchmark_results.png         # Generated multi-panel visual chart
```

---

## 5. Prerequisites & Build Instructions

### Prerequisites
- Linux Kernel $\ge 5.8$ with eBPF and XDP support
- `clang` / `llvm` (Clang 15+)
- `libbpf` (development headers)
- `gcc` / `make`
- `python3` (with `matplotlib` and `numpy` for plotting)

### Building all Targets
```bash
# Build XDP eBPF bytecode, userspace loader, DNS server, and flood generator:
make all
```

Outputs created:
- `src/xdp_dns_ratelimit.bpf.o`: eBPF bytecode object
- `src/loader`: Control plane binary
- `src/dns_server`: UDP DNS server binary
- `traffic/flood_generator`: High-throughput synthetic flooder binary

---

## 6. Running in the Lab

### Step 1: Initialize the Isolated Namespaces
```bash
sudo ./scripts/setup_lab.sh
```
This creates:
- `ns_srv`: Protected server namespace (`10.0.0.1/24`, interface `veth_srv`)
- `ns_cli`: Generator client namespace (`10.0.0.2/24`, interface `veth_cli`)

### Step 2: Start the Test DNS Server
```bash
sudo ip netns exec ns_srv ./src/dns_server -l 10.0.0.1 -p 53
```

### Step 3: Attach the XDP Filter
```bash
# Attach in generic/skb mode (or native 'drv' mode on physical NICs):
sudo ip netns exec ns_srv ./src/loader -i veth_srv -m generic -s 100 -b 50 -g 50000 -G 10000
```

### Step 4: Run Flood Traffic
From a separate terminal:
```bash
# Pattern A: Single-source flood
sudo ip netns exec ns_cli ./traffic/flood_generator -t 10.0.0.1 -p 53 -P A -s 10.0.0.10 -d 10

# Pattern B: Multi-source spoofed flood
sudo ip netns exec ns_cli ./traffic/flood_generator -t 10.0.0.1 -p 53 -P B -s 10.0.0.100 -c 100 -d 10

# Pattern C: Pulsed flood with random subdomains
sudo ip netns exec ns_cli ./traffic/flood_generator -t 10.0.0.1 -p 53 -P C -d 10
```

### Step 5: Run Legitimate Prober Concurrently
```bash
sudo ip netns exec ns_cli python3 ./traffic/legitimate_prober.py -t 10.0.0.1 -p 53 -q 20 -d 10
```

### Step 6: Teardown Lab
```bash
sudo ./scripts/teardown_lab.sh
```

---

## 7. Benchmark Results

The benchmark suite evaluates all 3 configurations across the 3 attack patterns under identical conditions (flood volume $\approx 350\text{k} - 425\text{k}$ PPS):

| Configuration | Pattern | Attack Type | Flood Rate | Legit Success % | Avg Latency | SoftIRQ CPU % | Server Idle CPU % |
|---|---|---|---|---|---|---|---|
| **no-filter** | A | Single-Source | 385,000 pps | **14.2%** | 182.4 ms | 68.4% | 8.2% |
| **no-filter** | B | Multi-Source | 410,000 pps | **11.8%** | 210.1 ms | 74.1% | 5.0% |
| **no-filter** | C | Pulsed PRSD | 340,000 pps | **28.5%** | 145.6 ms | 52.3% | 22.0% |
| **nftables** | A | Single-Source | 372,000 pps | **62.4%** | 42.1 ms | 48.6% | 34.0% |
| **nftables** | B | Multi-Source | 365,000 pps | **49.0%** | 58.7 ms | 59.2% | 21.5% |
| **nftables** | C | Pulsed PRSD | 350,000 pps | **68.1%** | 38.9 ms | 39.8% | 44.2% |
| **XDP (Proposed)** | A | Single-Source | 390,000 pps | **99.8%** | **1.25 ms** | **8.4%** | **85.6%** |
| **XDP (Proposed)** | B | Multi-Source | 425,000 pps | **98.6%** | **1.48 ms** | **11.2%** | **81.0%** |
| **XDP (Proposed)** | C | Pulsed PRSD | 360,000 pps | **99.4%** | **1.32 ms** | **9.1%** | **84.3%** |

### Key Takeaways:
1. **Legitimate Availability:** Under XDP protection, legitimate queries maintain $\ge 98.6\%$ delivery with sub-2ms latency, compared to severe degradation ($11\% - 28\%$) with no filter and noticeable drop rates with netfilter.
2. **CPU Efficiency:** XDP reduces kernel SoftIRQ CPU overhead from $74.1\%$ down to $11.2\%$, leaving over $80\%$ of CPU resources free for actual application processing.
3. **Multi-Source Resilience:** The combination of LRU per-source tracking and per-CPU global buckets absorbs spoofed multi-source floods without lock contention or table exhaustion.

---

## 8. CLI Reference

### `src/loader`
```
Usage: src/loader [OPTIONS]
Options:
  -i, --interface <ifname>  Network interface name (required)
  -m, --mode <mode>         XDP mode: auto, drv, generic (default: auto)
  -s, --src-rate <pps>      Per-source IP rate limit (default: 100 pps)
  -b, --src-burst <tokens>  Per-source token burst (default: 50)
  -g, --global-rate <pps>   Global total rate limit (default: 50000 pps)
  -G, --global-burst <tok>  Global token burst (default: 10000)
  -p, --poll <interval_sec> Telemetry poll interval in seconds (default: 1, 0 to exit after load)
  -j, --json                Output metrics as JSON stream
  -d, --detach              Detach existing XDP filter from interface and exit
  -h, --help                Show this help message
```

### `traffic/flood_generator`
```
Usage: traffic/flood_generator [OPTIONS]
Options:
  -t, --target <ip>         Target DNS server IP (default: 10.0.0.1)
  -p, --port <port>         Target UDP port (default: 53)
  -P, --pattern <A|B|C>     Flood pattern (default: A)
                            A = Single-source flood
                            B = Multi-source spoofed flood
                            C = Pulsed on/off flood with random synthetic labels
  -s, --src-ip <ip>         Base source IP (default: 10.0.0.10)
  -c, --src-count <num>     Number of rotating source IPs for Pattern B (default: 100)
  -n, --threads <num>       Number of flooder threads (default: 2)
  -r, --rate <pps>          Target total PPS (0 = unconstrained/max speed, default: 0)
  -d, --duration <sec>      Test duration in seconds (0 = run forever, default: 10)
  -h, --help                Show this help message
```

---

## 9. Scope and Safety

- **Lab Testing Only:** All benchmarks are executed exclusively inside local network namespaces or isolated lab host pairs. No external or public flood traffic is ever emitted.
- **Header Bounded:** The filter validates only the 12-byte DNS header; it does not perform semantic record or recursion resolution.
- **Reflection Attacks:** Rate limiting dampens incoming floods at the resolver, but does not alter reflection attacks upstream.

---

## 10. References

1. T. Høiland-Jørgensen, J. D. Brouer, D. Borkmann, J. Fastabend, T. Herbert, D. Ahern, D. Miller. *"The eXpress Data Path: Fast Programmable Packet Processing in the Operating System Kernel."* In: Proc. ACM CoNEXT 2018.
2. G. Bertin. *"XDP in practice: integrating XDP into our DDoS mitigation pipeline."* NetDev 2.1, 2017 (Cloudflare).
3. P. Mockapetris. *"Domain Names - Implementation and Specification."* RFC 1035, IETF, 1987.
4. J. Damas, F. Neves. *"Preventing Use of Recursive Nameservers in Reflector Attacks."* RFC 5358 (BCP 140), IETF, 2008.
5. Linux Kernel Documentation. *"BPF Documentation."* https://docs.kernel.org/bpf/
