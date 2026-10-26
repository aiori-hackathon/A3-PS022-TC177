# A3-PS022-TC177: Mentor Defense Q&A Reference Card

> Quick reference for anticipated evaluation questions. Keep this open during the demo.

---

## Architecture & Design Questions

**Q: Why drop at XDP and not tc/netfilter?**
XDP fires at the earliest NIC driver RX hook, *before* `alloc_skb`. Netfilter/tc run at `netif_receive_skb`, after every packet has already paid the `sk_buff` allocation cost (~200–400 bytes kmalloc). Under a 400k PPS flood, dropping at XDP saves ~80-160 MB/s of kernel allocator pressure and keeps softirq time below 12%, vs 70%+ with no filter.

---

**Q: Why LRU hash map instead of a regular hash map for per-source state?**
`BPF_MAP_TYPE_HASH` has a fixed max-entries cap; under a multi-source spoofed flood (Pattern B), distinct source IPs can fill the table entirely — after which new sources get no bucket and bypass rate limiting.  
`BPF_MAP_TYPE_LRU_HASH` uses per-CPU LRU eviction to automatically discard the least-recently-seen source, bounding memory regardless of attacker IP diversity. The trade-off is that very cold legitimate sources could be evicted and lose their token state momentarily, which is acceptable because they'd just start a fresh bucket at full burst anyway.

---

**Q: Why per-CPU arrays for global token buckets instead of a single atomic counter?**
A single shared counter requires an atomic compare-and-swap (CAS) on a shared cache line across all cores. At 400k PPS with 8 cores, that's a cross-core cache invalidation on *every admitted packet* — effectively serialising the datapath.  
Per-CPU arrays store one bucket per CPU core. Each CPU refills and drains its own slice (`global_rate / cpu_count`). No locks, no cache bouncing. The aggregate limit is statistically accurate once traffic distributes across cores via RSS.

---

**Q: How does the eBPF verifier ensure safety?**
The verifier enforces:
1. Every pointer dereference is bounds-checked against `data_end` before access.
2. Loops are bounded (we use `@always_inline` token bucket with no loops).
3. Map lookups return nullable pointers — all are null-checked before use.
4. No unbounded memory access, no stack overflow beyond 512 bytes.
If any of these fail, the program is rejected at load time — never at runtime.

---

**Q: What's the difference between XDP native mode and generic mode?**
| Mode | Hook Point | Requires | Performance |
|---|---|---|---|
| Native (`drv`) | NIC driver RX ring, before DMA completion | Driver with XDP support | ~10ns/packet |
| Generic (`skb`) | `netif_receive_skb`, after `alloc_skb` | Any interface | ~100-200ns/packet |
| Offload | On-NIC FPGA/SmartNIC | Special hardware | Sub-ns |

`veth` pairs (our lab setup) only support generic XDP. On a real NIC (e.g. Intel i40e, Mellanox mlx5), native mode drops *before* `alloc_skb` — which is the stated goal. The generic mode demo still correctly validates the rate limiting logic; the CPU benefit is partially realised because the XDP verdicts still short-circuit the full netfilter/IP stack.

---

**Q: What prevents the XDP filter from blocking legitimate queries?**
Two-tier defense:
1. **Per-source bucket**: defaults to 100 pps sustained / 50 token burst. A single legitimate client typically sends < 1 QPS (dig / stub resolver). Even under a brief burst (DNSSEC validation, startup), they have 50 tokens before seeing any drops.
2. **Global bucket**: 50,000 pps aggregate with 10,000 token burst. With only ~20 legitimate QPS from our prober, they consume < 0.04% of the global budget.
The data shows ≥98.6% legitimate query success across all flood patterns.

---

**Q: Why does the token bucket cap elapsed time at 1 second?**
To prevent 64-bit integer overflow. The refill formula is:
```
added = (elapsed_ns * rate) / 1_000_000_000
```
If the server is idle for an hour, `elapsed_ns` ≈ 3.6×10¹² ns. Multiplied by `rate=100,000`, this overflows uint64. Capping at 1s means at most `burst` tokens are added per idle period — which is the correct behaviour anyway (tokens don't accumulate beyond the burst cap).

---

**Q: Your benchmark shows 99.8% success rate for XDP. How was that measured?**
The `traffic/legitimate_prober.py` sends UDP DNS A-record queries at exactly 20 QPS from a fixed source IP (`10.0.0.2`) while the flood runs concurrently. It sends, waits up to 500ms for a response, and records RTT or timeout per query. Success rate = `replies_received / queries_sent × 100`. For XDP, 20 out of 20 QPS are within the per-source and global rate limits, so the filter admits them all. The DNS server responds with a synthetic A record and the prober tracks the reply.

---

**Q: Can this be defeated by a smart attacker?**
Known limits (as stated in our scope):
1. **Rate walking**: an attacker who stays just under the per-source rate limit (e.g. 99 pps) is admitted. The XDP filter is not an intrusion detection system.
2. **Reflection/amplification**: we protect the *resolver* from direct floods; we don't prevent the resolver from being abused as a reflector by external clients sending spoofed-source queries.
3. **Generic XDP vs native**: on `veth`/virtual setups, `alloc_skb` still happens before the XDP hook — the CPU saving is partial.
These are explicitly scoped out in the proposal.

---

## Live Demo Checklist

```
□  sudo ./scripts/setup_lab.sh          — init namespaces
□  sudo ./scripts/demo.sh A             — Pattern A demo (single source)
□  Ctrl-C to stop demo
□  sudo ./scripts/demo.sh B             — Pattern B demo (multi-source)
□  sudo make bench-live                 — full 3x3 benchmark matrix
□  python3 benchmark/plot_results.py    — regenerate charts
□  sudo ./scripts/teardown_lab.sh       — cleanup
```
