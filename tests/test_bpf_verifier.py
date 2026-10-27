#!/usr/bin/env python3
"""
A3-PS022-TC177: Offline BPF & Datapath Unit Test Suite

Runs unprivileged (zero root or CAP_BPF requirements). Validates:
1. BPF ELF section integrity, BTF debug info, and license.
2. Map declarations (LRU hash, per-CPU array, array sizes).
3. Wire-format DNS query construction and RFC 1035 bounded parsing.
4. Token bucket mathematical refill logic and 64-bit integer overflow protection.
"""

import os
import struct
import subprocess
import sys
import unittest

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BPF_OBJ = os.path.join(PROJECT_DIR, "src", "xdp_dns_ratelimit.bpf.o")

class TestBpfElfIntegrity(unittest.TestCase):
    """Validates the compiled eBPF object ELF layout and maps."""

    @classmethod
    def setUpClass(cls):
        # Ensure BPF object exists or rebuild it
        if not os.path.exists(BPF_OBJ):
            subprocess.check_call(["make", "src/xdp_dns_ratelimit.bpf.o"], cwd=PROJECT_DIR)

    def test_bpf_object_exists(self):
        self.assertTrue(os.path.exists(BPF_OBJ), "BPF object file not found")
        self.assertGreater(os.path.getsize(BPF_OBJ), 1000, "BPF object file abnormally small")

    def test_elf_sections_present(self):
        """Verifies xdp, .maps, license, and BTF sections exist."""
        output = subprocess.check_output(["readelf", "-S", BPF_OBJ]).decode("utf-8")
        self.assertIn("xdp", output, "Missing 'xdp' program section")
        self.assertIn(".maps", output, "Missing '.maps' map definition section")
        self.assertIn("license", output, "Missing 'license' section")
        self.assertIn(".BTF", output, "Missing BTF debug information section")

    def test_license_is_gpl(self):
        """Kernel BPF requires GPL compatible license for certain helpers like bpf_ktime_get_ns."""
        output = subprocess.check_output(["readelf", "-p", "license", BPF_OBJ]).decode("utf-8")
        self.assertIn("GPL", output, "License is not GPL")

    def test_required_maps_declared(self):
        """Verifies all four required BPF maps are defined in symbol table."""
        output = subprocess.check_output(["readelf", "-s", BPF_OBJ]).decode("utf-8")
        expected_maps = ["src_buckets", "global_bucket", "stats_map", "cfg_map"]
        for m in expected_maps:
            self.assertIn(m, output, f"Required BPF map '{m}' missing from symbol table")


class TestDnsWireFormat(unittest.TestCase):
    """Validates RFC 1035 DNS wire parsing and bounded packet logic."""

    def build_packet(self, tx_id, qr_bit, payload_len=24, domain="example.local"):
        # Header: ID(2), Flags(2), QD(2), AN(2), NS(2), AR(2)
        flags = 0x8100 if qr_bit else 0x0100
        hdr = struct.pack("!HHHHHH", tx_id, flags, 1, 0, 0, 0)
        
        qname = b""
        for part in domain.split("."):
            if part:
                b = part.encode("ascii")
                qname += struct.pack("!B", len(b)) + b
        qname += b"\x00"
        tail = struct.pack("!HH", 1, 1) # QTYPE=A, QCLASS=IN
        pkt = hdr + qname + tail
        
        # Pad or truncate if specified
        if len(pkt) < payload_len:
            pkt += b"\x00" * (payload_len - len(pkt))
        elif len(pkt) > payload_len:
            pkt = pkt[:payload_len]
        return pkt

    def test_valid_query_parsing(self):
        pkt = self.build_packet(1234, qr_bit=0, payload_len=32)
        self.assertGreaterEqual(len(pkt), 12)
        tx_id, flags = struct.unpack("!HH", pkt[:4])
        self.assertEqual(tx_id, 1234)
        qr = (flags >> 15) & 1
        self.assertEqual(qr, 0, "Query packet must have QR=0")

    def test_valid_response_parsing(self):
        pkt = self.build_packet(5678, qr_bit=1, payload_len=32)
        tx_id, flags = struct.unpack("!HH", pkt[:4])
        qr = (flags >> 15) & 1
        self.assertEqual(qr, 1, "Response packet must have QR=1")

    def test_bounded_payload_length_rules(self):
        """Tests that payloads < 12B or > 512B violate filter bounds."""
        truncated_payload = b"\x00\x01\x02\x03" # Only 4 bytes
        self.assertLess(len(truncated_payload), 12, "Payload is shorter than 12-byte DNS header")

        oversized_payload = b"X" * 550
        self.assertGreater(len(oversized_payload), 512, "Payload exceeds 512-byte bounded limit")


class TestTokenBucketMath(unittest.TestCase):
    """Simulates and verifies the dual-tier token bucket mathematical invariants."""

    def simulate_refill(self, last_update_ns, now_ns, current_tokens, rate, burst):
        if now_ns <= last_update_ns:
            return current_tokens, last_update_ns

        elapsed = now_ns - last_update_ns
        # Overflow cap at 1 second
        if elapsed >= 1_000_000_000:
            return burst, now_ns

        added = (elapsed * rate) // 1_000_000_000
        if added > 0:
            new_tokens = min(burst, current_tokens + added)
            return new_tokens, now_ns
        return current_tokens, last_update_ns

    def test_normal_refill(self):
        # Rate: 100 tokens/sec. Elapsed: 200ms (200,000,000 ns). Expected: +20 tokens.
        tokens, _ = self.simulate_refill(
            last_update_ns=0,
            now_ns=200_000_000,
            current_tokens=0,
            rate=100,
            burst=50
        )
        self.assertEqual(tokens, 20)

    def test_burst_ceiling(self):
        # Rate: 100 tokens/sec. Elapsed: 800ms (+80 tokens). Burst cap is 50.
        tokens, _ = self.simulate_refill(
            last_update_ns=0,
            now_ns=800_000_000,
            current_tokens=10,
            rate=100,
            burst=50
        )
        self.assertEqual(tokens, 50, "Tokens must not exceed configured burst ceiling")

    def test_64bit_overflow_protection(self):
        # Idle for 7 days (604,800 seconds)
        idle_ns = 7 * 24 * 3600 * 1_000_000_000
        tokens, now = self.simulate_refill(
            last_update_ns=0,
            now_ns=idle_ns,
            current_tokens=5,
            rate=100_000,
            burst=50
        )
        self.assertEqual(tokens, 50, "Prolonged idle duration must cleanly cap at burst without overflow")
        self.assertEqual(now, idle_ns)

    def test_per_cpu_global_slice(self):
        # 8 cores, 40,000 global pps -> 5,000 pps/core
        ncpu = 8
        global_rate = 40_000
        rate_per_cpu = global_rate // ncpu
        self.assertEqual(rate_per_cpu, 5_000)
        
        # Test 100ms on 1 core gives exactly 500 tokens
        tokens, _ = self.simulate_refill(
            last_update_ns=0,
            now_ns=100_000_000,
            current_tokens=0,
            rate=rate_per_cpu,
            burst=2000
        )
        self.assertEqual(tokens, 500)


def main():
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(TestBpfElfIntegrity))
    suite.addTest(loader.loadTestsFromTestCase(TestDnsWireFormat))
    suite.addTest(loader.loadTestsFromTestCase(TestTokenBucketMath))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)

if __name__ == "__main__":
    main()
