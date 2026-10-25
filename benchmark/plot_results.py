#!/usr/bin/env python3
"""
A3-PS022-TC177: Benchmark Results Plotter
Generates presentation-ready comparative charts from benchmark metrics.

Usage:
  python3 benchmark/plot_results.py                     # uses benchmark/results.json
  python3 benchmark/plot_results.py --input path.json   # custom input
  python3 benchmark/plot_results.py --sensitivity       # also plot sensitivity results
"""

import argparse
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_JSON = os.path.join(PROJECT_DIR, "benchmark", "results.json")
SENSITIVITY_TXT = os.path.join(PROJECT_DIR, "benchmark", "sensitivity_results.txt")
OUTPUT_PNG = os.path.join(PROJECT_DIR, "benchmark", "benchmark_results.png")
OUTPUT_SENS_PNG = os.path.join(PROJECT_DIR, "benchmark", "sensitivity_results.png")

CONFIGS = ["no-filter", "nftables", "xdp"]
CONFIG_LABELS = ["No Filter", "nftables", "XDP (Proposed)"]
PATTERNS = ["A", "B", "C"]
PATTERN_LABELS = ["Pattern A\n(Single-Source)", "Pattern B\n(Multi-Source)", "Pattern C\n(Pulsed PRSD)"]
COLORS = ["#e74c3c", "#f39c12", "#2ecc71"]


def extract_matrix(data, key):
    """Builds a (3 configs x 3 patterns) numpy matrix for a given metric key."""
    m = np.zeros((3, 3))
    for entry in data:
        if entry.get("config") not in CONFIGS:
            continue
        if entry.get("pattern") not in PATTERNS:
            continue
        ci = CONFIGS.index(entry["config"])
        pi = PATTERNS.index(entry["pattern"])
        m[ci][pi] = entry.get(key, 0.0)
    return m


def annotate_bars(ax, rects, fmt="{:.1f}", suffix=""):
    for rect in rects:
        h = rect.get_height()
        ax.annotate(
            fmt.format(h) + suffix,
            xy=(rect.get_x() + rect.get_width() / 2, h),
            xytext=(0, 3), textcoords="offset points",
            ha="center", va="bottom", fontsize=7.5, fontweight="bold"
        )


def plot_main(data, output_path):
    success_rates = extract_matrix(data, "success_rate_pct")
    softirq_pcts  = extract_matrix(data, "softirq_pct")
    latencies_avg = extract_matrix(data, "latency_avg_ms")
    latencies_p95 = extract_matrix(data, "latency_p95_ms")

    fig, axes = plt.subplots(2, 2, figsize=(18, 11))
    fig.patch.set_facecolor("#ffffff")

    x = np.arange(len(PATTERNS))
    w = 0.25

    # --- Panel 1: Legitimate Query Success Rate ---
    ax = axes[0][0]
    for i in range(3):
        rects = ax.bar(x + (i-1)*w, success_rates[i], w, label=CONFIG_LABELS[i],
                       color=COLORS[i], edgecolor="black", linewidth=0.8)
        annotate_bars(ax, rects, fmt="{:.1f}", suffix="%")
    ax.set_title("Legitimate Query Success Rate", fontsize=12, fontweight="bold", pad=10)
    ax.set_xticks(x); ax.set_xticklabels(PATTERN_LABELS, fontsize=9)
    ax.set_ylabel("Success Rate (%) — Higher is Better", fontsize=9)
    ax.set_ylim(0, 118)
    ax.grid(axis="y", linestyle="--", alpha=0.45)
    ax.legend(loc="lower right", fontsize=8, frameon=True)

    # --- Panel 2: SoftIRQ CPU Utilization ---
    ax = axes[0][1]
    for i in range(3):
        rects = ax.bar(x + (i-1)*w, softirq_pcts[i], w, label=CONFIG_LABELS[i],
                       color=COLORS[i], edgecolor="black", linewidth=0.8)
        annotate_bars(ax, rects, fmt="{:.1f}", suffix="%")
    ax.set_title("Server SoftIRQ CPU Utilisation", fontsize=12, fontweight="bold", pad=10)
    ax.set_xticks(x); ax.set_xticklabels(PATTERN_LABELS, fontsize=9)
    ax.set_ylabel("SoftIRQ % — Lower is Better", fontsize=9)
    ax.set_ylim(0, 100)
    ax.grid(axis="y", linestyle="--", alpha=0.45)

    # --- Panel 3: Average Latency (log scale) ---
    ax = axes[1][0]
    for i in range(3):
        rects = ax.bar(x + (i-1)*w, latencies_avg[i], w, label=CONFIG_LABELS[i],
                       color=COLORS[i], edgecolor="black", linewidth=0.8)
        # Custom annotation for log scale
        for rect in rects:
            h = rect.get_height()
            label = f"{h:.2f}ms" if h < 10 else f"{h:.0f}ms"
            ax.annotate(label,
                        xy=(rect.get_x() + rect.get_width() / 2, h),
                        xytext=(0, 4), textcoords="offset points",
                        ha="center", va="bottom", fontsize=7.5, fontweight="bold")
    ax.set_title("Legitimate Query Avg RTT (Log Scale)", fontsize=12, fontweight="bold", pad=10)
    ax.set_xticks(x); ax.set_xticklabels(PATTERN_LABELS, fontsize=9)
    ax.set_ylabel("Avg RTT ms — Lower is Better", fontsize=9)
    ax.set_yscale("log")
    ax.set_ylim(0.5, 500)
    ax.grid(axis="y", linestyle="--", alpha=0.45)
    ax.legend(loc="upper right", fontsize=8, frameon=True)

    # --- Panel 4: p95 Latency (log scale) ---
    ax = axes[1][1]
    for i in range(3):
        rects = ax.bar(x + (i-1)*w, latencies_p95[i], w, label=CONFIG_LABELS[i],
                       color=COLORS[i], edgecolor="black", linewidth=0.8)
        for rect in rects:
            h = rect.get_height()
            label = f"{h:.2f}ms" if h < 10 else f"{h:.0f}ms"
            ax.annotate(label,
                        xy=(rect.get_x() + rect.get_width() / 2, h),
                        xytext=(0, 4), textcoords="offset points",
                        ha="center", va="bottom", fontsize=7.5, fontweight="bold")
    ax.set_title("Legitimate Query p95 RTT (Log Scale)", fontsize=12, fontweight="bold", pad=10)
    ax.set_xticks(x); ax.set_xticklabels(PATTERN_LABELS, fontsize=9)
    ax.set_ylabel("p95 RTT ms — Lower is Better", fontsize=9)
    ax.set_yscale("log")
    ax.set_ylim(0.5, 1000)
    ax.grid(axis="y", linestyle="--", alpha=0.45)

    plt.suptitle(
        "A3-PS022-TC177 — XDP vs nftables vs No-Filter: DNS Flood Mitigation Benchmark",
        fontsize=13, fontweight="bold", y=0.99
    )
    plt.tight_layout(rect=[0, 0, 1, 0.97])
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"[+] Visualization saved to: {output_path}")


def plot_sensitivity(txt_path, output_path):
    """Parses benchmark/sensitivity_results.txt and plots LRU and burst sweep charts."""
    if not os.path.exists(txt_path):
        print(f"[!] Sensitivity file not found: {txt_path} — skipping sensitivity plot.")
        return

    lru_rows = []
    burst_rows = []
    section = None

    with open(txt_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "LRU Map Size" in line:
                section = "lru"
                continue
            if "Burst Size" in line:
                section = "burst"
                continue
            if line.startswith("LRU_SIZE") or line.startswith("BURST"):
                continue  # header row
            parts = line.split("|")
            if len(parts) < 4:
                continue
            parts = [p.strip() for p in parts]
            try:
                if section == "lru":
                    lru_rows.append({
                        "lru_size": int(parts[0]),
                        "burst": int(parts[1]),
                        "src_drop_pps": float(parts[2]),
                        "pass_pps": float(parts[3]),
                    })
                elif section == "burst":
                    burst_rows.append({
                        "lru_size": int(parts[0]),
                        "burst": int(parts[1]),
                        "src_drop_pps": float(parts[2]),
                        "pass_pps": float(parts[3]),
                    })
            except (ValueError, IndexError):
                continue

    if not lru_rows and not burst_rows:
        print("[!] No valid sensitivity data found to plot.")
        return

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.patch.set_facecolor("#ffffff")

    # LRU sweep
    ax = axes[0]
    if lru_rows:
        sizes = [r["lru_size"] for r in lru_rows]
        passes = [r["pass_pps"] for r in lru_rows]
        drops = [r["src_drop_pps"] for r in lru_rows]
        xi = np.arange(len(sizes))
        ax.bar(xi - 0.2, passes, 0.35, label="pass_pps", color="#2ecc71", edgecolor="black", linewidth=0.8)
        ax.bar(xi + 0.2, drops, 0.35, label="src_drop_pps", color="#e74c3c", edgecolor="black", linewidth=0.8)
        ax.set_xticks(xi)
        ax.set_xticklabels([str(s) for s in sizes], fontsize=9)
        ax.set_xlabel("LRU Map Max Entries", fontsize=10)
    ax.set_title("LRU Map Size Sensitivity\n(Pattern B, burst=50)", fontsize=11, fontweight="bold")
    ax.set_ylabel("Packets/sec", fontsize=9)
    ax.legend(fontsize=9)
    ax.grid(axis="y", linestyle="--", alpha=0.45)

    # Burst sweep
    ax = axes[1]
    if burst_rows:
        bursts = [r["burst"] for r in burst_rows]
        passes = [r["pass_pps"] for r in burst_rows]
        drops = [r["src_drop_pps"] for r in burst_rows]
        xi = np.arange(len(bursts))
        ax.bar(xi - 0.2, passes, 0.35, label="pass_pps", color="#2ecc71", edgecolor="black", linewidth=0.8)
        ax.bar(xi + 0.2, drops, 0.35, label="src_drop_pps", color="#e74c3c", edgecolor="black", linewidth=0.8)
        ax.set_xticks(xi)
        ax.set_xticklabels([str(b) for b in bursts], fontsize=9)
        ax.set_xlabel("Per-Source Burst Size (tokens)", fontsize=10)
    ax.set_title("Burst Parameter Sensitivity\n(Pattern B, LRU=65536)", fontsize=11, fontweight="bold")
    ax.set_ylabel("Packets/sec", fontsize=9)
    ax.legend(fontsize=9)
    ax.grid(axis="y", linestyle="--", alpha=0.45)

    plt.suptitle("A3-PS022-TC177 — XDP Rate Limiter Parameter Sensitivity Analysis",
                 fontsize=12, fontweight="bold", y=1.01)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"[+] Sensitivity visualization saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="A3-PS022-TC177 Benchmark Plotter")
    parser.add_argument("--input", default=RESULTS_JSON, help="Path to results JSON")
    parser.add_argument("--output", default=OUTPUT_PNG, help="Output PNG path for main chart")
    parser.add_argument("--sensitivity", action="store_true", help="Also generate sensitivity chart")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: {args.input} not found. Run the benchmark first.")
        sys.exit(1)

    with open(args.input) as f:
        data = json.load(f)

    plot_main(data, args.output)

    if args.sensitivity:
        plot_sensitivity(SENSITIVITY_TXT, OUTPUT_SENS_PNG)


if __name__ == "__main__":
    main()
