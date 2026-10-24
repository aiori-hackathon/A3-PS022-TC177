#!/usr/bin/env python3
"""
A3-PS022-TC177: Benchmark Results Plotter
Generates presentation-ready comparative charts from benchmark metrics.
"""

import json
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_JSON = os.path.join(PROJECT_DIR, "benchmark", "results.json")
OUTPUT_PNG = os.path.join(PROJECT_DIR, "benchmark", "benchmark_results.png")

def plot():
    if not os.path.exists(RESULTS_JSON):
        print(f"Error: {RESULTS_JSON} not found. Run benchmark/run_benchmarks.py first.")
        return

    with open(RESULTS_JSON, "r") as f:
        data = json.load(f)

    # Group by config and pattern
    patterns = ["A", "B", "C"]
    pattern_labels = ["Pattern A\n(Single-Source)", "Pattern B\n(Multi-Source)", "Pattern C\n(Pulsed PRSD)"]
    configs = ["no-filter", "nftables", "xdp"]
    config_labels = ["No Filter", "nftables (Baseline)", "XDP (Proposed)"]
    colors = ["#e74c3c", "#f39c12", "#2ecc71"]

    # Extract metrics into matrices [config_idx][pattern_idx]
    success_rates = np.zeros((3, 3))
    softirq_pcts = np.zeros((3, 3))
    latencies = np.zeros((3, 3))

    for entry in data:
        c_idx = configs.index(entry["config"])
        p_idx = patterns.index(entry["pattern"])
        success_rates[c_idx][p_idx] = entry["success_rate_pct"]
        softirq_pcts[c_idx][p_idx] = entry["softirq_pct"]
        latencies[c_idx][p_idx] = entry["latency_avg_ms"]

    # Create 3-panel figure
    fig, axes = plt.subplots(1, 3, figsize=(18, 5.5))
    fig.patch.set_facecolor("#ffffff")

    x = np.arange(len(patterns))
    width = 0.25

    # 1. Legitimate Query Success Rate
    ax1 = axes[0]
    for i in range(3):
        rects = ax1.bar(x + (i - 1) * width, success_rates[i], width, label=config_labels[i], color=colors[i], edgecolor="black", linewidth=0.8)
        for rect in rects:
            height = rect.get_height()
            ax1.annotate(f"{height:.1f}%",
                         xy=(rect.get_x() + rect.get_width() / 2, height),
                         xytext=(0, 3), textcoords="offset points",
                         ha="center", va="bottom", fontsize=8, fontweight="bold")
    ax1.set_title("Legitimate Query Success Rate (%)", fontsize=12, fontweight="bold", pad=12)
    ax1.set_xticks(x)
    ax1.set_xticklabels(pattern_labels, fontsize=9)
    ax1.set_ylabel("Success Rate (%)", fontsize=10)
    ax1.set_ylim(0, 115)
    ax1.grid(axis="y", linestyle="--", alpha=0.5)
    ax1.legend(loc="upper right", frameon=True, fontsize=8)

    # 2. Kernel SoftIRQ CPU Utilization
    ax2 = axes[1]
    for i in range(3):
        rects = ax2.bar(x + (i - 1) * width, softirq_pcts[i], width, label=config_labels[i], color=colors[i], edgecolor="black", linewidth=0.8)
        for rect in rects:
            height = rect.get_height()
            ax2.annotate(f"{height:.1f}%",
                         xy=(rect.get_x() + rect.get_width() / 2, height),
                         xytext=(0, 3), textcoords="offset points",
                         ha="center", va="bottom", fontsize=8, fontweight="bold")
    ax2.set_title("Server SoftIRQ CPU Utilization (%)", fontsize=12, fontweight="bold", pad=12)
    ax2.set_xticks(x)
    ax2.set_xticklabels(pattern_labels, fontsize=9)
    ax2.set_ylabel("CPU SoftIRQ % (Lower is Better)", fontsize=10)
    ax2.set_ylim(0, 100)
    ax2.grid(axis="y", linestyle="--", alpha=0.5)

    # 3. Legitimate Query Latency (RTT)
    ax3 = axes[2]
    for i in range(3):
        rects = ax3.bar(x + (i - 1) * width, latencies[i], width, label=config_labels[i], color=colors[i], edgecolor="black", linewidth=0.8)
        for rect in rects:
            height = rect.get_height()
            ax3.annotate(f"{height:.1f}ms",
                         xy=(rect.get_x() + rect.get_width() / 2, height),
                         xytext=(0, 3), textcoords="offset points",
                         ha="center", va="bottom", fontsize=8, fontweight="bold")
    ax3.set_title("Legitimate Query Average Latency (ms)", fontsize=12, fontweight="bold", pad=12)
    ax3.set_xticks(x)
    ax3.set_xticklabels(pattern_labels, fontsize=9)
    ax3.set_ylabel("Average RTT ms (Log Scale, Lower is Better)", fontsize=10)
    ax3.set_yscale("log")
    ax3.set_ylim(0.5, 500)
    ax3.grid(axis="y", linestyle="--", alpha=0.5)

    plt.suptitle("A3-PS022-TC177: DNS Query Flood Mitigation — XDP vs nftables vs Baseline",
                 fontsize=14, fontweight="bold", y=0.98)
    plt.tight_layout(rect=[0, 0, 1, 0.93])
    plt.savefig(OUTPUT_PNG, dpi=300)
    plt.close()
    print(f"[+] Visualization saved to: {OUTPUT_PNG}")

if __name__ == "__main__":
    plot()
