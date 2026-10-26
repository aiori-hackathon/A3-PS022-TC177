#!/usr/bin/env bash
# A3-PS022-TC177: Parameter Sensitivity Sweep Runner
# Usage: sudo ./scripts/sensitivity_sweep.sh
#
# Sweeps two independent dimensions:
#   Phase 1 — LRU Map Size  (requires BPF recompile):  4096 | 16384 | 65536 | 131072
#   Phase 2 — Burst Size    (loader CLI flags only):    10 | 50 | 200 | 500
#
# Results saved to benchmark/sensitivity_results.txt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_FILE="$PROJECT_DIR/benchmark/sensitivity_results.txt"
BPF_SRC="$PROJECT_DIR/src/xdp_dns_ratelimit.bpf.c"
BPF_OBJ="$PROJECT_DIR/src/xdp_dns_ratelimit.bpf.o"
LOADER="$PROJECT_DIR/src/loader"
FLOODER="$PROJECT_DIR/traffic/flood_generator"

# Sweep parameters
LRU_SIZES=(4096 16384 65536 131072)
BURST_SIZES=(10 50 200 500)

# Fixed defaults for each phase
DEFAULT_LRU=65536
DEFAULT_BURST=50
DEFAULT_SRC=100
DEFAULT_GLOB_PPS=50000
DEFAULT_GLOB_BURST=10000

FLOOD_DURATION=10  # seconds total per run
STAT_WINDOW=5      # last N seconds to average

# ── Privilege check ───────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    echo "[sweep] ERROR: Must be run as root." >&2
    exit 1
fi

# ── Helpers ───────────────────────────────────────────────────────────────────

mkdir -p "$PROJECT_DIR/benchmark"

recompile_bpf() {
    local map_size="$1"
    echo "[sweep] Recompiling BPF object with MAX_SRC_ENTRIES=${map_size}..."
    /usr/lib/llvm21/bin/clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
        -DMAX_SRC_ENTRIES="${map_size}" \
        -I/usr/include \
        -c "$BPF_SRC" -o "$BPF_OBJ"
}

restore_bpf_default() {
    echo "[sweep] Restoring default BPF object..."
    make -C "$PROJECT_DIR" src/xdp_dns_ratelimit.bpf.o 2>/dev/null || true
}

# Run one measurement: starts loader in JSON mode, floods for FLOOD_DURATION s,
# averages the last STAT_WINDOW JSON lines.
# Outputs: "src_drop_pps glob_drop_pps pass_pps"
run_measurement() {
    local burst="$1"
    local src_rate="$DEFAULT_SRC"
    local glob_pps="$DEFAULT_GLOB_PPS"
    local glob_burst="$DEFAULT_GLOB_BURST"

    local loader_log
    loader_log="$(mktemp /tmp/sweep_loader.XXXXXX)"

    # Start loader in JSON mode
    ip netns exec ns_srv "$LOADER" \
        -i veth_srv -m generic \
        -s "$src_rate" -b "$burst" \
        -g "$glob_pps" -G "$glob_burst" \
        -p 1 -j \
        >"$loader_log" 2>&1 &
    local loader_pid=$!

    # Give loader a moment to attach
    sleep 1

    # Run Pattern B flood (most sensitive to LRU map size)
    ip netns exec ns_cli "$FLOODER" \
        -t 10.0.0.1 -P B -n 4 \
        -d "$FLOOD_DURATION" \
        >/dev/null 2>&1 || true

    # Let the loader emit a couple more stat lines after flood ends
    sleep 2

    kill "$loader_pid" 2>/dev/null || true
    wait "$loader_pid" 2>/dev/null || true

    # Parse: take the last STAT_WINDOW JSON lines, average the fields
    local avg_src avg_glob avg_pass
    avg_src=$(grep -o '"src_drop_pps":[0-9]*' "$loader_log" | tail -n "$STAT_WINDOW" \
        | awk -F: '{s+=$2; n++} END {printf "%d", (n ? s/n : 0)}')
    avg_glob=$(grep -o '"glob_drop_pps":[0-9]*' "$loader_log" | tail -n "$STAT_WINDOW" \
        | awk -F: '{s+=$2; n++} END {printf "%d", (n ? s/n : 0)}')
    avg_pass=$(grep -o '"pass_pps":[0-9]*' "$loader_log" | tail -n "$STAT_WINDOW" \
        | awk -F: '{s+=$2; n++} END {printf "%d", (n ? s/n : 0)}')

    rm -f "$loader_log"

    # Fallback to 0 if no JSON captured
    avg_src="${avg_src:-0}"
    avg_glob="${avg_glob:-0}"
    avg_pass="${avg_pass:-0}"

    echo "$avg_src $avg_glob $avg_pass"
}

print_header() {
    printf "%-12s %-8s %-16s %-16s %-12s\n" \
        "LRU_SIZE" "BURST" "src_drop_pps" "glob_drop_pps" "pass_pps"
    printf "%-12s %-8s %-16s %-16s %-12s\n" \
        "--------" "-----" "------------" "-------------" "--------"
}

print_row() {
    local lru="$1" burst="$2" src_d="$3" glob_d="$4" pass="$5"
    printf "%-12s %-8s %-16s %-16s %-12s\n" \
        "$lru" "$burst" "$src_d" "$glob_d" "$pass"
}

# ── Teardown guard ────────────────────────────────────────────────────────────

cleanup() {
    # Kill any stray loader / flooder processes
    pkill -f "src/loader" 2>/dev/null || true
    pkill -f "flood_generator" 2>/dev/null || true
    restore_bpf_default
}
trap cleanup EXIT INT TERM

# ── Sanity checks ─────────────────────────────────────────────────────────────

if [[ ! -f "$LOADER" ]]; then
    echo "[sweep] ERROR: $LOADER not found. Run 'make all' first." >&2
    exit 1
fi
if [[ ! -f "$FLOODER" ]]; then
    echo "[sweep] ERROR: $FLOODER not found. Run 'make all' first." >&2
    exit 1
fi
if [[ ! -f "$BPF_SRC" ]]; then
    echo "[sweep] ERROR: $BPF_SRC not found." >&2
    exit 1
fi

# Verify namespaces are up
if ! ip netns list | grep -q ns_srv; then
    echo "[sweep] ERROR: ns_srv namespace not found. Run setup_lab.sh first." >&2
    exit 1
fi

# ── Output file header ────────────────────────────────────────────────────────

{
    echo "# A3-PS022-TC177 Sensitivity Sweep Results"
    echo "# Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo ""
} > "$RESULTS_FILE"

# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== [Sensitivity Sweep] Phase 1: LRU Map Size Sweep ==="
echo "    Fixed burst=$DEFAULT_BURST, Pattern=B, flood=${FLOOD_DURATION}s"
echo ""

{
    echo "=== Phase 1: LRU Map Size Sweep (burst=${DEFAULT_BURST}) ==="
    print_header
} | tee -a "$RESULTS_FILE"

prev_lru=""
for lru_size in "${LRU_SIZES[@]}"; do
    # Only recompile when map size actually changes (first run always recompiles)
    if [[ "$lru_size" != "$prev_lru" ]]; then
        recompile_bpf "$lru_size"
        prev_lru="$lru_size"
    fi

    echo -n "[sweep]   LRU=${lru_size} BURST=${DEFAULT_BURST} ... "
    read -r src_d glob_d pass_d < <(run_measurement "$DEFAULT_BURST")
    echo "src_drop_pps=${src_d} glob_drop_pps=${glob_d} pass_pps=${pass_d}"

    print_row "$lru_size" "$DEFAULT_BURST" "$src_d" "$glob_d" "$pass_d" \
        | tee -a "$RESULTS_FILE"
done

# Restore default BPF object between phases
restore_bpf_default

# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== [Sensitivity Sweep] Phase 2: Burst Size Sweep ==="
echo "    Fixed LRU=${DEFAULT_LRU} (default), Pattern=B, flood=${FLOOD_DURATION}s"
echo ""

{
    echo ""
    echo "=== Phase 2: Burst Size Sweep (LRU=${DEFAULT_LRU} default) ==="
    print_header
} | tee -a "$RESULTS_FILE"

for burst_size in "${BURST_SIZES[@]}"; do
    echo -n "[sweep]   LRU=${DEFAULT_LRU} BURST=${burst_size} ... "
    read -r src_d glob_d pass_d < <(run_measurement "$burst_size")
    echo "src_drop_pps=${src_d} glob_drop_pps=${glob_d} pass_pps=${pass_d}"

    print_row "$DEFAULT_LRU" "$burst_size" "$src_d" "$glob_d" "$pass_d" \
        | tee -a "$RESULTS_FILE"
done

# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo "[sweep] Results saved to: $RESULTS_FILE"
echo "[sweep] Sweep complete."
