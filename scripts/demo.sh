#!/usr/bin/env bash
# A3-PS022-TC177: Live Demo Launcher
# Usage: sudo ./scripts/demo.sh [pattern]
# Pattern defaults to A if not specified

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SESSION="dns-demo"
PATTERN="${1:-A}"

# ── Dependency / privilege checks ────────────────────────────────────────────

if ! command -v tmux &>/dev/null; then
    echo "[demo] ERROR: tmux is not installed. Install it with: apt install tmux" >&2
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "[demo] ERROR: This script must be run as root (required for netns, XDP, and raw sockets)." >&2
    echo "       Try: sudo $0 $*" >&2
    exit 1
fi

if [[ ! "$PATTERN" =~ ^[ABCabc]$ ]]; then
    echo "[demo] ERROR: Invalid pattern '$PATTERN'. Choose A, B, or C." >&2
    exit 1
fi
PATTERN="${PATTERN^^}"

# ── Cleanup trap ─────────────────────────────────────────────────────────────

teardown() {
    echo ""
    echo "[demo] Tearing down lab environment..."
    bash "$SCRIPT_DIR/teardown_lab.sh" 2>/dev/null || true
    echo "[demo] Done."
}
trap teardown EXIT INT TERM

# ── ASCII banner ──────────────────────────────────────────────────────────────

cat <<'BANNER'
╔══════════════════════════════════════════════════════════════════╗
║          A3-PS022-TC177 · XDP DNS Rate-Limiter Live Demo         ║
╠══════════════════════════════════════════════════════════════════╣
║  PANE 0 (top-left) │ DNS Server          — query log + QPS       ║
║  PANE 1 (top-right)│ XDP Loader          — per-src & global drop ║
║  PANE 2 (bottom)   │ Traffic             — flood + legit prober   ║
╚══════════════════════════════════════════════════════════════════╝
BANNER
echo ""
echo "[demo] Pattern: $PATTERN"
echo "[demo] Tearing down any previous lab state..."

# ── Environment setup ─────────────────────────────────────────────────────────

bash "$SCRIPT_DIR/teardown_lab.sh" 2>/dev/null || true
echo "[demo] Setting up lab..."
bash "$SCRIPT_DIR/setup_lab.sh"

# ── Build binaries if needed ──────────────────────────────────────────────────

if [[ ! -f "$PROJECT_DIR/src/loader" ]]; then
    echo "[demo] Binaries missing — running 'make all'..."
    make -C "$PROJECT_DIR" all
fi

# ── tmux session ──────────────────────────────────────────────────────────────

# Kill any stale session with the same name
tmux kill-session -t "$SESSION" 2>/dev/null || true

# Pane 0 (top-left): DNS Server
tmux new-session -d -s "$SESSION" -x 220 -y 50
tmux rename-window -t "$SESSION" "demo"
tmux send-keys -t "$SESSION:0.0" \
    "echo '=== PANE 0: DNS Server ==='; ip netns exec ns_srv $PROJECT_DIR/src/dns_server -l 10.0.0.1 -p 53" \
    Enter

sleep 1

# Pane 1 (top-right): XDP Loader — split horizontally from pane 0
tmux split-window -t "$SESSION:0.0" -h
tmux send-keys -t "$SESSION:0.1" \
    "echo '=== PANE 1: XDP Loader | Pass/Drop Stats ==='; sleep 1; ip netns exec ns_srv $PROJECT_DIR/src/loader -i veth_srv -m generic -s 100 -b 50 -g 50000 -G 10000 -p 1" \
    Enter

sleep 1

# Pane 2 (bottom, full width): Traffic — split vertically spanning full width
tmux split-window -t "$SESSION:0.0" -v -f
tmux send-keys -t "$SESSION:0.2" \
    "echo '=== PANE 2: Traffic (Flood + Legit Prober) ==='; \
ip netns exec ns_cli $PROJECT_DIR/traffic/flood_generator -t 10.0.0.1 -P $PATTERN -n 4 -d 30 & \
ip netns exec ns_cli python3 $PROJECT_DIR/traffic/legitimate_prober.py -t 10.0.0.1 -q 20 -d 30; \
wait" \
    Enter

# ── Attach ────────────────────────────────────────────────────────────────────

echo "[demo] Attaching to tmux session '$SESSION' — press Ctrl-B D to detach, Ctrl-C to stop."
tmux attach-session -t "$SESSION"
