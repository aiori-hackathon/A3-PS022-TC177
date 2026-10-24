#!/usr/bin/env bash
# A3-PS022-TC177: Lab Environment Teardown Script
#
# Cleans up namespaces, veth interfaces, and lingering background test processes.

set -euo pipefail

NS_SRV="ns_srv"
NS_CLI="ns_cli"

echo "=== [Lab Teardown] Cleaning Up ==="

# Kill running test instances
pkill -f "dns_server" 2>/dev/null || true
pkill -f "flood_generator" 2>/dev/null || true
pkill -f "loader" 2>/dev/null || true
pkill -f "legitimate_prober" 2>/dev/null || true

# Flush nftables table if active
if command -v nft >/dev/null 2>&1; then
    nft delete table inet ddos_filter 2>/dev/null || true
fi

# Delete namespaces (also destroys veth peers)
ip netns del "${NS_SRV}" 2>/dev/null || true
ip netns del "${NS_CLI}" 2>/dev/null || true

echo "=== [Lab Teardown Complete] ==="
