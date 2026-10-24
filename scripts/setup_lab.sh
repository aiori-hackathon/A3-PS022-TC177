#!/usr/bin/env bash
# A3-PS022-TC177: Lab Environment Setup Script
#
# Sets up isolated network namespaces and a veth pair to simulate a two-host
# testbed on a single Linux machine.

set -euo pipefail

NS_SRV="ns_srv"
NS_CLI="ns_cli"
VETH_SRV="veth_srv"
VETH_CLI="veth_cli"

IP_SRV="10.0.0.1/24"
IP_CLI="10.0.0.2/24"

echo "=== [Lab Setup] Initializing Isolated Network Namespaces ==="

# Clean existing namespaces if present
ip netns del "${NS_SRV}" 2>/dev/null || true
ip netns del "${NS_CLI}" 2>/dev/null || true

# 1. Create namespaces
ip netns add "${NS_SRV}"
ip netns add "${NS_CLI}"

# 2. Create veth peer pair
ip link add "${VETH_SRV}" type veth peer name "${VETH_CLI}"

# 3. Assign veth endpoints into respective namespaces
ip link set "${VETH_SRV}" netns "${NS_SRV}"
ip link set "${VETH_CLI}" netns "${NS_CLI}"

# 4. Configure Server namespace (ns_srv)
ip -n "${NS_SRV}" addr add "${IP_SRV}" dev "${VETH_SRV}"
ip -n "${NS_SRV}" link set "${VETH_SRV}" up
ip -n "${NS_SRV}" link set lo up

# Disable offloads on server interface for accurate packet-level evaluation
ip netns exec "${NS_SRV}" ethtool -K "${VETH_SRV}" gro off gso off tso off 2>/dev/null || true

# 5. Configure Client namespace (ns_cli)
ip -n "${NS_CLI}" addr add "${IP_CLI}" dev "${VETH_CLI}"
ip -n "${NS_CLI}" link set "${VETH_CLI}" up
ip -n "${NS_CLI}" link set lo up

# Disable offloads on client interface
ip netns exec "${NS_CLI}" ethtool -K "${VETH_CLI}" gro off gso off tso off 2>/dev/null || true

# Verify link connectivity
echo "Testing namespace connectivity via ping..."
ip netns exec "${NS_CLI}" ping -c 2 -W 1 10.0.0.1 >/dev/null

echo "=== [Lab Setup Complete] ==="
echo "  Server NS: ${NS_SRV} (IP: 10.0.0.1, Interface: ${VETH_SRV})"
echo "  Client NS: ${NS_CLI} (IP: 10.0.0.2, Interface: ${VETH_CLI})"
echo "Run benchmarks with: sudo python3 benchmark/run_benchmarks.py"
