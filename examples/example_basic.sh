#!/bin/bash

# Example 1: Basic bruteforce attack
# Test single credential against Mikrotik device

echo "=== Example 1: Basic Attack ==="
python ../mikrotikapi-bf.py \
  -t 192.168.88.1 \
  -U admin \
  -P password123

echo ""
echo "Press Enter to continue..."
read

