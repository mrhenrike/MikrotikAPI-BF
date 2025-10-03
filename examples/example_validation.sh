#!/bin/bash

# Example 5: Post-login validation
# Test found credentials on multiple services

echo "=== Example 5: Full Service Validation ==="

python ../mikrotikapi-bf.py \
  -t 192.168.88.1 \
  -d found_credentials.txt \
  --validate ftp,ssh,telnet \
  --progress \
  --export-all \
  -vv

echo ""
echo "Validation complete. Check which services are accessible."

