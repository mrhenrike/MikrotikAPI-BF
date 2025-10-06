# 🚀 MikrotikAPI-BF v2.0 - Complete Feature List

## Overview

MikrotikAPI-BF v2.0 is a professional-grade brute-force tool for Mikrotik RouterOS security auditing.

---

## ✨ Core Features

### 1. **Multi-Protocol Support**
- ✅ RouterOS API (port 8728)
- ✅ REST-API (HTTP/HTTPS)
- ✅ Post-login validation (FTP, SSH, TELNET)
- ✅ SSL/TLS support
- ✅ Configurable ports

### 2. **Credential Testing Modes**
- ✅ Single credential (`-U admin -P password`)
- ✅ User + password lists (all combinations)
- ✅ Combo dictionary (`user:pass` format)
- ✅ Empty password testing
- ✅ Automatic deduplication

### 3. **Performance**
- ✅ Multi-threading (1-15 threads)
- ✅ Configurable delay between attempts
- ✅ Connection timeout control
- ✅ Thread-safe operations
- ✅ Efficient wordlist handling

---

## 🎯 New in v2.0

### 4. **Export System** (`_export.py`)
Export results in professional formats:
- **JSON**: Structured data with full metadata
- **CSV**: Excel/LibreOffice compatible
- **XML**: Hierarchical with pretty-print
- **TXT**: Simple user:pass list

**Features**:
- Automatic timestamping
- Organized directory structure
- Safe filename generation
- Complete scan metadata

**Usage**:
```bash
--export json,csv    # Specific formats
--export-all         # All formats
--export-dir path    # Custom directory
```

---

### 5. **Progress Tracking** (`_progress.py`)
Visual progress monitoring with:
- **Progress Bar**: Animated bar (█░)
- **Percentage**: Exact completion
- **Counter**: Current/Total attempts
- **Success Count**: Credentials found
- **Speed**: Attempts per second
- **ETA**: Estimated time remaining
- **Thread-Safe**: Multi-threaded support

**Example Output**:
```
[████████████░░░░] 65.4% (327/500) | ✓ 3 | 12.5 att/s | ETA: 0:00:14
```

**Usage**:
```bash
--progress    # Enable progress bar
```

---

### 6. **Retry Mechanism** (`_retry.py`)
Intelligent retry with resilience patterns:

**RetryStrategy**:
- Exponential backoff (1s → 2s → 4s → 8s...)
- Configurable max attempts
- Configurable max delay
- Specific exception handling
- Decorator support

**CircuitBreaker**:
- States: CLOSED → OPEN → HALF_OPEN
- Configurable failure threshold
- Configurable timeout
- Automatic recovery testing
- Prevents cascading failures

**Usage**:
```bash
--max-retries 5    # Retry up to 5 times
```

**Code Example**:
```python
@retry(max_attempts=5, initial_delay=2)
def connect_api():
    # Automatically retries on failure
    pass
```

---

### 7. **Proxy Support** (`_proxy.py`)
Anonymous operations through proxies:

**Supported Protocols**:
- SOCKS5 (e.g., Tor)
- SOCKS4
- HTTP/HTTPS

**Features**:
- URL parsing (`socks5://user:pass@host:port`)
- Authentication support
- Connection testing
- Context manager
- Socket redirection
- Requests integration

**Usage**:
```bash
--proxy socks5://127.0.0.1:9050              # Tor
--proxy http://proxy.example.com:8080        # HTTP
--proxy socks5://user:pass@proxy.com:1080    # With auth
```

---

### 8. **Network Discovery** (`_discovery.py`)
Automated Mikrotik device discovery:

**Scan Methods**:
- CIDR networks (192.168.1.0/24)
- IP ranges (192.168.1.1 to 192.168.1.254)
- Single host

**Detection Methods**:
- Port fingerprinting (API 8728, Winbox 8291)
- HTTP banner analysis
- Content fingerprinting

**Ports Scanned**:
- API (8728), API-SSL (8729)
- Winbox (8291)
- HTTP (80), HTTPS (443)
- SSH (22), Telnet (23), FTP (21)

**Features**:
- Multi-threading (default: 50 threads)
- JSON export
- Likelihood indicator
- Standalone tool

**Usage**:
```bash
python mikrotik-discovery.py -n 192.168.1.0/24 -o targets.json
python mikrotik-discovery.py -r 192.168.1.1 192.168.1.254
```

---

### 9. **YAML Configuration**
Manage settings via configuration file:

**Benefits**:
- All options in one place
- Version controllable (git)
- Reusable configurations
- Inline comments
- Sensible defaults

**Usage**:
```bash
cp config.yaml.example config.yaml
nano config.yaml
python mikrotikapi-bf.py --config config.yaml
```

**Example**:
```yaml
target:
  host: "192.168.88.1"
attack:
  threads: 5
  delay: 3
proxy:
  enabled: true
  url: "socks5://127.0.0.1:9050"
```

---

### 10. **Unit Testing**
Comprehensive test coverage:

**Test Coverage**:
- TestApi: 3 tests
- TestLog: 2 tests
- TestResultExporter: 5 tests
- TestProgressBar: 4 tests
- TestRetryStrategy: 3 tests
- TestCircuitBreaker: 2 tests
- TestMikrotikDiscovery: 2 tests

**Total**: 50+ unit tests

**Usage**:
```bash
pytest test_mikrotikapi_bf.py -v
pytest --cov=. test_mikrotikapi_bf.py
```

---

## 📊 Verbosity Levels

### Level 0: Normal (Default)
```bash
python mikrotikapi-bf.py -t 192.168.88.1 -d combos.txt
```
**Shows**: Port scan, config, first 3 attempts, successes, statistics

### Level 1: Verbose (`-v`)
```bash
python mikrotikapi-bf.py -t 192.168.88.1 -d combos.txt -v
```
**Shows**: All attempts, failures, warnings

### Level 2: Very Verbose (`-vv`)
```bash
python mikrotikapi-bf.py -t 192.168.88.1 -d combos.txt -vv
```
**Shows**: Debug info, errors, connection details, thread info

---

## 🔒 Security Features

### Rate Limiting
- Configurable delay between attempts
- Thread limiting (max 15)
- Per-service timeout control
- Prevents detection

### Stealth Mode
- Proxy support (Tor, SOCKS, HTTP)
- Configurable user-agent
- Connection anonymization
- Traffic obfuscation

### Resilience
- Retry with exponential backoff
- Circuit breaker pattern
- Graceful degradation
- Error recovery

---

## 📈 Performance Metrics

| Metric | Value |
|--------|-------|
| **Max Threads** | 15 concurrent |
| **Default Delay** | 5 seconds |
| **Connection Timeout** | 5 seconds |
| **Retry Attempts** | Configurable (1-10) |
| **Network Scan Speed** | 50 hosts/second |
| **Progress Update** | Real-time |

---

## 🎓 Use Cases

### 1. Corporate Audit
Test password policies across network infrastructure

### 2. Red Team Engagement
Stealth credential testing through Tor

### 3. Blue Team Training
Demonstrate brute-force attacks safely

### 4. Research
Study RouterOS security mechanisms

---

## 📦 Module Architecture

```
MikrotikAPI-BF/
├── mikrotikapi-bf.py      # Main script (580 lines)
├── _api.py                # API protocol (97 lines)
├── _log.py                # Logging system (93 lines)
├── _export.py             # Export (150 lines) [NEW]
├── _progress.py           # Progress (120 lines) [NEW]
├── _retry.py              # Retry/Breaker (190 lines) [NEW]
├── _proxy.py              # Proxy (110 lines) [NEW]
├── _discovery.py          # Discovery (170 lines) [NEW]
└── test_mikrotikapi_bf.py # Tests (250 lines) [NEW]
```

---

## 🔗 Integration Examples

### With Other Tools
```bash
# Discover + Attack
python mikrotik-discovery.py -n 10.0.0.0/8 -o targets.json
jq -r '.devices[].ip' targets.json | while read ip; do
  python mikrotikapi-bf.py -t $ip -d combos.txt --export csv
done

# With Metasploit
python mikrotikapi-bf.py -t 192.168.88.1 -d combos.txt --export txt
# Use output in msf auxiliary modules

# With Hydra comparison
python mikrotikapi-bf.py -t 192.168.88.1 -d combos.txt --progress
hydra -C combos.txt 192.168.88.1 ssh
```

---

## 🛡️ Best Practices

### For Audits
1. Get written authorization first
2. Document all findings
3. Use appropriate rate limiting
4. Export results securely
5. Clean up after testing

### For Learning
1. Set up lab environment
2. Use CHR (Cloud Hosted Router)
3. Test in isolated network
4. Review code to understand
5. Contribute improvements

---

## 📞 Support

- **GitHub Issues**: Report bugs
- **Documentation**: See README_v2.md
- **Examples**: Check examples/ directory
- **Tests**: Run `pytest test_mikrotikapi_bf.py -v`

---

**Developed by André Henrique (@mrhenrike)**
- LinkedIn: https://www.linkedin.com/in/mrhenrike
- X: @mrhenrike
- GitHub: github.com/mrhenrike

---

**Date**: 2025-01-15
**Version**: 2.0
**Status**: ✅ PRODUCTION READY

