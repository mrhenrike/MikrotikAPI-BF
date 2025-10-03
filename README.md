# Mikrotik RouterOS API Bruteforce Tool v2.0
[![Latest Version](https://img.shields.io/badge/version-2.0-blue)](https://github.com/mrhenrike/MikrotikAPI-BF)
![Supported Python versions](https://img.shields.io/badge/Python-3.8--3.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## 🚀 What's New in v2.0

### Major Enhancements
- ✨ **Export Results**: JSON, CSV, XML, TXT formats
- 📊 **Progress Bar**: Visual progress with ETA and speed
- 🔄 **Retry Mechanism**: Exponential backoff for failed connections
- 🌐 **Proxy Support**: SOCKS5, SOCKS4, HTTP proxies for stealth
- 🔍 **Network Discovery**: Scan entire networks for Mikrotik devices
- ⚙️ **Configuration Files**: YAML/JSON config support
- 🧪 **Unit Tests**: Comprehensive test suite with pytest
- 🔒 **Circuit Breaker**: Prevents cascading failures
- ⏸️ **Better Error Handling**: Improved exception management

---

## Description
MikrotikAPI-BF is a professional Python-based brute-force tool designed to test Mikrotik RouterOS credentials via its API (port 8728) and validate successful logins against additional services such as FTP, SSH, and TELNET.

> **ALERT**: This tool was crafted for educational, research, and auditing purposes in penetration testing labs, red teaming environments, and training exercises.

---

## 📦 Installation

### Quick Install
```bash
git clone https://github.com/mrhenrike/MikrotikAPI-BF
cd MikrotikAPI-BF
pip install -r requirements.txt
```

### Python 3.12 Installation

#### Linux (Kali/Ubuntu/Parrot)
```bash
chmod +x install-python-3.12.sh
./install-python-3.12.sh
```

#### Windows
```powershell
Set-ExecutionPolicy RemoteSigned
.\install-python-3.12.ps1
```

---

## 🎯 Features

### Core Features
- ✅ RouterOS API authentication testing (port 8728)
- ✅ REST-API testing (HTTP/HTTPS)
- ✅ Post-login service validation (FTP, SSH, TELNET)
- ✅ Multi-threading (max 15 threads)
- ✅ SSL/TLS support
- ✅ Combo dictionary support (user:pass)
- ✅ Verbosity levels (-v, -vv)

### New Features
- ✨ **Result Export**: Save results in JSON, CSV, XML, TXT
- 📊 **Progress Tracking**: Real-time progress bar with ETA
- 🔄 **Smart Retry**: Exponential backoff for network issues
- 🌐 **Proxy Chains**: Route traffic through SOCKS5/HTTP proxies
- 🔍 **Network Scanner**: Discover Mikrotik devices automatically
- ⚙️ **Config Files**: Use YAML configuration files
- 🔒 **Circuit Breaker**: Automatic failure protection

---

## 📖 Usage

### Basic Usage
```bash
python mikrotikapi-bf.py -t 192.168.88.1 -U admin -P password123
```

### Using Configuration File
```bash
# Copy example config
cp config.yaml.example config.yaml

# Edit config.yaml with your settings
nano config.yaml

# Run with config
python mikrotikapi-bf.py --config config.yaml
```

### Network Discovery
```bash
# Discover Mikrotik devices on network
python mikrotik-discovery.py -n 192.168.1.0/24

# Scan IP range
python mikrotik-discovery.py -r 192.168.1.1 192.168.1.254

# Export results
python mikrotik-discovery.py -n 192.168.1.0/24 -o discovered.json
```

### Export Results
```bash
# Auto-export to all formats
python mikrotikapi-bf.py -t 192.168.88.1 -d combos.txt --export-all

# Export specific formats
python mikrotikapi-bf.py -t 192.168.88.1 -d combos.txt --export json,csv

# Specify output directory
python mikrotikapi-bf.py -t 192.168.88.1 -d combos.txt --export-dir ./results
```

### Using Proxy
```bash
# SOCKS5 proxy (Tor)
python mikrotikapi-bf.py -t 192.168.88.1 -d combos.txt --proxy socks5://127.0.0.1:9050

# HTTP proxy
python mikrotikapi-bf.py -t 192.168.88.1 -d combos.txt --proxy http://proxy.example.com:8080

# SOCKS5 with authentication
python mikrotikapi-bf.py -t 192.168.88.1 -d combos.txt --proxy socks5://user:pass@proxy.com:1080
```

### Advanced Options
```bash
# Enable progress bar
python mikrotikapi-bf.py -t 192.168.88.1 -d combos.txt --progress

# Retry with backoff
python mikrotikapi-bf.py -t 192.168.88.1 -d combos.txt --max-retries 5

# Circuit breaker
python mikrotikapi-bf.py -t 192.168.88.1 -d combos.txt --circuit-breaker
```

---

## 🔧 Configuration File Example

```yaml
# config.yaml
target:
  host: "192.168.88.1"
  api_port: 8728
  use_ssl: false

attack:
  delay: 5
  threads: 2
  max_retries: 3

credentials:
  dictionary: "combos.txt"

validation:
  enabled: true
  services:
    ftp:
      enabled: true
      port: 21
    ssh:
      enabled: true
      port: 22

proxy:
  enabled: true
  url: "socks5://127.0.0.1:9050"

output:
  verbosity: 1
  progress_bar: true
  export:
    enabled: true
    formats:
      - json
      - csv
```

---

## 📊 Output Examples

### Progress Bar
```
[████████████████████░░░░░░░░░░] 65.4% (327/500) | ✓ 3 | 12.5 attempts/s | ETA: 0:00:14
```

### Export Formats

#### JSON
```json
{
  "scan_info": {
    "target": "192.168.88.1",
    "timestamp": "2025-01-15T10:30:00",
    "total_found": 2
  },
  "credentials": [
    {
      "user": "admin",
      "pass": "password123",
      "services": ["api", "ftp", "ssh"]
    }
  ]
}
```

#### CSV
```csv
username,password,services
admin,password123,"api, ftp, ssh"
manager,mikrotik,"api"
```

---

## 🧪 Testing

Run unit tests:
```bash
# Install pytest
pip install pytest

# Run all tests
pytest test_mikrotikapi_bf.py -v

# Run specific test
pytest test_mikrotikapi_bf.py::TestApi::test_api_initialization -v

# With coverage
pytest --cov=. test_mikrotikapi_bf.py
```

---

## 🌐 Proxy Setup Examples

### Tor (SOCKS5)
```bash
# Start Tor service
sudo service tor start

# Use Tor proxy
python mikrotikapi-bf.py -t 192.168.88.1 -d combos.txt \
  --proxy socks5://127.0.0.1:9050
```

### SSH Tunnel (SOCKS5)
```bash
# Create SSH tunnel
ssh -D 8080 -N user@jump-server.com

# Use tunnel
python mikrotikapi-bf.py -t 192.168.88.1 -d combos.txt \
  --proxy socks5://127.0.0.1:8080
```

---

## 📋 Command-Line Options

### Target
```
-t, --target       Mikrotik IP address (required)
--api-port         API port (default: 8728)
--rest-port        REST API port (default: 8729)
--http-port        HTTP port (default: 80)
--ssl-port         HTTPS port (default: 443)
--ssl              Use SSL/TLS
```

### Credentials
```
-U, --user         Single username
-P, --passw        Single password
-u, --userlist     Path to user wordlist
-p, --passlist     Path to password wordlist
-d, --dictionary   Path to combo wordlist (user:pass)
```

### Performance
```
-s, --seconds      Delay between attempts (default: 5)
--threads          Number of threads (default: 2, max: 15)
--max-retries      Max retry attempts (default: 3)
--timeout          Connection timeout (default: 5)
```

### Validation
```
--validate         Services to validate (ftp,ssh,telnet)
                   Example: --validate ftp,ssh=2222,telnet
```

### Proxy & Stealth
```
--proxy            Proxy URL (socks5://host:port)
--user-agent       Custom user agent
--circuit-breaker  Enable circuit breaker
```

### Output
```
-v, --verbose      Show failed attempts
-vv, --verbose-all Show debug output
--progress         Show progress bar
--export           Export formats (json,csv,xml,txt)
--export-dir       Export directory (default: results)
--export-all       Export to all formats
```

### Discovery
```
--discover         Enable discovery mode
-n, --network      Network CIDR (e.g., 192.168.1.0/24)
--discover-threads Threads for discovery (default: 50)
```

### Configuration
```
-c, --config       Load settings from YAML file
```

---

## 🔒 Security Features

### Retry with Backoff
Prevents detection by spacing out retries:
```python
Attempt 1: Wait 1 second
Attempt 2: Wait 2 seconds
Attempt 3: Wait 4 seconds
Attempt 4: Wait 8 seconds
...
```

### Circuit Breaker
Automatically stops attacking unresponsive targets:
- Opens after 5 failures
- Waits 60 seconds before retry
- Closes after 2 successes

### Rate Limiting
- Configurable delay between attempts
- Thread limiting (max 15)
- Per-service timeout control

---

## 📚 Module Documentation

### `_api.py`
RouterOS API protocol implementation
- Socket communication
- Length encoding/decoding
- Authentication handling

### `_log.py`
Colored logging system
- Verbosity levels
- Timestamp formatting
- Cross-platform colors

### `_export.py`
Result export functionality
- JSON, CSV, XML, TXT formats
- Automatic timestamping
- Safe filename generation

### `_progress.py`
Progress tracking
- Real-time progress bar
- ETA calculation
- Speed monitoring
- Spinner animation

### `_retry.py`
Retry and circuit breaker
- Exponential backoff
- Circuit breaker pattern
- Decorator support

### `_proxy.py`
Proxy management
- SOCKS5/SOCKS4/HTTP support
- Authentication handling
- Connection testing

### `_discovery.py`
Network discovery
- Port scanning
- Device identification
- CIDR/range support

---

## 🎓 Examples

### Example 1: Basic Audit
```bash
python mikrotikapi-bf.py \
  -t 192.168.88.1 \
  -u usernames.txt \
  -p common_passwords.txt \
  --progress \
  --export json
```

### Example 2: Stealth Attack
```bash
python mikrotikapi-bf.py \
  -t target.com \
  -d combos.txt \
  --proxy socks5://127.0.0.1:9050 \
  --threads 1 \
  --seconds 10 \
  --max-retries 5
```

### Example 3: Full Validation
```bash
python mikrotikapi-bf.py \
  -t 192.168.88.1 \
  -d found_creds.txt \
  --validate ftp,ssh,telnet \
  --export-all \
  -vv
```

### Example 4: Network Discovery + Attack
```bash
# Step 1: Discover
python mikrotik-discovery.py -n 192.168.1.0/24 -o targets.json

# Step 2: Attack each target
for ip in $(jq -r '.devices[].ip' targets.json); do
  python mikrotikapi-bf.py -t $ip -d combos.txt --export csv
done
```

---

## 🐛 Troubleshooting

### ImportError: No module named 'socks'
```bash
pip install PySocks
```

### telnetlib not found (Python 3.13+)
```bash
# Use Python 3.12
python3.12 mikrotikapi-bf.py [options]
```

### Connection timeout
```bash
# Increase timeout
python mikrotikapi-bf.py -t 192.168.88.1 -d combos.txt --timeout 10
```

### Proxy connection failed
```bash
# Test proxy first
curl --proxy socks5://127.0.0.1:9050 https://check.torproject.org
```

---

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

---

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file.

---

## 👤 Author

**André Henrique**
- LinkedIn: [@mrhenrike](https://www.linkedin.com/in/mrhenrike)
- Instagram: [@uniaogeek](https://instagram.com/uniaogeek)
- X: [@mrhenrike](https://x.com/mrhenrike)
- GitHub: [github.com/mrhenrike](https://github.com/mrhenrike)

---

## ⚠️ Disclaimer

Usage of this software for attacking targets without prior consent is **illegal**. It's the end user's responsibility to obey all applicable laws. The developer is not responsible for any misuse of these functions.

This tool is intended for:
- ✅ Authorized penetration testing
- ✅ Security audits with permission
- ✅ Educational purposes
- ✅ Research in controlled environments
- ❌ Unauthorized access attempts
- ❌ Malicious activities

---

## 🙏 Acknowledgments

Based on:
- [Mikrotik API Python3](https://wiki.mikrotik.com/wiki/Manual:API_Python3)
- [MKBRUTUS](http://mkbrutusproject.github.io/MKBRUTUS/)
- [RouterOS_API](https://github.com/DEssMALA/RouterOS_API)

---

## 📊 Project Stats

- **Version**: 2.0
- **Python**: 3.8 - 3.12
- **Modules**: 10+
- **Tests**: 50+ unit tests
- **Platforms**: Windows, Linux, macOS
- **License**: MIT

---

## 🔗 Links

- 🐛 [Issue Tracker](https://github.com/mrhenrike/MikrotikAPI-BF/issues)
- 📦 [Releases](https://github.com/mrhenrike/MikrotikAPI-BF/releases)

