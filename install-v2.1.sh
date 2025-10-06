#!/bin/bash

# MikrotikAPI-BF v2.1 Installation Script
# Author: André Henrique (@mrhenrike)

echo "=========================================="
echo "MikrotikAPI-BF v2.1 Installation Script"
echo "=========================================="
echo

# Check Python version
echo "[*] Checking Python version..."
python_version=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then
    echo "[+] Python version $python_version is supported"
else
    echo "[!] Python version $python_version is not supported. Required: >= 3.8"
    echo "[*] Installing Python 3.12..."
    chmod +x install-python-3.12.sh
    ./install-python-3.12.sh
fi

# Install dependencies
echo
echo "[*] Installing dependencies..."
pip3 install -r requirements.txt

# Create necessary directories
echo
echo "[*] Creating directories..."
mkdir -p results
mkdir -p sessions
mkdir -p reports
mkdir -p wordlists

# Make scripts executable
echo
echo "[*] Setting permissions..."
chmod +x mikrotikapi-bf-v2.1.py
chmod +x test_chr_targets.py
chmod +x mikrotik-discovery.py

# Test installation
echo
echo "[*] Testing installation..."
python3 -c "
try:
    from _stealth import StealthManager
    from _fingerprint import MikrotikFingerprinter
    from _wordlists import SmartWordlistManager
    from _reports import PentestReportGenerator
    from _cli import PentestCLI
    print('[+] All v2.1 modules imported successfully')
except ImportError as e:
    print(f'[!] Import error: {e}')
    exit(1)
"

if [ $? -eq 0 ]; then
    echo
    echo "=========================================="
    echo "INSTALLATION COMPLETED SUCCESSFULLY!"
    echo "=========================================="
    echo
    echo "New features available:"
    echo "✓ Stealth Mode (Fibonacci delays, User-Agent rotation)"
    echo "✓ Advanced Fingerprinting"
    echo "✓ Smart Wordlists (Brazilian wordlists included)"
    echo "✓ Interactive CLI"
    echo "✓ Professional Reports"
    echo
    echo "Usage examples:"
    echo "  python3 mikrotikapi-bf-v2.1.py --interactive"
    echo "  python3 mikrotikapi-bf-v2.1.py -t 192.168.1.1 --stealth --fingerprint"
    echo "  python3 test_chr_targets.py"
    echo
    echo "Ready to use! 🚀"
else
    echo
    echo "[!] Installation failed. Please check the errors above."
    exit 1
fi
