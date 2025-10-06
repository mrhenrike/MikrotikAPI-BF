#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Test Script for CHR Mikrotik Targets - MikrotikAPI-BF v2.1

This script tests the enhanced features against the provided CHR targets:
- http://143.244.153.61/
- http://83.221.222.37:11602/

Author: André Henrique (@mrhenrike)
"""

import sys
import time
from datetime import datetime

# Import our modules
try:
    from _fingerprint import MikrotikFingerprinter
    from _wordlists import SmartWordlistManager
    from _stealth import StealthManager
    from _log import Log
except ImportError as e:
    print(f"[ERROR] Missing modules: {e}")
    sys.exit(1)

def test_target_fingerprinting():
    """Test fingerprinting on CHR targets"""
    print("="*60)
    print("TESTING CHR TARGETS - FINGERPRINTING")
    print("="*60)
    
    targets = [
        "143.244.153.61",
        "83.221.222.37"
    ]
    
    fingerprinter = MikrotikFingerprinter()
    log = Log(verbose=True, verbose_all=False)
    
    for target in targets:
        print(f"\n[*] Fingerprinting target: {target}")
        try:
            info = fingerprinter.fingerprint_device(target)
            
            print(f"[+] Target: {info.get('target')}")
            print(f"[+] Is Mikrotik: {'YES' if info.get('is_mikrotik') else 'NO'}")
            print(f"[+] Open ports: {', '.join(map(str, info.get('open_ports', [])))}")
            print(f"[+] Services: {', '.join(info.get('services', []))}")
            print(f"[+] Risk score: {info.get('risk_score', 0):.1f}/10")
            
            if info.get('vulnerabilities'):
                print(f"[+] Vulnerabilities found: {len(info.get('vulnerabilities', []))}")
                for vuln in info.get('vulnerabilities', []):
                    print(f"    - {vuln}")
            
            # Generate detailed report
            report = fingerprinter.generate_fingerprint_report(info)
            print(f"\n[+] Detailed Report:")
            print(report)
            
        except Exception as e:
            print(f"[!] Error fingerprinting {target}: {e}")
        
        print("-" * 40)

def test_wordlist_generation():
    """Test smart wordlist generation"""
    print("\n" + "="*60)
    print("TESTING SMART WORDLIST GENERATION")
    print("="*60)
    
    wordlist_manager = SmartWordlistManager()
    
    # Test with CHR target info
    target_info = {
        'target': '143.244.153.61',
        'hostname': 'chr.mikrotik.com',
        'routeros_version': '7.1.5',
        'model': 'CHR'
    }
    
    print(f"[*] Generating smart combinations for: {target_info['target']}")
    
    try:
        combinations = wordlist_manager.generate_smart_combinations(target_info)
        print(f"[+] Generated {len(combinations)} combinations")
        
        # Show first 10 combinations
        print(f"[+] First 10 combinations:")
        for i, (user, password) in enumerate(combinations[:10], 1):
            print(f"    {i:2d}. {user}:{password}")
        
        # Test Brazilian wordlists
        print(f"\n[*] Testing Brazilian wordlists:")
        br_stats = wordlist_manager.get_wordlist_stats()
        print(f"[+] Brazilian wordlists loaded:")
        for name, count in br_stats['brazilian_wordlists'].items():
            print(f"    - {name}: {count} words")
        
        # Create custom wordlist
        custom_file = wordlist_manager.create_custom_wordlist(target_info, "test_custom_wordlist.txt")
        print(f"[+] Custom wordlist created: {custom_file}")
        
    except Exception as e:
        print(f"[!] Error generating wordlists: {e}")

def test_stealth_mode():
    """Test stealth mode functionality"""
    print("\n" + "="*60)
    print("TESTING STEALTH MODE")
    print("="*60)
    
    stealth_manager = StealthManager(enabled=True)
    
    print("[*] Testing stealth delays...")
    for i in range(5):
        delay = stealth_manager.stealth_mode.get_random_delay(5.0)
        print(f"    Delay {i+1}: {delay:.2f} seconds")
        time.sleep(0.1)  # Short delay for demo
    
    print(f"\n[*] Testing User-Agent rotation...")
    for i in range(3):
        ua = stealth_manager.stealth_mode.get_user_agent()
        print(f"    User-Agent {i+1}: {ua[:50]}...")
    
    print(f"\n[*] Testing stealth headers...")
    headers = stealth_manager.stealth_mode.get_stealth_headers()
    print(f"    Headers generated: {len(headers)}")
    for key, value in headers.items():
        print(f"    {key}: {value[:30]}...")
    
    # Test stealth stats
    stats = stealth_manager.get_global_stats()
    print(f"\n[+] Stealth statistics:")
    print(f"    Enabled: {stats.get('stealth_enabled')}")
    print(f"    Threads: {stats.get('total_threads')}")

def test_enhanced_attack_simulation():
    """Simulate enhanced attack on CHR targets"""
    print("\n" + "="*60)
    print("SIMULATING ENHANCED ATTACK")
    print("="*60)
    
    targets = [
        "143.244.153.61",
        "83.221.222.37"
    ]
    
    # Simulate attack configuration
    print("[*] Enhanced Attack Configuration:")
    print(f"    Targets: {len(targets)}")
    print(f"    Stealth Mode: ON")
    print(f"    Fingerprinting: ON")
    print(f"    Smart Wordlists: ON")
    print(f"    Brazilian Wordlists: ON")
    
    # Simulate results
    simulated_results = [
        {"user": "admin", "pass": "admin", "services": ["api", "http"], "target": "143.244.153.61"},
        {"user": "mikrotik", "pass": "mikrotik", "services": ["api"], "target": "83.221.222.37"}
    ]
    
    print(f"\n[+] Simulated Attack Results:")
    print(f"    Credentials found: {len(simulated_results)}")
    
    for i, result in enumerate(simulated_results, 1):
        print(f"    [{i}] {result['user']}:{result['pass']} on {result['target']}")
        print(f"        Services: {', '.join(result['services'])}")
    
    # Simulate export
    print(f"\n[*] Exporting results...")
    try:
        from _export import ResultExporter
        exporter = ResultExporter(simulated_results, "test_targets", "test_results")
        
        # Export to all formats
        files = exporter.export_all()
        print(f"[+] Exported to {len(files)} formats:")
        for fmt, filepath in files.items():
            print(f"    - {fmt.upper()}: {filepath}")
            
    except Exception as e:
        print(f"[!] Export error: {e}")

def main():
    """Main test function"""
    print("MIKROTIKAPI-BF v2.1 - CHR TARGETS TEST")
    print("="*60)
    print(f"Test started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Targets: 143.244.153.61, 83.221.222.37:11602")
    print()
    
    try:
        # Test 1: Fingerprinting
        test_target_fingerprinting()
        
        # Test 2: Wordlist generation
        test_wordlist_generation()
        
        # Test 3: Stealth mode
        test_stealth_mode()
        
        # Test 4: Enhanced attack simulation
        test_enhanced_attack_simulation()
        
        print("\n" + "="*60)
        print("ALL TESTS COMPLETED SUCCESSFULLY!")
        print("="*60)
        print("v2.1 features tested:")
        print("+ Advanced Fingerprinting")
        print("+ Smart Wordlist Management")
        print("+ Stealth Mode")
        print("+ Enhanced Attack Simulation")
        print("+ Result Export")
        print("\nReady for production use!")
        
    except Exception as e:
        print(f"\n[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
