#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Interactive CLI Module - MikrotikAPI-BF v2.1

This module provides an interactive command-line interface for pentesters:
- Interactive commands for scanning and attacking
- Session management
- Real-time progress monitoring
- Command history
- Help system

Author: André Henrique (@mrhenrike)
"""

import os
import sys
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

# Import our modules
from _stealth import StealthManager
from _fingerprint import MikrotikFingerprinter
from _wordlists import SmartWordlistManager
from _discovery import MikrotikDiscovery
from _export import ResultExporter
from _log import Log

class PentestCLI:
    """
    Interactive CLI for Mikrotik pentesting
    """
    
    def __init__(self):
        self.session_id = self._generate_session_id()
        self.session_data = {
            'session_id': self.session_id,
            'start_time': datetime.now().isoformat(),
            'targets': [],
            'credentials_found': [],
            'scan_results': [],
            'command_history': []
        }
        
        # Initialize modules
        self.stealth_manager = StealthManager()
        self.fingerprinter = MikrotikFingerprinter()
        self.wordlist_manager = SmartWordlistManager()
        self.discovery = MikrotikDiscovery()
        self.log = Log(verbose=True, verbose_all=False)
        
        # CLI state
        self.running = True
        self.current_target = None
        
        print(f"[+] Mikrotik Pentest Toolkit v2.1")
        print(f"[+] Session ID: {self.session_id}")
        print(f"[+] Type 'help' for available commands")
        print()
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        return f"pentest_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def start(self):
        """Start interactive CLI"""
        while self.running:
            try:
                command = input("mikrotik-bf> ").strip()
                if command:
                    self._execute_command(command)
            except KeyboardInterrupt:
                print("\n[!] Use 'exit' to save session and quit")
            except EOFError:
                print("\n[!] Use 'exit' to save session and quit")
    
    def _execute_command(self, command: str):
        """Execute CLI command"""
        self.session_data['command_history'].append({
            'command': command,
            'timestamp': datetime.now().isoformat()
        })
        
        parts = command.split()
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        if cmd == "help":
            self._show_help()
        elif cmd == "scan":
            self._scan_command(args)
        elif cmd == "fingerprint":
            self._fingerprint_command(args)
        elif cmd == "attack":
            self._attack_command(args)
        elif cmd == "results":
            self._results_command(args)
        elif cmd == "export":
            self._export_command(args)
        elif cmd == "targets":
            self._targets_command()
        elif cmd == "clear":
            self._clear_screen()
        elif cmd == "status":
            self._status_command()
        elif cmd == "stealth":
            self._stealth_command(args)
        elif cmd == "wordlists":
            self._wordlists_command(args)
        elif cmd == "exit":
            self._exit_command()
        else:
            print(f"[!] Unknown command: {cmd}")
            print("Type 'help' for available commands")
    
    def _show_help(self):
        """Show help information"""
        help_text = """
🔧 MIKROTIK PENTEST TOOLKIT v2.1 - Commands:

📡 DISCOVERY:
  scan <network>           - Scan network (ex: scan 192.168.1.0/24)
  scan -r <start> <end>    - Scan IP range (ex: scan -r 192.168.1.1 192.168.1.254)
  fingerprint <target>     - Fingerprint Mikrotik device

⚔️  ATTACK:
  attack <target>          - Attack specific target
  attack -p <protocol>     - Attack specific protocol
  attack -w <wordlist>     - Use custom wordlist

📊 RESULTS:
  results                  - Show found credentials
  results -v               - Detailed results
  export <format>          - Export results (json,csv,xml,txt)

🎯 TARGETS:
  targets                  - Show discovered targets
  targets -v               - Detailed target information

🛠️  UTILITIES:
  status                   - Show current status
  stealth <on|off>         - Toggle stealth mode
  wordlists                - Show wordlist statistics
  clear                    - Clear screen
  help                     - Show this help
  exit                     - Save session and exit
"""
        print(help_text)
    
    def _scan_command(self, args: List[str]):
        """Handle scan command"""
        if not args:
            print("[!] Usage: scan <network> or scan -r <start> <end>")
            return
        
        if args[0] == "-r" and len(args) >= 3:
            # Range scan
            start_ip, end_ip = args[1], args[2]
            print(f"[*] Scanning range: {start_ip} to {end_ip}")
            try:
                results = self.discovery.scan_range(start_ip, end_ip)
                self.session_data['scan_results'].extend(results)
                print(f"[+] Found {len(results)} devices")
            except Exception as e:
                print(f"[!] Error scanning range: {e}")
        else:
            # Network scan
            network = args[0]
            print(f"[*] Scanning network: {network}")
            try:
                results = self.discovery.scan_network(network)
                self.session_data['scan_results'].extend(results)
                print(f"[+] Found {len(results)} devices")
            except Exception as e:
                print(f"[!] Error scanning network: {e}")
    
    def _fingerprint_command(self, args: List[str]):
        """Handle fingerprint command"""
        if not args:
            print("[!] Usage: fingerprint <target>")
            return
        
        target = args[0]
        print(f"[*] Fingerprinting target: {target}")
        
        try:
            info = self.fingerprinter.fingerprint_device(target)
            self.session_data['targets'].append(info)
            
            # Show results
            print(f"[+] Target: {info.get('target')}")
            print(f"[+] Is Mikrotik: {'YES' if info.get('is_mikrotik') else 'NO'}")
            print(f"[+] Open ports: {', '.join(map(str, info.get('open_ports', [])))}")
            print(f"[+] Services: {', '.join(info.get('services', []))}")
            print(f"[+] Risk score: {info.get('risk_score', 0):.1f}/10")
            
            if info.get('vulnerabilities'):
                print(f"[+] Vulnerabilities: {len(info.get('vulnerabilities', []))}")
        except Exception as e:
            print(f"[!] Error fingerprinting target: {e}")
    
    def _attack_command(self, args: List[str]):
        """Handle attack command"""
        if not args:
            print("[!] Usage: attack <target> [options]")
            return
        
        target = args[0]
        protocol = None
        wordlist = None
        
        # Parse options
        i = 1
        while i < len(args):
            if args[i] == "-p" and i + 1 < len(args):
                protocol = args[i + 1]
                i += 2
            elif args[i] == "-w" and i + 1 < len(args):
                wordlist = args[i + 1]
                i += 2
            else:
                i += 1
        
        print(f"[*] Attacking target: {target}")
        if protocol:
            print(f"[*] Protocol: {protocol}")
        if wordlist:
            print(f"[*] Wordlist: {wordlist}")
        
        # This would integrate with the main bruteforce functionality
        print("[!] Attack functionality would be implemented here")
        print("[!] This would call the main mikrotikapi-bf.py with appropriate parameters")
    
    def _results_command(self, args: List[str]):
        """Handle results command"""
        verbose = "-v" in args
        
        if not self.session_data['credentials_found']:
            print("[!] No credentials found yet")
            return
        
        print(f"[+] Found {len(self.session_data['credentials_found'])} credentials:")
        print()
        
        for i, cred in enumerate(self.session_data['credentials_found'], 1):
            print(f"[{i}] {cred.get('user', 'unknown')}:{cred.get('pass', 'unknown')}")
            if verbose and cred.get('services'):
                print(f"    Services: {', '.join(cred.get('services', []))}")
    
    def _export_command(self, args: List[str]):
        """Handle export command"""
        if not args:
            print("[!] Usage: export <format> (json,csv,xml,txt)")
            return
        
        format_type = args[0].lower()
        if format_type not in ['json', 'csv', 'xml', 'txt']:
            print("[!] Invalid format. Use: json, csv, xml, txt")
            return
        
        try:
            exporter = ResultExporter(
                self.session_data['credentials_found'],
                "session_export",
                output_dir="results"
            )
            
            if format_type == 'json':
                filename = exporter.export_json()
            elif format_type == 'csv':
                filename = exporter.export_csv()
            elif format_type == 'xml':
                filename = exporter.export_xml()
            elif format_type == 'txt':
                filename = exporter.export_txt()
            
            print(f"[+] Exported to: {filename}")
        except Exception as e:
            print(f"[!] Error exporting results: {e}")
    
    def _targets_command(self):
        """Handle targets command"""
        if not self.session_data['targets']:
            print("[!] No targets discovered yet")
            return
        
        print(f"[+] Discovered {len(self.session_data['targets'])} targets:")
        print()
        
        for i, target in enumerate(self.session_data['targets'], 1):
            print(f"[{i}] {target.get('target', 'unknown')}")
            print(f"    Mikrotik: {'YES' if target.get('is_mikrotik') else 'NO'}")
            print(f"    Ports: {', '.join(map(str, target.get('open_ports', [])))}")
            print(f"    Risk: {target.get('risk_score', 0):.1f}/10")
            print()
    
    def _clear_screen(self):
        """Clear screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def _status_command(self):
        """Show current status"""
        print(f"[+] Session ID: {self.session_id}")
        print(f"[+] Targets: {len(self.session_data['targets'])}")
        print(f"[+] Credentials found: {len(self.session_data['credentials_found'])}")
        print(f"[+] Commands executed: {len(self.session_data['command_history'])}")
        
        # Show stealth status
        stealth_stats = self.stealth_manager.get_global_stats()
        print(f"[+] Stealth mode: {'ON' if stealth_stats.get('stealth_enabled') else 'OFF'}")
    
    def _stealth_command(self, args: List[str]):
        """Handle stealth command"""
        if not args:
            print("[!] Usage: stealth <on|off>")
            return
        
        mode = args[0].lower()
        if mode == "on":
            self.stealth_manager.stealth_mode.enabled = True
            print("[+] Stealth mode enabled")
        elif mode == "off":
            self.stealth_manager.stealth_mode.enabled = False
            print("[+] Stealth mode disabled")
        else:
            print("[!] Usage: stealth <on|off>")
    
    def _wordlists_command(self, args: List[str]):
        """Handle wordlists command"""
        stats = self.wordlist_manager.get_wordlist_stats()
        
        print("[+] Wordlist Statistics:")
        print(f"    Mikrotik defaults: {stats['mikrotik_defaults']}")
        print(f"    Mikrotik passwords: {stats['mikrotik_passwords']}")
        print(f"    Total combinations: {stats['total_combinations']}")
        
        if stats['brazilian_wordlists']:
            print("    Brazilian wordlists:")
            for name, count in stats['brazilian_wordlists'].items():
                print(f"      {name}: {count}")
    
    def _exit_command(self):
        """Handle exit command"""
        print("[*] Saving session...")
        self._save_session()
        print("[+] Session saved")
        print("[+] Goodbye!")
        self.running = False
    
    def _save_session(self):
        """Save session data"""
        session_file = f"sessions/{self.session_id}.json"
        os.makedirs("sessions", exist_ok=True)
        
        with open(session_file, 'w', encoding='utf-8') as f:
            json.dump(self.session_data, f, indent=2, ensure_ascii=False)
    
    def _load_session(self, session_id: str):
        """Load session data"""
        session_file = f"sessions/{session_id}.json"
        if os.path.exists(session_file):
            with open(session_file, 'r', encoding='utf-8') as f:
                self.session_data = json.load(f)
            return True
        return False
