#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)

"""
Interactive CLI — MikrotikAPI-BF
==================================
REPL interface for pentesters: scan, fingerprint, attack, export, and view results.
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .log import Log


class PentestCLI:
    """Interactive command-line interface for Mikrotik pentesting."""

    PROMPT = "mikrotik-bf> "

    def __init__(self) -> None:
        self.log = Log(verbose=True)
        self.session_id = f"pentest_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.session_data: Dict = {
            "session_id": self.session_id,
            "start_time": datetime.now().isoformat(),
            "targets": [],
            "credentials_found": [],
            "scan_results": [],
            "command_history": [],
        }
        self._running = True
        self._current_target: Optional[str] = None

        # Lazy imports of feature modules to avoid circular deps
        self._fingerprinter = None
        self._discovery = None
        self._wordlist_mgr = None

        print(f"\n  MikrotikAPI-BF – Interactive Pentest Toolkit")
        print(f"  Session: {self.session_id}")
        print("  Type 'help' for available commands.\n")

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the REPL."""
        while self._running:
            try:
                raw = input(self.PROMPT).strip()
                if raw:
                    self._dispatch(raw)
            except KeyboardInterrupt:
                print("\n  [!] Use 'exit' to save and quit.")
            except EOFError:
                self._cmd_exit([])
                break

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------

    def _dispatch(self, raw: str) -> None:
        self.session_data["command_history"].append(
            {"command": raw, "timestamp": datetime.now().isoformat()}
        )
        parts = raw.split()
        cmd, args = parts[0].lower(), parts[1:]

        dispatch_table = {
            "help": self._cmd_help,
            "scan": self._cmd_scan,
            "fingerprint": self._cmd_fingerprint,
            "attack": self._cmd_attack,
            "results": self._cmd_results,
            "export": self._cmd_export,
            "targets": self._cmd_targets,
            "clear": self._cmd_clear,
            "status": self._cmd_status,
            "stealth": self._cmd_stealth,
            "wordlists": self._cmd_wordlists,
            "exploits": self._cmd_exploits,
            "run": self._cmd_run_exploit,
            "audit": self._cmd_audit,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
        }

        handler = dispatch_table.get(cmd)
        if handler:
            handler(args)
        else:
            print(f"  [!] Unknown command: {cmd}  (type 'help')")

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def _cmd_help(self, _: List[str]) -> None:
        print("""
  DISCOVERY:
    scan <network>              Scan CIDR (e.g. 192.168.1.0/24)
    scan -r <start> <end>       Scan IP range
    fingerprint <target>        Full fingerprint of a Mikrotik device

  ATTACK:
    attack <target>             Brute-force with built-in wordlists
    attack <target> -w <file>   Brute-force with custom wordlist

  EXPLOITATION:
    exploits <target>           Show applicable CVEs / exploits for target
    run <CVE_ID> <target>       Run a specific exploit/PoC check by CVE ID
    audit <target>              Run full 8-phase security audit via REST API

  RESULTS:
    results                     Show found credentials
    results -v                  Detailed view
    export <json|csv|xml|txt>   Export session results

  TARGETS:
    targets                     List discovered targets

  UTILITIES:
    status                      Current session statistics
    stealth <on|off>            Toggle stealth delays
    wordlists                   Show wordlist statistics
    clear                       Clear terminal
    exit / quit                 Save session and quit
""")

    def _cmd_scan(self, args: List[str]) -> None:
        disc = self._get_discovery()
        if not disc:
            return
        if args and args[0] == "-r" and len(args) >= 3:
            print(f"  [*] Scanning range {args[1]}–{args[2]}…")
            try:
                results = disc.scan_range(args[1], args[2])
                self.session_data["scan_results"].extend(results)
                print(f"  [+] Found {len(results)} device(s).")
            except Exception as exc:
                print(f"  [!] Error: {exc}")
        elif args:
            network = args[0]
            print(f"  [*] Scanning {network}…")
            try:
                results = disc.scan_network(network)
                self.session_data["scan_results"].extend(results)
                print(f"  [+] Found {len(results)} device(s).")
            except Exception as exc:
                print(f"  [!] Error: {exc}")
        else:
            print("  [!] Usage: scan <network> | scan -r <start> <end>")

    def _cmd_fingerprint(self, args: List[str]) -> None:
        if not args:
            print("  [!] Usage: fingerprint <target>")
            return
        fp = self._get_fingerprinter()
        if not fp:
            return
        target = args[0]
        print(f"  [*] Fingerprinting {target}…")
        try:
            info = fp.fingerprint_device(target)
            self.session_data["targets"].append(info)
            print(f"  [+] Is Mikrotik  : {'YES' if info.get('is_mikrotik') else 'NO'}")
            print(f"  [+] RouterOS ver : {info.get('routeros_version', 'Unknown')}")
            print(f"  [+] Open ports   : {', '.join(map(str, info.get('open_ports', [])))}")
            print(f"  [+] Services     : {', '.join(info.get('services', []))}")
            print(f"  [+] Risk score   : {info.get('risk_score', 0):.1f}/10")
            if info.get("vulnerabilities"):
                print("  [+] Issues:")
                for v in info["vulnerabilities"]:
                    print(f"        - {v}")
        except Exception as exc:
            print(f"  [!] Error: {exc}")

    def _cmd_attack(self, args: List[str]) -> None:
        if not args:
            print("  [!] Usage: attack <target> [-w <wordlist>]")
            return
        target = args[0]
        wordlist = None
        if "-w" in args:
            idx = args.index("-w")
            if idx + 1 < len(args):
                wordlist = args[idx + 1]

        # Build the CLI invocation message (attack is delegated to the main script)
        cmd = f"python mikrotikapi-bf.py -t {target}"
        if wordlist:
            cmd += f" -d {wordlist}"
        print(f"  [!] To attack from CLI, run:\n      {cmd}")

    def _cmd_exploits(self, args: List[str]) -> None:
        if not args:
            print("  [!] Usage: exploits <target>")
            return
        target = args[0]
        print(f"  [*] Checking exploits for {target}…")
        try:
            from xpl.scanner import ExploitScanner
            scanner = ExploitScanner()
            results = scanner.scan_target(target)
            scanner.print_results(results)
        except ImportError:
            print("  [!] xpl module not available.")
        except Exception as exc:
            print(f"  [!] Error: {exc}")

    def _cmd_run_exploit(self, args: List[str]) -> None:
        if len(args) < 2:
            print("  [!] Usage: run <CVE_ID> <target>")
            return
        cve_id, target = args[0].upper(), args[1]
        print(f"  [*] Running {cve_id} against {target}…")
        try:
            from xpl.exploits import EXPLOIT_REGISTRY
            exploit_cls = EXPLOIT_REGISTRY.get(cve_id)
            if not exploit_cls:
                print(f"  [!] Exploit '{cve_id}' not found.")
                avail = ", ".join(sorted(list(EXPLOIT_REGISTRY.keys())[:8]))
                print(f"  [i] Available: {avail}…")
                return
            exploit = exploit_cls(target=target, timeout=10)
            result = exploit.check()
            vuln = result.get("vulnerable", False)
            print(f"  [+] Vulnerable: {'YES' if vuln else 'NO'}")
            print(f"  [+] Evidence:   {result.get('evidence', 'N/A')[:150]}")
        except Exception as exc:
            print(f"  [!] Error: {exc}")

    def _cmd_audit(self, args: List[str]) -> None:
        if not args:
            print("  [!] Usage: audit <target>")
            return
        target = args[0]
        print(f"  [*] Starting full audit on {target}…")
        try:
            from xpl.auditor import MikroTikAuditor
            from pathlib import Path
            auditor = MikroTikAuditor(host=target, user="admin", password="")
            results = auditor.run_full_audit()
            report_dir = Path("results")
            rpt = auditor.generate_report(results, report_dir)
            print(f"  [+] Report: {rpt}")
            self.session_data["scan_results"].append({
                "type": "audit", "target": target,
                "findings": len(auditor.findings),
            })
        except ImportError:
            print("  [!] xpl.auditor module not available.")
        except Exception as exc:
            print(f"  [!] Error: {exc}")

    def _cmd_results(self, args: List[str]) -> None:
        creds = self.session_data["credentials_found"]
        if not creds:
            print("  [!] No credentials found yet.")
            return
        verbose = "-v" in args
        print(f"\n  Found {len(creds)} credential(s):\n")
        for i, c in enumerate(creds, 1):
            print(f"  [{i:02}] {c.get('user', '?')}:{c.get('pass', '?')}")
            if verbose:
                print(f"       Services: {', '.join(c.get('services', []))}")
                print(f"       Target  : {c.get('target', '?')}")

    def _cmd_export(self, args: List[str]) -> None:
        if not args or args[0] not in ("json", "csv", "xml", "txt"):
            print("  [!] Usage: export <json|csv|xml|txt>")
            return
        try:
            from .export import ResultExporter
            fmt = args[0]
            exporter = ResultExporter(
                self.session_data["credentials_found"], "session_export", output_dir="results"
            )
            method = getattr(exporter, f"export_{fmt}")
            path = method()
            print(f"  [+] Exported: {path}")
        except Exception as exc:
            print(f"  [!] Export error: {exc}")

    def _cmd_targets(self, _: List[str]) -> None:
        targets = self.session_data["targets"]
        if not targets:
            print("  [!] No targets discovered yet.")
            return
        print(f"\n  Discovered {len(targets)} target(s):\n")
        for i, t in enumerate(targets, 1):
            print(f"  [{i:02}] {t.get('target', '?')}")
            print(f"       Mikrotik: {'YES' if t.get('is_mikrotik') else 'NO'}")
            print(f"       Ports   : {', '.join(map(str, t.get('open_ports', [])))}")
            print(f"       Risk    : {t.get('risk_score', 0):.1f}/10")

    def _cmd_clear(self, _: List[str]) -> None:
        os.system("cls" if os.name == "nt" else "clear")

    def _cmd_status(self, _: List[str]) -> None:
        print(f"\n  Session  : {self.session_id}")
        print(f"  Targets  : {len(self.session_data['targets'])}")
        print(f"  Creds    : {len(self.session_data['credentials_found'])}")
        print(f"  Commands : {len(self.session_data['command_history'])}")

    def _cmd_stealth(self, args: List[str]) -> None:
        if not args or args[0] not in ("on", "off"):
            print("  [!] Usage: stealth <on|off>")
            return
        print(f"  [+] Stealth mode: {args[0].upper()}")

    def _cmd_wordlists(self, _: List[str]) -> None:
        mgr = self._get_wordlist_mgr()
        if not mgr:
            return
        stats = mgr.get_wordlist_stats()
        print(f"\n  Mikrotik defaults : {stats['mikrotik_defaults']}")
        print(f"  Mikrotik passwords: {stats['mikrotik_passwords']}")
        print(f"  Total combos      : {stats['total_combinations']}")

    def _cmd_exit(self, _: List[str]) -> None:
        print("  [*] Saving session…")
        self._save_session()
        print("  [+] Done. Goodbye.\n")
        self._running = False

    # ------------------------------------------------------------------
    # Session I/O
    # ------------------------------------------------------------------

    def _save_session(self) -> None:
        Path("sessions").mkdir(exist_ok=True)
        path = Path("sessions") / f"{self.session_id}.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.session_data, fh, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # Lazy module getters
    # ------------------------------------------------------------------

    def _get_fingerprinter(self):
        if self._fingerprinter is None:
            try:
                from modules.fingerprint import MikrotikFingerprinter
                self._fingerprinter = MikrotikFingerprinter()
            except ImportError:
                print("  [!] fingerprint module not available.")
        return self._fingerprinter

    def _get_discovery(self):
        if self._discovery is None:
            try:
                from modules.discovery import MikrotikDiscovery
                self._discovery = MikrotikDiscovery()
            except ImportError:
                print("  [!] discovery module not available.")
        return self._discovery

    def _get_wordlist_mgr(self):
        if self._wordlist_mgr is None:
            try:
                from modules.wordlists import SmartWordlistManager
                self._wordlist_mgr = SmartWordlistManager()
            except ImportError:
                print("  [!] wordlists module not available.")
        return self._wordlist_mgr
