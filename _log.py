#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This module provides a simple logging system with color-coded output for terminal
# It respects verbosity flags: normal, verbose, and very verbose (debug)

from datetime import datetime
from colorama import Fore, Style, init

# Initialize color support for all platforms
init(autoreset=True)

class Log:
    def __init__(self, verbose=False, verbose_all=False):
        self.verbose = verbose        # Enable logs like FAIL/WARN
        self.verbose_all = verbose_all  # Enable DEBUG/ERROR logs

    def timestamp(self):
        return datetime.now().strftime("%H:%M:%S")

    def _format(self, level, message, color):
        # General formatter used internally for consistent structure
        print(f"{color}[{level:<4}] [{self.timestamp()}] {message}{Style.RESET_ALL}")

    def info(self, message):
        # General output for normal execution flow (always visible)
        self._format("INFO", message, Fore.YELLOW)

    def success(self, message):
        # Highlight successful logins or events
        self._format("SUCC", message, Fore.GREEN)

    def fail(self, message):
        # Only show failed attempts if verbosity is enabled
        if self.verbose:
            self._format("FAIL", message, Fore.RED)

    def warning(self, message):
        # Show warnings if in very verbose (debug) mode
        if self.verbose_all:
            self._format("WARN", message, Fore.LIGHTMAGENTA_EX)

    def error(self, message):
        # Show errors if in very verbose (debug) mode
        if self.verbose_all:
            self._format("ERRO", message, Fore.LIGHTRED_EX)

    def debug(self, message):
        # For debug information (developer or troubleshooting mode)
        if self.verbose_all:
            self._format("DEBB", message, Fore.CYAN)
    
    @staticmethod
    def banner():
        print(f"""
            __  __ _ _              _   _ _        _    ____ ___      ____  _____
            |  \/  (_) | ___ __ ___ | |_(_) | __   / \\  |  _ \\_ _|    | __ )|  ___|
            | |\\/| | | |/ / '__/ _ \\| __| | |/ /  / _ \\ | |_) | |_____|  _ \\| |_
            | |  | | |   <| | | (_) | |_| |   <  / ___ \\|  __/| |_____| |_) |  _|
            |_|  |_|_|_|\\_\\_|  \\___/ \\__|_|_|\\_\\/_/   \\_\\_|  |___|    |____/|_|

                        Mikrotik RouterOS API Bruteforce Tool v1.10
                        André Henrique (X / Linkedin: @mrhenrike)
                Please report tips, suggests and problems to X or LinkedIn
                        https://github.com/mrhenrike/MikrotikAPI-BF
        """)