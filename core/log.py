#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)

"""
Logging Module — MikrotikAPI-BF
=================================
Color-coded terminal logging with configurable verbosity levels.

Levels:
  INFO   – always visible (yellow)
  SUCC   – success events (green)
  WARN   – warnings (magenta)
  FAIL   – failed attempts (red, only in verbose mode)
  SKIP   – skipped entries (blue, only in verbose mode)
  ERRO   – errors (light red, only in very-verbose mode)
  DEBB   – debug traces (cyan, only in very-verbose mode)
"""

from datetime import datetime

try:
    from colorama import Fore, Style, init as _colorama_init
    _colorama_init(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False

    class _DummyColor:
        def __getattr__(self, _: str) -> str:
            return ""

    class _DummyStyle:
        RESET_ALL = ""

    Fore = _DummyColor()      # type: ignore[assignment]
    Style = _DummyStyle()     # type: ignore[assignment]


class Log:
    """
    Simple, dependency-light logger with ANSI color support.

    Args:
        verbose:     Enable FAIL/SKIP/WARN output.
        verbose_all: Enable DEBUG/ERROR output on top of verbose.
    """

    def __init__(self, verbose: bool = False, verbose_all: bool = False) -> None:
        self.verbose = verbose
        self.verbose_all = verbose_all

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _ts() -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _print(self, level: str, message: str, color: str) -> None:
        reset = Style.RESET_ALL if _HAS_COLOR else ""
        print(f"{color}[{level:<4}] [{self._ts()}] {message}{reset}")

    # ------------------------------------------------------------------
    # Public log methods
    # ------------------------------------------------------------------

    def info(self, message: str) -> None:
        """Always-visible informational message."""
        self._print("INFO", message, Fore.YELLOW)

    def success(self, message: str) -> None:
        """Highlight a successful event (always visible)."""
        self._print("SUCC", message, Fore.GREEN)

    def warning(self, message: str) -> None:
        """Warning message (always visible)."""
        self._print("WARN", message, Fore.LIGHTMAGENTA_EX)

    def fail(self, message: str) -> None:
        """Failed login attempt — shown only when verbose."""
        if self.verbose or self.verbose_all:
            self._print("FAIL", message, Fore.RED)

    def skip(self, message: str) -> None:
        """Skipped entry — shown only when verbose."""
        if self.verbose or self.verbose_all:
            self._print("SKIP", message, Fore.BLUE)

    def error(self, message: str) -> None:
        """Error message — shown only in very-verbose mode."""
        if self.verbose_all:
            self._print("ERRO", message, Fore.LIGHTRED_EX)

    def debug(self, message: str) -> None:
        """Debug trace — shown only in very-verbose mode."""
        if self.verbose_all:
            self._print("DEBB", message, Fore.CYAN)

    # ------------------------------------------------------------------
    # Banner
    # ------------------------------------------------------------------

    @staticmethod
    def banner(version: str = "3.0") -> None:
        """Print the application banner."""
        cyan = Fore.CYAN if _HAS_COLOR else ""
        green = Fore.GREEN if _HAS_COLOR else ""
        yellow = Fore.YELLOW if _HAS_COLOR else ""
        reset = Style.RESET_ALL if _HAS_COLOR else ""

        print(f"""{cyan}
  ███╗   ███╗██╗██╗  ██╗██████╗  ██████╗ ████████╗██╗██╗  ██╗     █████╗ ██████╗ ██╗      ██████╗ ███████╗
  ████╗ ████║██║██║ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝██║██║ ██╔╝    ██╔══██╗██╔══██╗██║     ██╔═══██╗██╔════╝
  ██╔████╔██║██║█████╔╝ ██████╔╝██║   ██║   ██║   ██║█████╔╝     ███████║██████╔╝██║     ██║   ██║███████╗
  ██║╚██╔╝██║██║██╔═██╗ ██╔══██╗██║   ██║   ██║   ██║██╔═██╗     ██╔══██║██╔═══╝ ██║     ██║   ██║╚════██║
  ██║ ╚═╝ ██║██║██║  ██╗██║  ██║╚██████╔╝   ██║   ██║██║  ██╗    ██║  ██║██║     ███████╗╚██████╔╝███████║
  ╚═╝     ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚══════╝
{reset}
  {green}┌─────────────────────────────────────────────────────────────────────┐{reset}
  {green}│  MikrotikAPI-BF v{version:<8}  RouterOS Attack & Exploitation Framework  │{reset}
  {green}│  André Henrique  ·  X / LinkedIn: @mrhenrike                        │{reset}
  {green}│  https://github.com/mrhenrike/MikrotikAPI-BF                        │{reset}
  {green}└─────────────────────────────────────────────────────────────────────┘{reset}
  {yellow}  ⚠  For authorized security testing only. Use responsibly.{reset}
""")
