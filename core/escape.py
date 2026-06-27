#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Graceful interrupt handling: Ctrl+C, Ctrl+D, Esc."""

from __future__ import annotations

import os
import signal
import sys
import threading
from typing import Optional

_HANDLERS_INSTALLED = False


class UserAbort(Exception):
    """User cancelled input (Esc / Ctrl+D / declined)."""


class ShutdownCoordinator:
    """Coordinates SIGINT with running brute-force workers."""

    _lock = threading.Lock()
    _stop = threading.Event()
    _active: Optional[object] = None
    _warned = False

    @classmethod
    def stop_requested(cls) -> bool:
        return cls._stop.is_set()

    @classmethod
    def register(cls, engine: object) -> None:
        with cls._lock:
            cls._active = engine
            cls._stop.clear()
            cls._warned = False

    @classmethod
    def unregister(cls, engine: object) -> None:
        with cls._lock:
            if cls._active is engine:
                cls._active = None

    @classmethod
    def request_stop(cls, *, force: bool = False) -> None:
        cls._stop.set()
        if force:
            print("\n  [!] Force exit.\n")
            os._exit(130)
        if not cls._warned:
            cls._warned = True
            print(
                "\n  [!] Stop requested — finishing active attempts… "
                "(Ctrl+C again to force exit, Esc cancels prompts)\n"
            )

    @classmethod
    def reset(cls) -> None:
        cls._stop.clear()
        cls._warned = False

    @classmethod
    def should_emit_logs(cls) -> bool:
        """False after stop requested — suppress late FAIL lines."""
        return not cls._stop.is_set()


def install_signal_handlers() -> None:
    """Install SIGINT handler once per process."""
    global _HANDLERS_INSTALLED
    if _HANDLERS_INSTALLED:
        return

    def _on_sigint(signum, frame):  # noqa: ARG001
        if ShutdownCoordinator.stop_requested():
            ShutdownCoordinator.request_stop(force=True)
        ShutdownCoordinator.request_stop()

    try:
        signal.signal(signal.SIGINT, _on_sigint)
        _HANDLERS_INSTALLED = True
    except (ValueError, OSError):
        pass


def _read_key_esc_aware(prompt: str) -> Optional[str]:
    """Read a line; Esc alone cancels (returns None). Ctrl+C/D propagate."""
    if not sys.stdin.isatty():
        return input(prompt)

    try:
        import termios
        import tty
    except ImportError:
        return input(prompt)

    sys.stdout.write(prompt)
    sys.stdout.flush()

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    buf: list[str] = []

    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)
            if ch == "\x03":  # Ctrl+C
                raise KeyboardInterrupt
            if ch == "\x04":  # Ctrl+D
                raise EOFError
            if ch == "\x1b":  # Esc
                sys.stdout.write("\n")
                sys.stdout.flush()
                return None
            if ch in ("\r", "\n"):
                sys.stdout.write("\n")
                sys.stdout.flush()
                return "".join(buf)
            if ch in ("\x7f", "\b"):  # backspace
                if buf:
                    buf.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                continue
            if ch.isprintable():
                buf.append(ch)
                sys.stdout.write(ch)
                sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def safe_input(
    prompt: str,
    default: str = "",
    *,
    esc_cancel: bool = True,
) -> Optional[str]:
    """
    Prompt for input.

    Returns None on Esc (if esc_cancel). Raises KeyboardInterrupt / EOFError.
    """
    suffix = f" [{default}]" if default else ""
    full = f"{prompt}{suffix}: "

    try:
        if esc_cancel and sys.stdin.isatty():
            raw = _read_key_esc_aware(full)
            if raw is None:
                return None
            val = raw.strip()
        else:
            val = input(full).strip()
    except KeyboardInterrupt:
        print("\n  [!] Cancelled (Ctrl+C).\n")
        raise
    except EOFError:
        print("\n  [!] Cancelled (Ctrl+D).\n")
        raise

    return val or default


def safe_confirm(prompt: str, *, default_yes: bool = False) -> Optional[bool]:
    """
    y/N or Y/n prompt. None = Esc cancel.

    Ctrl+C / Ctrl+D raise after a short message.
    """
    hint = "[Y/n]" if default_yes else "[y/N]"
    ans = safe_input(f"{prompt} {hint}", esc_cancel=True)
    if ans is None:
        print("  [!] Cancelled (Esc).\n")
        return None
    if not ans:
        return default_yes
    return ans.lower() in ("y", "yes", "s", "sim")


def abort_message(reason: str = "Aborted by user.") -> None:
    from core.console import warn

    print(f"\n  {warn('[!]')} {reason}\n")
