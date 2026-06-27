#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Launch menu and guided wizard when no CLI args are provided."""

from __future__ import annotations

from typing import List, Optional

from .security import validate_target_format
from .lab_wordlists import default_lab_credentials
from .escape import safe_confirm, safe_input


def _ask(prompt: str, default: str = "") -> str:
    val = safe_input(f"  {prompt}", default, esc_cancel=True)
    if val is None:
        raise KeyboardInterrupt
    return val


def _yes_no(prompt: str, default_yes: bool = False) -> bool:
    ans = safe_confirm(prompt, default_yes=default_yes)
    if ans is None:
        raise KeyboardInterrupt
    return ans


def run_launch_menu() -> Optional[List[str]]:
    """
    Main menu — returns argv tail for mikrotikapi-bf.py or None to exit.

    None triggers REPL mode (interactive flag).
    """
    try:
        return _run_launch_menu_inner()
    except KeyboardInterrupt:
        print("\n  [!] Menu cancelled (Ctrl+C / Esc).\n")
        return None
    except EOFError:
        print("\n  [!] Menu cancelled (Ctrl+D).\n")
        return None


def _run_launch_menu_inner() -> Optional[List[str]]:
    print("\n=== MikrotikAPI-BF — Launch Menu ===\n")
    print("  [1] Guided attack       → target + wordlist")
    print("  [2] Full REPL           → interactive command shell")
    print("  [3] Fingerprint + CVE   → target, no brute-force")
    print("  [0] Exit\n")

    choice = _ask("Choice", "1")
    if choice == "0":
        return None
    if choice == "2":
        return ["--interactive"]

    if choice == "3":
        target = _ask("Target IP/hostname")
        if not target:
            print("\n  [!] Target required.\n")
            return run_launch_menu()
        try:
            validate_target_format(target)
        except ValueError as exc:
            print(f"\n  [!] {exc}\n")
            return run_launch_menu()
        return ["-t", target, "--yes-authorized", "--fingerprint", "--scan-cve"]

    if choice != "1":
        print("\n  [!] Invalid option.\n")
        return run_launch_menu()

    target = _ask("Target IP/hostname")
    if not target:
        print("\n  [!] Target required.\n")
        return run_launch_menu()
    try:
        validate_target_format(target)
    except ValueError as exc:
        print(f"\n  [!] {exc}\n")
        return run_launch_menu()

    argv: List[str] = ["-t", target, "--yes-authorized"]

    use_wfh = _yes_no("Use WFH labs wordlists (labs_users + labs_passwords)?", True)
    if use_wfh:
        try:
            ulist, plist = default_lab_credentials()
            argv.extend(["-u", ulist, "-p", plist])
            print(f"\n  [i] Wordlists: {ulist} + {plist}\n")
        except (FileNotFoundError, KeyError) as exc:
            print(f"  [!] {exc}")
            combo = _ask("Combo/wordlist file (-d)", "examples/combos.txt")
            if combo:
                argv.extend(["-d", combo])
    else:
        combo = _ask("Combo/wordlist file (-d)", "examples/combos.txt")
        if combo:
            argv.extend(["-d", combo])
        else:
            user = _ask("Username (-U)", "admin")
            pwd = _ask("Password (-P)", "")
            argv.extend(["-U", user, "-P", pwd])

    if "-u" not in argv and "-d" not in argv and "-U" not in argv:
        combo = _ask("Combo/wordlist file (-d)", "examples/combos.txt")
        if combo:
            argv.extend(["-d", combo])

    threads = _ask("Threads (--threads)", "2")
    if threads.isdigit():
        argv.extend(["--threads", threads])

    delay_mode = _ask("Delay mode (high/balanced/stealth/custom)", "balanced")
    if delay_mode in ("high", "balanced", "stealth", "custom"):
        argv.extend(["--delay-mode", delay_mode])
        if delay_mode == "custom":
            secs = _ask("Delay seconds (-s)", "1.0")
            argv.extend(["-s", secs])

    if _yes_no("Disable progress bar?", False):
        argv.append("--no-progress")

    if _yes_no("Enable stealth delays?", False):
        argv.append("--stealth")

    print(f"\n  [i] Command: python mikrotikapi-bf.py {' '.join(argv)}\n")
    if not _yes_no("Start attack now?", True):
        print("\n  Cancelled.\n")
        return None

    return argv
