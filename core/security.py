#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Authorization, target validation, and credential checks for MikrotikAPI-BF."""

from __future__ import annotations

import ipaddress
import os
import re
import sys
from typing import Optional

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*$"
)


def get_allowed_targets() -> set[str]:
    """Allowlist targets from env (MIKROTIK_BF_ALLOWED_TARGETS / MIKROTIK_BF_LAB_TARGET)."""
    allowed: set[str] = set()
    extra = os.environ.get("MIKROTIK_BF_ALLOWED_TARGETS", "").strip()
    if extra:
        for part in extra.replace(";", ",").split(","):
            t = part.strip()
            if t:
                allowed.add(t)
    single = os.environ.get("MIKROTIK_BF_LAB_TARGET", "").strip()
    if single:
        allowed.add(single)
    return allowed


def default_lab_target() -> str:
    """Target from MIKROTIK_BF_LAB_TARGET (empty if unset)."""
    return os.environ.get("MIKROTIK_BF_LAB_TARGET", "").strip()


def normalize_target(raw: str) -> str:
    return (raw or "").strip().strip("[]")


def validate_target_format(target: str) -> None:
    """Raise ValueError if target is not a valid IP or hostname."""
    t = normalize_target(target)
    if not t:
        raise ValueError("Target cannot be empty.")
    try:
        ipaddress.ip_address(t)
        return
    except ValueError:
        pass
    if _HOSTNAME_RE.match(t):
        return
    raise ValueError(f"Invalid target format: {target!r} (expected IP or hostname)")


def is_private_or_local(target: str) -> bool:
    t = normalize_target(target)
    try:
        ip = ipaddress.ip_address(t)
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        return False


def is_lab_target(target: str) -> bool:
    return normalize_target(target) in get_allowed_targets()


def print_authorization_banner(target: str) -> None:
    from .console import warn, highlight, ok

    lab = is_lab_target(target)
    tag = ok("ALLOWLIST") if lab else warn("EXTERNAL TARGET")
    print(
        f"\n  {warn('[!]')} Authorized security testing only ({tag}).\n"
        f"  {warn('[!]')} Target: {highlight(target)}\n"
        f"  {warn('[!]')} You must have explicit written permission to test this system.\n"
        f"  {warn('[i]')} Esc cancel · Ctrl+C abort · Ctrl+D exit\n"
    )


def confirm_authorization(
    target: str,
    *,
    skip: bool = False,
    stdin_is_tty: bool = True,
) -> None:
    """Interactive confirmation before network attack."""
    from .escape import safe_confirm, safe_input, abort_message

    if skip or os.environ.get("MIKROTIK_BF_SKIP_CONFIRM", "").strip().lower() in ("1", "yes", "true"):
        print_authorization_banner(target)
        print("  [i] Authorization confirmation skipped (--yes-authorized or env).\n")
        return

    print_authorization_banner(target)

    if not stdin_is_tty:
        print("  [ERROR] Non-interactive shell: use --yes-authorized for authorized lab runs.\n")
        sys.exit(1)

    try:
        if is_lab_target(target):
            ans = safe_confirm("Confirm pentest on allowlisted target?", default_yes=False)
            if ans is None:
                abort_message("Cancelled (Esc).")
                sys.exit(0)
            if not ans:
                abort_message()
                sys.exit(0)
            return

        print("  [WARNING] Target is NOT in the allowlist.")
        print(f"  Type the target IP/hostname to confirm: {target}")
        typed = safe_input("  Confirm target", esc_cancel=True)
        if typed is None:
            abort_message("Cancelled (Esc).")
            sys.exit(0)
        if typed != normalize_target(target):
            abort_message("Confirmation mismatch.")
            sys.exit(1)
    except KeyboardInterrupt:
        abort_message("Cancelled (Ctrl+C).")
        sys.exit(130)
    except EOFError:
        abort_message("Cancelled (Ctrl+D).")
        sys.exit(0)


def validate_attack_credentials(
    *,
    user: Optional[str],
    passw: Optional[str],
    userlist: Optional[str],
    passlist: Optional[str],
    dictionary: Optional[str],
    allow_defaults: bool = False,
) -> None:
    """Ensure at least one credential source is explicitly provided."""
    has_combo = bool(dictionary)
    has_lists = bool(userlist and passlist)
    has_single = bool(user and passw is not None and passw != "")
    has_user_and_pass = bool((userlist or user) and (passlist or passw is not None))

    if has_combo or has_lists or has_single:
        return

    if has_user_and_pass and user != "admin":
        return

    if allow_defaults:
        print(
            "  [WARN] No wordlist/credentials specified — "
            "using fallback admin + empty password only.\n"
        )
        return

    raise ValueError(
        "Credentials required for brute-force. Use one of:\n"
        "  -d combos.lst          combo file (user:pass)\n"
        "  -U admin -P secret     single user/password\n"
        "  -u users.txt -p pass.txt\n"
        "  --allow-default-creds  (fallback admin/empty — lab only)\n"
    )


def warn_public_target(target: str) -> None:
    """Extra warning when attacking non-private, non-lab IPs."""
    t = normalize_target(target)
    if is_lab_target(t):
        return
    if is_private_or_local(t):
        return
    print(
        f"\n  [WARN] {t} is a public/routable address. "
        "Ensure you have written authorization.\n"
    )
