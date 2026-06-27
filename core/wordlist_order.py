#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Wordlist / combo ordering for brute-force attacks."""

from __future__ import annotations

import random
from typing import List, Sequence, Tuple

Combo = Tuple[str, str]

VALID_ORDERS = (
    "random",
    "forward",
    "reverse",
    "password-first",
)


def build_user_pass_combos(
    users: Sequence[str],
    passwords: Sequence[str],
    *,
    nest: str = "user-outer",
) -> List[Combo]:
    """Cartesian product; nest=user-outer (default) or password-first."""
    if nest in ("password-first", "pass-first", "line"):
        return [(u, p) for p in passwords for u in users]
    return [(u, p) for u in users for p in passwords]


def apply_wordlist_order(combos: List[Combo], mode: str = "random") -> List[Combo]:
    """
    Reorder credential combinations.

    Modes:
      random          — shuffle (default)
      forward         — top-down / file line order
      reverse         — bottom-up
      password-first  — password list drives outer loop (when built user-outer, re-nest)
    """
    if not combos:
        return []

    m = (mode or "random").lower().replace("_", "-")

    if m in ("forward", "top-down", "sequential", "line"):
        return list(combos)

    if m in ("reverse", "bottom-up"):
        return list(reversed(combos))

    if m in ("password-first", "pass-first"):
        users = list(dict.fromkeys(u for u, _ in combos))
        passwords = list(dict.fromkeys(p for _, p in combos))
        return build_user_pass_combos(users, passwords, nest="password-first")

    if m in ("random", "shuffle", "dynamic"):
        out = list(combos)
        random.shuffle(out)
        return out

    raise ValueError(
        f"Unknown wordlist order: {mode!r}. "
        f"Choose: {', '.join(VALID_ORDERS)}"
    )


def nest_for_order(mode: str) -> str:
    """Which nested loop to use when building from separate user/pass files."""
    m = (mode or "random").lower().replace("_", "-")
    if m in ("password-first", "pass-first", "line"):
        return "password-first"
    return "user-outer"
