#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Bridge to BruteforceEngine defined in mikrotikapi-bf.py (avoid circular imports)."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _load_main_module():
    root = Path(__file__).resolve().parent.parent
    main_path = root / "mikrotikapi-bf.py"
    spec = importlib.util.spec_from_file_location("mikrotikapi_bf_main", main_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {main_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def scan_services(
    target: str,
    api_port: int = 8728,
    http_port: int = 80,
    ssl_port: int = 443,
    use_ssl: bool = False,
) -> Dict[str, bool]:
    mod = _load_main_module()
    return mod._scan_services(target, api_port, http_port, ssl_port, use_ssl)


def run_bruteforce(
    target: str,
    *,
    usernames: Optional[str] = None,
    passwords: Optional[str] = None,
    combo_dict: Optional[str] = None,
    delay: float = 0.0,
    api_port: int = 8728,
    rest_port: int = 8729,
    http_port: int = 80,
    ssl_port: int = 443,
    use_ssl: bool = False,
    max_workers: int = 2,
    verbose: bool = False,
    verbose_all: bool = False,
    show_progress: bool = True,
    stealth_mode: bool = False,
    fingerprint: bool = False,
    export_formats: Optional[List[str]] = None,
    export_dir: str = "results",
    wordlist_order: str = "random",
) -> List[Dict[str, Any]]:
    """Run BruteforceEngine against a single target."""
    mod = _load_main_module()
    services_ok = scan_services(target, api_port, http_port, ssl_port, use_ssl)
    engine = mod.BruteforceEngine(
        target=target,
        usernames=usernames,
        passwords=passwords,
        combo_dict=combo_dict,
        delay=delay,
        api_port=api_port,
        rest_port=rest_port,
        http_port=http_port,
        ssl_port=ssl_port,
        use_ssl=use_ssl,
        max_workers=max_workers,
        verbose=verbose,
        verbose_all=verbose_all,
        validate_services={},
        services_ok=services_ok,
        show_progress=show_progress,
        export_formats=export_formats or [],
        export_dir=export_dir,
        stealth_mode=stealth_mode,
        fingerprint=fingerprint,
        wordlist_order=wordlist_order,
    )
