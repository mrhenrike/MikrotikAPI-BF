"""PoC engine — runs only reproducible (MSF/EDB/GitHub) exploits."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from xpl.exploits import EXPLOIT_REGISTRY
from xpl.reproducible_catalog import REPRODUCIBLE_IDS, is_reproducible

log = logging.getLogger(__name__)

# PoCs that send destructive payloads (DoS) — only run with explicit lab authorization.
DESTRUCTIVE_IDS = frozenset({"CVE-2020-11881", "CVE-2024-27686"})


def has_exploit_method(cls: type) -> bool:
    """Return True if *cls* implements a real exploit() beyond BaseExploit stub."""
    return callable(getattr(cls, "exploit", None)) and "exploit" in cls.__dict__


def full_registry() -> Dict[str, type]:
    """Return reproducible exploit registry (no version-only stubs)."""
    return dict(EXPLOIT_REGISTRY)


def run_all_pocs(
    target: str,
    username: str = "",
    password: str = "",
    cve_ids: Optional[List[str]] = None,
    timeout: int = 10,
) -> List[Dict[str, Any]]:
    """Run every reproducible PoC against *target*."""
    from xpl.cve_db import get_cves_for_version

    reg = full_registry()
    ver = None
    try:
        probe_cls = next(iter(reg.values()))
        probe = probe_cls(target=target, username=username, password=password)
        ver = probe._get_routeros_version()
    except Exception:
        pass

    applicable = {c["cve_id"] for c in get_cves_for_version(ver)} if ver else set(reg.keys())
    applicable &= REPRODUCIBLE_IDS
    ids = cve_ids or sorted(applicable & set(reg.keys()))
    results: List[Dict[str, Any]] = []
    for cid in ids:
        if not is_reproducible(cid):
            results.append({"cve_id": cid, "status": "skipped", "reason": "not_reproducible"})
            continue
        cls = reg.get(cid)
        if not cls:
            continue
        meta_auth = getattr(cls, "AUTH_REQUIRED", False)
        if meta_auth and not username:
            results.append({"cve_id": cid, "status": "skipped", "reason": "auth_required"})
            continue
        try:
            exploit = cls(target=target, username=username, password=password, timeout=timeout)
            r = exploit.check()
            results.append({"cve_id": cid, **r})
        except Exception as exc:
            results.append({"cve_id": cid, "status": "error", "error": str(exc)})
    return results


def run_e2e_poc(
    cve_id: str,
    target: str,
    username: str = "",
    password: str = "",
    timeout: int = 10,
    allow_destructive: bool = False,
) -> Dict[str, Any]:
    """Run check() then exploit() when available for a single PoC."""
    reg = full_registry()
    cls = reg.get(cve_id)
    if not cls:
        return {"cve_id": cve_id, "status": "error", "error": "not_in_registry"}
    if not is_reproducible(cve_id):
        return {"cve_id": cve_id, "status": "skipped", "reason": "not_reproducible"}
    meta_auth = getattr(cls, "AUTH_REQUIRED", False)
    if meta_auth and not username:
        return {"cve_id": cve_id, "status": "skipped", "reason": "auth_required"}

    out: Dict[str, Any] = {"cve_id": cve_id, "target": target}
    try:
        exploit = cls(target=target, username=username, password=password, timeout=timeout)
        check = exploit.check()
        out["check"] = check
        out["vulnerable"] = check.get("vulnerable", False)
        out["evidence"] = check.get("evidence", "")

        if has_exploit_method(cls):
            if cve_id in DESTRUCTIVE_IDS and not allow_destructive:
                out["exploit"] = {"status": "skipped", "reason": "destructive_requires_lab_auth"}
            elif out["vulnerable"] or cve_id in DESTRUCTIVE_IDS:
                exp = exploit.exploit()
                out["exploit"] = exp
                if exp.get("vulnerable"):
                    out["exploited"] = True
                    out["exploit_evidence"] = exp.get("evidence", "")
            else:
                out["exploit"] = {"status": "skipped", "reason": "check_not_vulnerable"}
        else:
            out["exploited"] = out.get("vulnerable", False)
    except Exception as exc:
        out["status"] = "error"
        out["error"] = str(exc)
    return out


def run_e2e_pocs(
    target: str,
    username: str = "",
    password: str = "",
    cve_ids: Optional[List[str]] = None,
    timeout: int = 10,
    allow_destructive: bool = False,
    max_pocs: int = 0,
) -> List[Dict[str, Any]]:
    """Run E2E (check + exploit) for applicable reproducible PoCs."""
    from xpl.cve_db import get_cves_for_version

    reg = full_registry()
    ver = None
    try:
        probe_cls = next(iter(reg.values()))
        probe = probe_cls(target=target, username=username, password=password)
        ver = probe._get_routeros_version()
    except Exception:
        pass

    applicable = {c["cve_id"] for c in get_cves_for_version(ver)} if ver else set(reg.keys())
    applicable &= REPRODUCIBLE_IDS
    ids = cve_ids or sorted(applicable & set(reg.keys()))
    if max_pocs > 0:
        ids = ids[:max_pocs]

    return [
        run_e2e_poc(
            cid, target, username, password, timeout, allow_destructive=allow_destructive
        )
        for cid in ids
    ]
