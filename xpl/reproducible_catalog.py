"""Canonical catalog of reproducible MikroTik PoCs (MSF/EDB/GitHub only)."""
from __future__ import annotations

from typing import Any, Dict, FrozenSet, List, Set, Type

# IDs with public reproducible PoC code — version-only stubs are excluded.
REPRODUCIBLE_IDS: FrozenSet[str] = frozenset({
    "CVE-2018-7445", "CVE-2018-10066", "CVE-2018-14847", "CVE-2018-14847-MAC",
    "CVE-2018-14847-DECRYPT",
    "CVE-2019-3924", "CVE-2019-3943", "CVE-2019-3976", "CVE-2019-3977",
    "CVE-2019-3978", "CVE-2019-3981",
    "CVE-2020-11881", "CVE-2020-20215", "CVE-2020-5720",
    "CVE-2021-27263", "CVE-2021-36522", "CVE-2021-41987", "CVE-2021-3014",
    "CVE-2022-34960", "CVE-2022-45313", "CVE-2022-45315",
    "CVE-2023-30799", "CVE-2023-30800",
    "CVE-2024-2169", "CVE-2024-27686", "CVE-2024-27887", "CVE-2024-35274",
    "CVE-2025-61481", "CVE-2025-10948", "CVE-2025-6563",
    "CVE-2017-20149",
    "MIKROTIK-CONFIG-001", "MIKROTIK-CONFIG-002", "MIKROTIK-CONFIG-003",
    "MIKROTIK-CONFIG-004", "MIKROTIK-CONFIG-005",
    "MIKROTIK-JAILBREAK-001",
    "MIKROTIK-JAILBREAK-002",
    "MIKROTIK-SVC-DUDE", "MIKROTIK-SVC-BTEST", "MIKROTIK-SVC-SETUP",
    "VU-375660",
    "EDB-31102", "EDB-6366", "EDB-44283/44284", "EDB-44450", "EDB-43317",
    "EDB-41752", "EDB-41601", "EDB-28056", "EDB-24968", "EDB-18817",
    "EDB-52366", "EDB-48474", "EDB-39817",
})

REPRODUCIBLE_SOURCES: Dict[str, str] = {
    "CVE-2018-14847": "MSF:auxiliary/gather/mikrotik_winbox_disclosure; EDB-45220; GitHub:BasuCert/WinboxPoC",
    "CVE-2024-27686": "EDB-51931",
    "CVE-2020-11881": "GitHub:botlabsDev/CVE-2020-11881",
    "CVE-2018-7445": "Core Security advisory; EDB",
    "CVE-2019-3924": "MSF:exploit/linux/http/mikrotik_www_exec",
}


def is_reproducible(cve_id: str) -> bool:
    return cve_id in REPRODUCIBLE_IDS


def filter_reproducible_registry(registry: Dict[str, type]) -> Dict[str, type]:
    """Return only entries with a public reproducible PoC."""
    return {k: v for k, v in registry.items() if k in REPRODUCIBLE_IDS}


def sync_cve_poc_flags(cve_database: List[Dict[str, Any]]) -> int:
    """Set poc_available=True only for reproducible catalog entries."""
    changed = 0
    for entry in cve_database:
        cid = entry.get("cve_id", "")
        want = cid in REPRODUCIBLE_IDS
        if entry.get("poc_available") != want:
            entry["poc_available"] = want
            changed += 1
    return changed


def get_reproducible_cves(cve_database: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [c for c in cve_database if c.get("cve_id") in REPRODUCIBLE_IDS]
