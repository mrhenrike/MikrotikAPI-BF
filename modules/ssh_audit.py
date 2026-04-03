#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)
# Version: 1.0.0

"""
SSH Audit Module — MikrotikAPI-BF
=================================
Audits SSH banner, algorithms, and crypto posture for RouterOS targets.
"""

from __future__ import annotations

import socket
from typing import Dict, List


class SSHAuditor:
    """Collect SSH protocol and crypto metadata."""

    def __init__(self, target: str, port: int = 22, timeout: float = 5.0) -> None:
        self.target = target
        self.port = port
        self.timeout = timeout

    def run(self) -> Dict[str, object]:
        """Run SSH audit and return findings."""
        banner = self._read_banner()
        algorithms = self._collect_algorithms()
        return {
            "target": self.target,
            "port": self.port,
            "banner": banner,
            "algorithms": algorithms,
            "weak_algorithms": self._find_weak_algorithms(algorithms),
            "risk": self._classify_risk(banner, algorithms),
        }

    def _read_banner(self) -> Dict[str, object]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            data = sock.recv(256).decode("utf-8", errors="replace").strip()
            return {"reachable": True, "value": data}
        except Exception as exc:
            return {"reachable": False, "error": str(exc), "value": ""}
        finally:
            sock.close()

    def _collect_algorithms(self) -> Dict[str, List[str]]:
        try:
            import paramiko
        except Exception:
            return {"kex": [], "ciphers": [], "macs": [], "host_keys": []}

        client = paramiko.Transport((self.target, self.port))
        client.banner_timeout = self.timeout
        try:
            client.start_client(timeout=self.timeout)
            sec_opts = client.get_security_options()
            return {
                "kex": list(sec_opts.kex),
                "ciphers": list(sec_opts.ciphers),
                "macs": list(sec_opts.digests),
                "host_keys": list(sec_opts.key_types),
            }
        except Exception:
            return {"kex": [], "ciphers": [], "macs": [], "host_keys": []}
        finally:
            client.close()

    @staticmethod
    def _find_weak_algorithms(algorithms: Dict[str, List[str]]) -> Dict[str, List[str]]:
        weak_tokens = ("diffie-hellman-group1", "3des-cbc", "cbc", "hmac-md5", "ssh-rsa")
        weak: Dict[str, List[str]] = {}
        for family, values in algorithms.items():
            weak[family] = [value for value in values if any(token in value for token in weak_tokens)]
        return weak

    @staticmethod
    def _classify_risk(banner: Dict[str, object], algorithms: Dict[str, List[str]]) -> str:
        if not banner.get("reachable"):
            return "unknown"
        weak = SSHAuditor._find_weak_algorithms(algorithms)
        weak_count = sum(len(values) for values in weak.values())
        if weak_count > 3:
            return "high"
        if weak_count > 0:
            return "medium"
        return "low"
