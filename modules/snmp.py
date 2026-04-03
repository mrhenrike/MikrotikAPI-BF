#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)
# Version: 1.0.0

"""
SNMP Security Module — MikrotikAPI-BF
=====================================
Enumerates SNMP exposure, tests common communities, and validates basic
read/write behavior for RouterOS environments.
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

LOGGER = logging.getLogger(__name__)


@dataclass
class SNMPTarget:
    """SNMP target descriptor."""

    host: str
    port: int = 161
    timeout: float = 2.0


class SNMPScanner:
    """Perform SNMP exposure and community checks.

    Args:
        target: Router host/IP.
        port: SNMP UDP port (default: 161).
        timeout: Socket timeout in seconds.
    """

    DEFAULT_COMMUNITIES: Tuple[str, ...] = (
        "public",
        "private",
        "mikrotik",
        "admin",
        "snmp",
    )

    SAFE_READ_OIDS: Tuple[str, ...] = (
        "1.3.6.1.2.1.1.1.0",  # sysDescr
        "1.3.6.1.2.1.1.5.0",  # sysName
        "1.3.6.1.2.1.1.3.0",  # sysUpTime
    )

    def __init__(self, target: str, port: int = 161, timeout: float = 2.0) -> None:
        self.target = SNMPTarget(host=target, port=port, timeout=timeout)

    def run(
        self,
        communities: Optional[Iterable[str]] = None,
        test_write: bool = False,
    ) -> Dict[str, object]:
        """Execute SNMP checks and return findings.

        Args:
            communities: Community strings to test.
            test_write: Whether to attempt SNMP SET probe.

        Returns:
            Dict with exposure and test results.
        """
        community_candidates = list(communities or self.DEFAULT_COMMUNITIES)
        results: Dict[str, object] = {
            "target": self.target.host,
            "port": self.target.port,
            "udp_reachable": self._is_udp_reachable(),
            "snmp_library": "pysnmp" if self._has_pysnmp() else "unavailable",
            "valid_communities": [],
            "read_results": {},
            "write_results": {},
            "risk": "unknown",
        }

        if not results["udp_reachable"]:
            results["risk"] = "low"
            return results

        if not self._has_pysnmp():
            LOGGER.warning("pysnmp not installed; SNMP auth/read checks skipped.")
            results["risk"] = "medium"
            results["note"] = "Install pysnmp for full SNMP checks."
            return results

        valid_communities = self.enumerate_communities(community_candidates)
        results["valid_communities"] = valid_communities

        read_results: Dict[str, Dict[str, object]] = {}
        write_results: Dict[str, Dict[str, object]] = {}
        for community in valid_communities:
            read_results[community] = self.read_oids(community, self.SAFE_READ_OIDS)
            if test_write:
                write_results[community] = self.try_write_probe(community)

        results["read_results"] = read_results
        results["write_results"] = write_results
        results["risk"] = self._classify_risk(valid_communities, write_results)
        return results

    def enumerate_communities(self, communities: Iterable[str]) -> List[str]:
        """Return community strings that permit SNMP read access."""
        valid: List[str] = []
        for community in communities:
            probe = self.read_oids(community, ("1.3.6.1.2.1.1.1.0",))
            if probe.get("success"):
                valid.append(community)
        return valid

    def read_oids(self, community: str, oids: Iterable[str]) -> Dict[str, object]:
        """Perform SNMP GET for each OID using SNMPv2c."""
        try:
            from pysnmp.hlapi import (  # type: ignore
                CommunityData,
                ContextData,
                ObjectIdentity,
                ObjectType,
                SnmpEngine,
                UdpTransportTarget,
                getCmd,
            )
        except Exception as exc:  # pragma: no cover
            return {"success": False, "error": f"pysnmp unavailable: {exc}", "values": {}}

        values: Dict[str, str] = {}
        for oid in oids:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1),
                UdpTransportTarget((self.target.host, self.target.port), timeout=self.target.timeout, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
            error_indication, error_status, _, var_binds = next(iterator)
            if error_indication:
                return {"success": False, "error": str(error_indication), "values": values}
            if error_status:
                return {"success": False, "error": str(error_status), "values": values}
            for var_bind in var_binds:
                values[str(var_bind[0])] = str(var_bind[1])
        return {"success": True, "error": None, "values": values}

    def try_write_probe(self, community: str) -> Dict[str, object]:
        """Attempt safe write probe against sysContact OID."""
        try:
            from pysnmp.hlapi import (  # type: ignore
                CommunityData,
                ContextData,
                ObjectIdentity,
                ObjectType,
                OctetString,
                SnmpEngine,
                UdpTransportTarget,
                setCmd,
            )
        except Exception as exc:  # pragma: no cover
            return {"success": False, "error": f"pysnmp unavailable: {exc}"}

        test_value = "mikrotikapi-bf-write-test"
        iterator = setCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((self.target.host, self.target.port), timeout=self.target.timeout, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.4.0"), OctetString(test_value)),
        )
        error_indication, error_status, _, _ = next(iterator)
        if error_indication:
            return {"success": False, "error": str(error_indication)}
        if error_status:
            return {"success": False, "error": str(error_status)}
        return {"success": True, "error": None}

    def _is_udp_reachable(self) -> bool:
        """Check if UDP/161 responds to SNMP-like packet."""
        payload = bytes.fromhex("302602010104067075626c6963a01902044f27f158020100020100300b300906052b060102010500")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(self.target.timeout)
            sock.sendto(payload, (self.target.host, self.target.port))
            sock.recvfrom(2048)
            return True
        except Exception:
            return False
        finally:
            sock.close()

    @staticmethod
    def _has_pysnmp() -> bool:
        try:
            import pysnmp  # type: ignore  # noqa: F401
            return True
        except Exception:
            return False

    @staticmethod
    def _classify_risk(valid_communities: List[str], write_results: Dict[str, Dict[str, object]]) -> str:
        if not valid_communities:
            return "low"
        if any(item.get("success") for item in write_results.values()):
            return "high"
        if "public" in valid_communities:
            return "high"
        return "medium"
