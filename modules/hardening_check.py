#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)
# Version: 1.0.0

"""
Hardening Validation Module — MikrotikAPI-BF
===========================================
Scores RouterOS hardening controls and outputs a concise checklist.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class HardeningControl:
    """Single hardening control definition."""

    id: str
    description: str
    weight: int


class HardeningValidator:
    """Validate hardening posture from collected target state."""

    CONTROLS: List[HardeningControl] = [
        HardeningControl("svc-telnet-disabled", "Telnet service disabled", 12),
        HardeningControl("svc-ftp-disabled", "FTP service disabled or restricted", 10),
        HardeningControl("svc-api-restricted", "API/API-SSL restricted to management network", 10),
        HardeningControl("dns-no-open-resolver", "DNS allow-remote-requests disabled", 12),
        HardeningControl("neighbor-disabled", "Neighbor discovery disabled outside mgmt", 10),
        HardeningControl("snmp-secure", "SNMP disabled or non-default community + ACL", 10),
        HardeningControl("ssh-strong", "SSH strong crypto enabled", 10),
        HardeningControl("firewall-default-deny", "Firewall input default deny with allow-list", 14),
        HardeningControl("bruteforce-protection", "Login brute-force protections configured", 12),
    ]

    def evaluate(self, state: Dict[str, object]) -> Dict[str, object]:
        """Compute hardening score and per-control status.

        Args:
            state: Collected hardening indicators.

        Returns:
            Dict containing score, passed controls, and recommendations.
        """
        checks: List[Dict[str, object]] = []
        score = 0
        max_score = sum(control.weight for control in self.CONTROLS)

        for control in self.CONTROLS:
            passed = self._check(control.id, state)
            if passed:
                score += control.weight
            checks.append(
                {
                    "id": control.id,
                    "description": control.description,
                    "weight": control.weight,
                    "passed": passed,
                }
            )

        percentage = round((score / max_score) * 100, 2) if max_score else 0.0
        return {
            "score": score,
            "max_score": max_score,
            "percentage": percentage,
            "grade": self._grade(percentage),
            "checks": checks,
            "recommendations": self._recommendations(checks),
        }

    @staticmethod
    def _check(control_id: str, state: Dict[str, object]) -> bool:
        open_services = set(state.get("open_services", []))
        if control_id == "svc-telnet-disabled":
            return "telnet" not in open_services
        if control_id == "svc-ftp-disabled":
            return "ftp" not in open_services
        if control_id == "svc-api-restricted":
            return bool(state.get("api_restricted", False))
        if control_id == "dns-no-open-resolver":
            return bool(state.get("dns_remote_requests_disabled", False))
        if control_id == "neighbor-disabled":
            return bool(state.get("neighbor_discovery_disabled", False))
        if control_id == "snmp-secure":
            return bool(state.get("snmp_hardened", False))
        if control_id == "ssh-strong":
            return bool(state.get("ssh_strong_crypto", False))
        if control_id == "firewall-default-deny":
            return bool(state.get("firewall_default_deny", False))
        if control_id == "bruteforce-protection":
            return bool(state.get("bruteforce_protection", False))
        return False

    @staticmethod
    def _grade(percentage: float) -> str:
        if percentage >= 90:
            return "A"
        if percentage >= 80:
            return "B"
        if percentage >= 70:
            return "C"
        if percentage >= 60:
            return "D"
        return "E"

    @staticmethod
    def _recommendations(checks: List[Dict[str, object]]) -> List[str]:
        recommendations: List[str] = []
        for item in checks:
            if item.get("passed"):
                continue
            recommendations.append(f"Implement control: {item['description']}")
        return recommendations
