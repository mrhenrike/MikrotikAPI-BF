#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)
# Version: 1.0.0

"""
Web Security Module — MikrotikAPI-BF
====================================
Checks WebFig/REST exposure, security headers, and authentication behavior.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebSecurityTester:
    """Perform baseline web security checks against RouterOS HTTP/HTTPS."""

    SECURITY_HEADERS: Tuple[str, ...] = (
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "content-security-policy",
        "referrer-policy",
        "permissions-policy",
    )

    def __init__(self, target: str, http_port: int = 80, https_port: int = 443, timeout: float = 5.0) -> None:
        self.target = target
        self.http_port = http_port
        self.https_port = https_port
        self.timeout = timeout

    def run(self, username: Optional[str] = None, password: Optional[str] = None) -> Dict[str, object]:
        """Execute web checks and return findings."""
        http_result = self._check_endpoint("http", self.http_port)
        https_result = self._check_endpoint("https", self.https_port)
        rest_result = self._check_rest_auth(username=username, password=password)

        return {
            "target": self.target,
            "http": http_result,
            "https": https_result,
            "rest_auth": rest_result,
            "risk": self._classify_risk(http_result, https_result, rest_result),
        }

    def _check_endpoint(self, scheme: str, port: int) -> Dict[str, object]:
        url = f"{scheme}://{self.target}:{port}/"
        try:
            response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
        except Exception as exc:
            return {"reachable": False, "error": str(exc)}

        headers = {key.lower(): value for key, value in response.headers.items()}
        missing_headers: List[str] = [header for header in self.SECURITY_HEADERS if header not in headers]

        return {
            "reachable": True,
            "status_code": response.status_code,
            "server": headers.get("server", ""),
            "missing_security_headers": missing_headers,
            "redirected_to_https": response.url.startswith("https://"),
        }

    def _check_rest_auth(self, username: Optional[str], password: Optional[str]) -> Dict[str, object]:
        url = f"http://{self.target}:{self.http_port}/rest/system/resource"
        try:
            anonymous = requests.get(url, timeout=self.timeout, verify=False)
            auth_status = None
            if username is not None and password is not None:
                authenticated = requests.get(url, auth=(username, password), timeout=self.timeout, verify=False)
                auth_status = authenticated.status_code
            return {
                "reachable": True,
                "anonymous_status": anonymous.status_code,
                "authenticated_status": auth_status,
                "allows_anonymous": anonymous.status_code == 200,
            }
        except Exception as exc:
            return {"reachable": False, "error": str(exc)}

    @staticmethod
    def _classify_risk(
        http_result: Dict[str, object],
        https_result: Dict[str, object],
        rest_result: Dict[str, object],
    ) -> str:
        if rest_result.get("allows_anonymous"):
            return "high"
        if http_result.get("reachable") and not https_result.get("reachable"):
            return "high"
        if http_result.get("reachable") and http_result.get("missing_security_headers"):
            return "medium"
        return "low"
