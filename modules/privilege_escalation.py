#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)
# Version: 1.0.0

"""
Privilege Escalation Test Module — MikrotikAPI-BF
=================================================
Executes low-impact privilege checks for limited users across RouterOS APIs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

import requests


@dataclass(frozen=True)
class Account:
    """Credential tuple for privilege checks."""

    username: str
    password: str


class PrivEscTester:
    """Run authenticated privilege escalation probes."""

    def __init__(self, target: str, timeout: float = 5.0, http_port: int = 80) -> None:
        self.target = target
        self.timeout = timeout
        self.http_port = http_port

    def run(self, accounts: List[Account]) -> Dict[str, object]:
        """Execute privilege probes for each account."""
        results: List[Dict[str, object]] = []
        for account in accounts:
            result = {
                "username": account.username,
                "rest_system_access": self._test_rest_system_access(account),
                "rest_write_attempt": self._test_rest_write(account),
                "api_sensitive_read": self._test_api_sensitive_read(account),
            }
            result["risk"] = self._classify(result)
            results.append(result)
        return {"target": self.target, "accounts": results}

    def _test_rest_system_access(self, account: Account) -> Dict[str, object]:
        url = f"http://{self.target}:{self.http_port}/rest/system/resource"
        try:
            response = requests.get(url, auth=(account.username, account.password), timeout=self.timeout, verify=False)
            return {"status_code": response.status_code, "allowed": response.status_code == 200}
        except Exception as exc:
            return {"status_code": None, "allowed": False, "error": str(exc)}

    def _test_rest_write(self, account: Account) -> Dict[str, object]:
        url = f"http://{self.target}:{self.http_port}/rest/system/identity"
        payload = {"name": "mikrotikapi-bf-privesc-probe"}
        try:
            response = requests.patch(
                url,
                auth=(account.username, account.password),
                timeout=self.timeout,
                verify=False,
                json=payload,
            )
            allowed = response.status_code in {200, 201, 204}
            return {"status_code": response.status_code, "write_allowed": allowed}
        except Exception as exc:
            return {"status_code": None, "write_allowed": False, "error": str(exc)}

    def _test_api_sensitive_read(self, account: Account) -> Dict[str, object]:
        try:
            from core.api import Api
            api = Api(self.target, 8728, timeout=self.timeout)
            if not api.login(account.username, account.password):
                return {"allowed": False, "error": "login_failed"}
            api.send(["/user/print"])
            sentence = api.read_sentence()
            api.disconnect()
            allowed = any("name=" in part for part in sentence)
            return {"allowed": allowed, "response_size": len(sentence)}
        except Exception as exc:
            return {"allowed": False, "error": str(exc)}

    @staticmethod
    def _classify(result: Dict[str, object]) -> str:
        rest_write = bool((result.get("rest_write_attempt") or {}).get("write_allowed"))
        api_sensitive = bool((result.get("api_sensitive_read") or {}).get("allowed"))
        if rest_write or api_sensitive:
            return "high"
        rest_system = bool((result.get("rest_system_access") or {}).get("allowed"))
        if rest_system:
            return "medium"
        return "low"

    @staticmethod
    def parse_accounts(raw_accounts: str, default_password: Optional[str] = None) -> List[Account]:
        """Parse account input format.

        Args:
            raw_accounts: Comma-separated entries (`user:pass,user2:pass2` or `user,user2`).
            default_password: Password used when entry has only username.
        """
        parsed: List[Account] = []
        for chunk in raw_accounts.split(","):
            token = chunk.strip()
            if not token:
                continue
            if ":" in token:
                user, pwd = token.split(":", 1)
                parsed.append(Account(username=user, password=pwd))
            elif default_password is not None:
                parsed.append(Account(username=token, password=default_password))
        return parsed
