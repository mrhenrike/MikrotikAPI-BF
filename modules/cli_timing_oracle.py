#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)
# Version: 1.0.0

"""
CLI Timing Oracle Module — MikrotikAPI-BF
=========================================
Measures authentication response timing over SSH, Telnet, FTP, and API.
"""

from __future__ import annotations

import ftplib
import socket
import statistics
import time
from typing import Dict, List


class CLITimingOracle:
    """Collect protocol-level authentication timing samples."""

    def __init__(self, target: str, username: str, timeout: float = 3.0) -> None:
        self.target = target
        self.username = username
        self.timeout = timeout

    def run(self, password: str, samples: int = 30) -> Dict[str, object]:
        """Measure average timings across supported channels."""
        channels = {
            "api": self._probe_api,
            "ftp": self._probe_ftp,
            "telnet": self._probe_telnet,
            "ssh": self._probe_ssh,
        }
        results: Dict[str, Dict[str, object]] = {}
        for channel, handler in channels.items():
            values = [handler(password) for _ in range(samples)]
            filtered = [value for value in values if value > 0]
            results[channel] = {
                "samples": len(filtered),
                "mean_us": statistics.mean(filtered) if filtered else 0.0,
                "stdev_us": statistics.pstdev(filtered) if len(filtered) > 1 else 0.0,
            }
        return {"target": self.target, "username": self.username, "results": results}

    def _probe_api(self, password: str) -> float:
        started = time.perf_counter_ns()
        try:
            from core.api import Api
            api = Api(self.target, 8728, timeout=self.timeout)
            api.login(self.username, password)
            api.disconnect()
        except Exception:
            pass
        return (time.perf_counter_ns() - started) / 1000.0

    def _probe_ftp(self, password: str) -> float:
        started = time.perf_counter_ns()
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.target, 21, timeout=self.timeout)
            ftp.login(self.username, password)
            ftp.quit()
        except Exception:
            pass
        return (time.perf_counter_ns() - started) / 1000.0

    def _probe_telnet(self, password: str) -> float:
        started = time.perf_counter_ns()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((self.target, 23))
            sock.recv(512)
            sock.sendall((self.username + "\r\n").encode("utf-8"))
            sock.recv(512)
            sock.sendall((password + "\r\n").encode("utf-8"))
            sock.recv(512)
        except Exception:
            pass
        finally:
            sock.close()
        return (time.perf_counter_ns() - started) / 1000.0

    def _probe_ssh(self, password: str) -> float:
        started = time.perf_counter_ns()
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.target,
                port=22,
                username=self.username,
                password=password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            client.close()
        except Exception:
            pass
        return (time.perf_counter_ns() - started) / 1000.0
