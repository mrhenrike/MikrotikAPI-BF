#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)

"""
Network Discovery Module — MikrotikAPI-BF
==========================================
Multi-threaded discovery of Mikrotik RouterOS devices on CIDR ranges
and IP ranges using common service port detection.
"""

import concurrent.futures
import ipaddress
import json
import socket
from datetime import datetime
from typing import Callable, Dict, List, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class MikrotikDiscovery:
    """
    Scan networks and IP ranges for Mikrotik devices.

    Args:
        timeout: Per-host TCP timeout in seconds.
        threads: Maximum concurrent threads for scanning.
    """

    MIKROTIK_PORTS: Dict[str, int] = {
        "api": 8728,
        "api-ssl": 8729,
        "winbox": 8291,
        "http": 80,
        "https": 443,
        "ssh": 22,
        "telnet": 23,
        "ftp": 21,
    }

    def __init__(self, timeout: int = 2, threads: int = 50) -> None:
        self.timeout = timeout
        self.threads = threads
        self.results: List[Dict] = []

    # ------------------------------------------------------------------
    # Public scan methods
    # ------------------------------------------------------------------

    def scan_network(
        self, network: str, callback: Optional[Callable[[int, int], None]] = None
    ) -> List[Dict]:
        """
        Scan all host addresses in a CIDR network.

        Args:
            network:  CIDR notation, e.g. ``"192.168.1.0/24"``.
            callback: Optional progress callback ``fn(done, total)``.

        Returns:
            List of result dicts for discovered devices.
        """
        net = ipaddress.ip_network(network, strict=False)
        hosts = [str(h) for h in net.hosts()]
        return self._scan_bulk(hosts, callback)

    def scan_range(
        self,
        start_ip: str,
        end_ip: str,
        callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[Dict]:
        """
        Scan an explicit IP range.

        Args:
            start_ip: First IP address of the range.
            end_ip:   Last IP address of the range.
            callback: Optional progress callback.

        Returns:
            List of result dicts for discovered devices.
        """
        start = ipaddress.ip_address(start_ip)
        end = ipaddress.ip_address(end_ip)
        if start > end:
            raise ValueError("start_ip must be ≤ end_ip")
        current = start
        ips: List[str] = []
        while current <= end:
            ips.append(str(current))
            current += 1  # type: ignore[assignment]
        return self._scan_bulk(ips, callback)

    def scan_host(self, ip: str) -> Optional[Dict]:
        """
        Scan a single host.

        Returns:
            Result dict if open Mikrotik-relevant ports found, else ``None``.
        """
        open_ports: Dict[str, int] = {}
        for service, port in self.MIKROTIK_PORTS.items():
            if self._tcp_open(ip, port):
                open_ports[service] = port

        if not open_ports:
            return None

        return {
            "ip": ip,
            "ports": open_ports,
            "likely_mikrotik": self._identify_mikrotik(ip, open_ports),
            "scanned_at": datetime.now().isoformat(),
        }

    def export_results(self, filename: str = "mikrotik_discovery.json") -> str:
        """Export discovery results to a JSON file."""
        data = {
            "scan_time": datetime.now().isoformat(),
            "total_found": len(self.results),
            "devices": self.results,
        }
        with open(filename, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=4)
        return filename

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _scan_bulk(
        self, ips: List[str], callback: Optional[Callable[[int, int], None]]
    ) -> List[Dict]:
        total = len(ips)
        done = 0
        discovered: List[Dict] = []

        print(f"[*] Scanning {total} host(s)…")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as pool:
            future_map = {pool.submit(self.scan_host, ip): ip for ip in ips}
            for future in concurrent.futures.as_completed(future_map):
                result = future.result()
                if result:
                    discovered.append(result)
                    self.results.append(result)
                    ports_str = ", ".join(result["ports"].keys())
                    print(f"[+] {result['ip']} — ports: {ports_str}")
                done += 1
                if callback:
                    callback(done, total)

        return discovered

    def _tcp_open(self, ip: str, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                return s.connect_ex((ip, port)) == 0
        except Exception:
            return False

    def _identify_mikrotik(self, ip: str, open_ports: Dict[str, int]) -> bool:
        # Strong indicators
        if any(svc in open_ports for svc in ("winbox", "api", "api-ssl")):
            return True
        # HTTP banner check
        if "http" in open_ports:
            try:
                resp = requests.get(
                    f"http://{ip}",
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False,
                )
                text = resp.text.lower()
                hdr = resp.headers.get("Server", "").lower()
                return (
                    "mikrotik" in hdr
                    or "routeros" in hdr
                    or "mikrotik" in text
                    or "routeros" in text
                )
            except Exception:
                pass
        return False
