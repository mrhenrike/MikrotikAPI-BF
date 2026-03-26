#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""
xpl — MikrotikAPI-BF Exploitation Module
==========================================
Provides a curated database of MikroTik RouterOS CVEs with PoC scripts,
NVD and Shodan integration for up-to-date vulnerability lookup, and a
version-aware exploit scanner.

Usage:
    from xpl.scanner import ExploitScanner
    scanner = ExploitScanner()
    results = scanner.scan_target("192.168.1.1")
    scanner.print_results(results)
"""

from .cve_db import CVE_DATABASE, get_cves_for_version, get_all_cves
from .scanner import ExploitScanner

__all__ = [
    "CVE_DATABASE",
    "get_cves_for_version",
    "get_all_cves",
    "ExploitScanner",
]
