#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""
Modules package for MikrotikAPI-BF.
Feature-level modules: stealth, fingerprinting, wordlists, reports,
proxy management, and network discovery.
"""

from .stealth import StealthManager
from .fingerprint import MikrotikFingerprinter
from .wordlists import SmartWordlistManager
from .proxy import ProxyManager
from .discovery import MikrotikDiscovery
from .snmp import SNMPScanner
from .hardening_check import HardeningValidator
from .web_security import WebSecurityTester
from .ssh_audit import SSHAuditor
from .timing_oracle import TimingOracleAttacker
from .privilege_escalation import PrivEscTester
from .cli_timing_oracle import CLITimingOracle

__all__ = [
    "StealthManager",
    "MikrotikFingerprinter",
    "SmartWordlistManager",
    "ProxyManager",
    "MikrotikDiscovery",
    "SNMPScanner",
    "HardeningValidator",
    "WebSecurityTester",
    "SSHAuditor",
    "TimingOracleAttacker",
    "PrivEscTester",
    "CLITimingOracle",
]
