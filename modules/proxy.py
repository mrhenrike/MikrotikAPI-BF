#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)

"""
Proxy Support Module — MikrotikAPI-BF
========================================
SOCKS5/SOCKS4/HTTP proxy integration for stealth operations.
"""

import socket
from urllib.parse import urlparse
from typing import Dict, Optional

try:
    import socks as _socks_lib  # PySocks
    _HAS_PYSOCKS = True
except ImportError:
    _HAS_PYSOCKS = False


class ProxyManager:
    """
    Configure and manage a proxy for both socket-level (API) and HTTP requests.

    Args:
        proxy_url: Proxy URL, e.g. ``socks5://127.0.0.1:9050`` or
                   ``http://user:pass@proxy.example.com:8080``.
    """

    _TYPES: Dict[str, int] = {
        "socks5": 2,   # socks.SOCKS5
        "socks4": 1,   # socks.SOCKS4
        "http":   3,   # socks.HTTP
    }

    _DEFAULT_PORTS: Dict[str, int] = {
        "socks5": 1080,
        "socks4": 1080,
        "http":   8080,
    }

    def __init__(self, proxy_url: Optional[str] = None) -> None:
        self.proxy_url = proxy_url
        self.proxy_type: Optional[int] = None
        self.proxy_host: Optional[str] = None
        self.proxy_port: Optional[int] = None
        self.proxy_user: Optional[str] = None
        self.proxy_pass: Optional[str] = None
        self._original_socket = socket.socket

        if proxy_url:
            self._parse(proxy_url)

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def _parse(self, url: str) -> None:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme not in self._TYPES:
            raise ValueError(f"Unsupported proxy scheme: {scheme!r}")
        self.proxy_type = self._TYPES[scheme]
        self.proxy_host = parsed.hostname
        self.proxy_port = parsed.port or self._DEFAULT_PORTS[scheme]
        self.proxy_user = parsed.username
        self.proxy_pass = parsed.password

    # ------------------------------------------------------------------
    # Socket-level proxy (for RouterOS API TCP connections)
    # ------------------------------------------------------------------

    def setup_socket(self) -> None:
        """Monkeypatch ``socket.socket`` to route through the proxy."""
        if not self.proxy_url or not _HAS_PYSOCKS:
            return
        _socks_lib.set_default_proxy(
            self.proxy_type,
            self.proxy_host,
            self.proxy_port,
            username=self.proxy_user,
            password=self.proxy_pass,
        )
        socket.socket = _socks_lib.socksocket  # type: ignore[assignment]

    def restore_socket(self) -> None:
        """Restore the original socket."""
        socket.socket = self._original_socket

    # ------------------------------------------------------------------
    # HTTP-level proxy (for requests library)
    # ------------------------------------------------------------------

    def get_requests_proxies(self) -> Optional[Dict[str, str]]:
        """Return a ``proxies`` dict suitable for ``requests.get``."""
        if not self.proxy_url:
            return None
        return {"http": self.proxy_url, "https": self.proxy_url}

    # ------------------------------------------------------------------
    # Testing
    # ------------------------------------------------------------------

    def test_connection(self, host: str = "8.8.8.8", port: int = 53, timeout: int = 5) -> bool:
        """Return ``True`` if the proxy is reachable."""
        if not self.proxy_url:
            return True
        try:
            self.setup_socket()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            s.close()
            return True
        except Exception:
            return False
        finally:
            self.restore_socket()

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "ProxyManager":
        self.setup_socket()
        return self

    def __exit__(self, *_) -> None:
        self.restore_socket()
