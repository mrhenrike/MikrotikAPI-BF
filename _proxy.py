#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Proxy Support Module - MikrotikAPI-BF v2.0

This module provides proxy support for stealth operations:
- SOCKS5/SOCKS4/HTTP proxy protocols
- Authentication support
- Connection testing
- Context manager for automatic setup/restore

Author: André Henrique (@mrhenrike)
"""

import socket
import socks
from urllib.parse import urlparse

class ProxyManager:
    """
    Manages proxy connections for API and HTTP requests
    """
    
    PROXY_TYPES = {
        'socks5': socks.SOCKS5,
        'socks4': socks.SOCKS4,
        'http': socks.HTTP
    }
    
    def __init__(self, proxy_url=None):
        """
        Initialize proxy manager
        
        Args:
            proxy_url: Proxy URL in format: protocol://host:port
                      Examples: socks5://127.0.0.1:9050
                               http://proxy.example.com:8080
        """
        self.proxy_url = proxy_url
        self.proxy_type = None
        self.proxy_host = None
        self.proxy_port = None
        self.proxy_username = None
        self.proxy_password = None
        self.original_socket = socket.socket
        
        if proxy_url:
            self._parse_proxy()
    
    def _parse_proxy(self):
        """Parse proxy URL into components"""
        try:
            parsed = urlparse(self.proxy_url)
            
            # Get proxy type
            scheme = parsed.scheme.lower()
            if scheme not in self.PROXY_TYPES:
                raise ValueError(f"Unsupported proxy type: {scheme}")
            
            self.proxy_type = self.PROXY_TYPES[scheme]
            self.proxy_host = parsed.hostname
            self.proxy_port = parsed.port or self._default_port(scheme)
            self.proxy_username = parsed.username
            self.proxy_password = parsed.password
            
        except Exception as e:
            raise ValueError(f"Invalid proxy URL: {e}")
    
    @staticmethod
    def _default_port(scheme):
        """Get default port for proxy scheme"""
        defaults = {
            'socks5': 1080,
            'socks4': 1080,
            'http': 8080
        }
        return defaults.get(scheme, 1080)
    
    def setup_socket(self):
        """Configure socket to use proxy"""
        if not self.proxy_url:
            return
        
        socks.set_default_proxy(
            self.proxy_type,
            self.proxy_host,
            self.proxy_port,
            username=self.proxy_username,
            password=self.proxy_password
        )
        socket.socket = socks.socksocket
    
    def restore_socket(self):
        """Restore original socket"""
        socket.socket = self.original_socket
    
    def get_requests_proxies(self):
        """
        Get proxy dict for requests library
        
        Returns:
            dict: Proxies dict for requests
        """
        if not self.proxy_url:
            return None
        
        return {
            'http': self.proxy_url,
            'https': self.proxy_url
        }
    
    def test_connection(self, test_host="8.8.8.8", test_port=53, timeout=5):
        """
        Test if proxy is working
        
        Returns:
            bool: True if proxy works
        """
        if not self.proxy_url:
            return True
        
        try:
            self.setup_socket()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((test_host, test_port))
            sock.close()
            self.restore_socket()
            return True
        except Exception:
            self.restore_socket()
            return False
    
    def __enter__(self):
        """Context manager entry"""
        self.setup_socket()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.restore_socket()

