#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Network Discovery Module - MikrotikAPI-BF v2.0

This module handles automated discovery of Mikrotik devices on networks:
- CIDR network scanning (e.g., 192.168.1.0/24)
- IP range scanning
- Intelligent device identification
- Multi-threaded scanning
- JSON export

Author: André Henrique (@mrhenrike)
"""

import socket
import concurrent.futures
import ipaddress
from datetime import datetime

class MikrotikDiscovery:
    """
    Discovers Mikrotik devices on the network by scanning common ports
    """
    
    MIKROTIK_PORTS = {
        'api': 8728,
        'api-ssl': 8729,
        'winbox': 8291,
        'http': 80,
        'https': 443,
        'ssh': 22,
        'telnet': 23,
        'ftp': 21
    }
    
    def __init__(self, timeout=2, threads=50):
        self.timeout = timeout
        self.threads = threads
        self.results = []
    
    def scan_host(self, ip):
        """
        Scan a single host for Mikrotik services
        
        Args:
            ip: IP address to scan
            
        Returns:
            dict: Host info with open ports or None
        """
        open_ports = {}
        
        for service, port in self.MIKROTIK_PORTS.items():
            if self._is_port_open(ip, port):
                open_ports[service] = port
        
        if open_ports:
            # Try to identify if it's really a Mikrotik
            is_mikrotik = self._identify_mikrotik(ip, open_ports)
            return {
                'ip': ip,
                'ports': open_ports,
                'likely_mikrotik': is_mikrotik,
                'scanned_at': datetime.now().isoformat()
            }
        
        return None
    
    def _is_port_open(self, ip, port):
        """Check if a port is open"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                return result == 0
        except:
            return False
    
    def _identify_mikrotik(self, ip, open_ports):
        """
        Try to identify if host is a Mikrotik device
        
        Returns:
            bool: True if likely a Mikrotik
        """
        # If Winbox or API ports are open, it's very likely a Mikrotik
        if 'winbox' in open_ports or 'api' in open_ports or 'api-ssl' in open_ports:
            return True
        
        # Try to get HTTP banner
        if 'http' in open_ports:
            try:
                import requests
                response = requests.get(
                    f"http://{ip}",
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False
                )
                
                # Check for Mikrotik indicators in headers or content
                server = response.headers.get('Server', '').lower()
                content = response.text.lower()
                
                if 'mikrotik' in server or 'routeros' in server:
                    return True
                if 'mikrotik' in content or 'routeros' in content:
                    return True
                    
            except:
                pass
        
        return False
    
    def scan_network(self, network, callback=None):
        """
        Scan an entire network for Mikrotik devices
        
        Args:
            network: Network in CIDR notation (e.g., "192.168.1.0/24")
            callback: Optional callback function(current, total)
            
        Returns:
            list: List of discovered hosts
        """
        try:
            net = ipaddress.ip_network(network, strict=False)
            hosts = list(net.hosts())
            total = len(hosts)
            
            print(f"[*] Scanning {total} hosts in {network}...")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_ip = {executor.submit(self.scan_host, str(ip)): ip for ip in hosts}
                
                completed = 0
                for future in concurrent.futures.as_completed(future_to_ip):
                    result = future.result()
                    if result:
                        self.results.append(result)
                        print(f"[+] Found Mikrotik device: {result['ip']} (ports: {', '.join(result['ports'].keys())})")
                    
                    completed += 1
                    if callback:
                        callback(completed, total)
            
            return self.results
            
        except ValueError as e:
            raise ValueError(f"Invalid network: {e}")
    
    def scan_range(self, start_ip, end_ip, callback=None):
        """
        Scan a range of IP addresses
        
        Args:
            start_ip: Starting IP address
            end_ip: Ending IP address
            callback: Optional callback function(current, total)
            
        Returns:
            list: List of discovered hosts
        """
        try:
            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)
            
            if start > end:
                raise ValueError("Start IP must be less than end IP")
            
            # Generate list of IPs
            current = start
            ips = []
            while current <= end:
                ips.append(str(current))
                current += 1
            
            total = len(ips)
            print(f"[*] Scanning {total} hosts from {start_ip} to {end_ip}...")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_ip = {executor.submit(self.scan_host, ip): ip for ip in ips}
                
                completed = 0
                for future in concurrent.futures.as_completed(future_to_ip):
                    result = future.result()
                    if result:
                        self.results.append(result)
                        print(f"[+] Found Mikrotik device: {result['ip']} (ports: {', '.join(result['ports'].keys())})")
                    
                    completed += 1
                    if callback:
                        callback(completed, total)
            
            return self.results
            
        except ValueError as e:
            raise ValueError(f"Invalid IP range: {e}")
    
    def export_results(self, filename="mikrotik_discovery.json"):
        """Export discovery results to JSON"""
        import json
        with open(filename, 'w') as f:
            json.dump({
                'scan_time': datetime.now().isoformat(),
                'total_found': len(self.results),
                'devices': self.results
            }, f, indent=4)
        return filename

