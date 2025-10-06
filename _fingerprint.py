#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Advanced Fingerprinting Module - MikrotikAPI-BF v2.1

This module provides advanced Mikrotik device fingerprinting:
- RouterOS version detection
- Model identification
- Service enumeration
- Vulnerability assessment
- Device characterization

Author: André Henrique (@mrhenrike)
"""

import socket
import requests
import re
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple

class MikrotikFingerprinter:
    """
    Advanced Mikrotik device fingerprinting
    """
    
    def __init__(self, timeout=5):
        self.timeout = timeout
        self.fingerprints = {
            'routeros_versions': [
                r'RouterOS (\d+\.\d+)',
                r'RouterOS v(\d+\.\d+\.\d+)',
                r'version (\d+\.\d+\.\d+)'
            ],
            'mikrotik_models': [
                r'RouterBoard (\w+)',
                r'model (\w+)',
                r'board-name (\w+)'
            ],
            'api_versions': [
                r'API version (\d+)',
                r'api-version (\d+)'
            ]
        }
        
        # Known Mikrotik ports and services
        self.mikrotik_ports = {
            'api': 8728,
            'api-ssl': 8729,
            'winbox': 8291,
            'http': 80,
            'https': 443,
            'ssh': 22,
            'telnet': 23,
            'ftp': 21,
            'snmp': 161
        }
        
        # Vulnerability patterns
        self.vulnerability_patterns = {
            'default_credentials': [
                'admin', 'mikrotik', 'routeros', 'user', 'manager'
            ],
            'weak_auth': [
                'password', '123456', 'admin123', 'mikrotik123'
            ],
            'exposed_services': [
                'winbox', 'api', 'telnet', 'ftp'
            ]
        }
    
    def fingerprint_device(self, target: str) -> Dict:
        """
        Comprehensive device fingerprinting
        
        Args:
            target: Target IP address or hostname
            
        Returns:
            Dictionary with device information
        """
        info = {
            'target': target,
            'is_mikrotik': False,
            'routeros_version': None,
            'model': None,
            'api_version': None,
            'open_ports': [],
            'services': [],
            'vulnerabilities': [],
            'risk_score': 0,
            'fingerprint_time': datetime.now().isoformat()
        }
        
        # Port scanning
        open_ports = self._scan_ports(target)
        info['open_ports'] = open_ports
        
        if not open_ports:
            return info
        
        # Service detection
        services = self._detect_services(target, open_ports)
        info['services'] = services
        
        # Check if it's Mikrotik
        if self._is_mikrotik_device(target, services):
            info['is_mikrotik'] = True
            
            # Get detailed information
            info.update(self._get_detailed_info(target, services))
            
            # Vulnerability assessment
            info['vulnerabilities'] = self._assess_vulnerabilities(target, info)
            info['risk_score'] = self._calculate_risk_score(info)
        
        return info
    
    def _scan_ports(self, target: str) -> List[int]:
        """Scan for open ports"""
        open_ports = []
        
        for service, port in self.mikrotik_ports.items():
            if self._is_port_open(target, port):
                open_ports.append(port)
        
        return open_ports
    
    def _is_port_open(self, target: str, port: int) -> bool:
        """Check if port is open"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))
                return result == 0
        except:
            return False
    
    def _detect_services(self, target: str, open_ports: List[int]) -> List[str]:
        """Detect services on open ports"""
        services = []
        
        for port in open_ports:
            service = self._identify_service(target, port)
            if service:
                services.append(service)
        
        return services
    
    def _identify_service(self, target: str, port: int) -> Optional[str]:
        """Identify service on specific port"""
        port_to_service = {
            8728: 'api',
            8729: 'api-ssl',
            8291: 'winbox',
            80: 'http',
            443: 'https',
            22: 'ssh',
            23: 'telnet',
            21: 'ftp',
            161: 'snmp'
        }
        
        service = port_to_service.get(port)
        if not service:
            return None
        
        # Verify service is actually running
        if self._verify_service(target, port, service):
            return service
        
        return None
    
    def _verify_service(self, target: str, port: int, service: str) -> bool:
        """Verify service is actually running"""
        try:
            if service in ['http', 'https']:
                protocol = 'https' if port == 443 else 'http'
                url = f"{protocol}://{target}:{port}"
                response = requests.get(url, timeout=self.timeout, verify=False)
                return 'mikrotik' in response.text.lower() or 'routeros' in response.text.lower()
            
            elif service == 'api':
                # Try to connect to API
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))
                sock.close()
                return True
            
            elif service == 'winbox':
                # Winbox uses UDP, but we can check if port is open
                return True
            
            else:
                return True
                
        except:
            return False
    
    def _is_mikrotik_device(self, target: str, services: List[str]) -> bool:
        """Determine if device is Mikrotik"""
        # Check for Mikrotik-specific services
        mikrotik_services = ['api', 'api-ssl', 'winbox']
        if any(service in services for service in mikrotik_services):
            return True
        
        # Check HTTP response
        try:
            response = requests.get(f"http://{target}", timeout=self.timeout, verify=False)
            if 'mikrotik' in response.text.lower() or 'routeros' in response.text.lower():
                return True
        except:
            pass
        
        return False
    
    def _get_detailed_info(self, target: str, services: List[str]) -> Dict:
        """Get detailed device information"""
        info = {}
        
        # Try to get RouterOS version
        if 'api' in services:
            version = self._get_routeros_version(target)
            if version:
                info['routeros_version'] = version
        
        # Try to get model information
        if 'http' in services or 'https' in services:
            model = self._get_device_model(target)
            if model:
                info['model'] = model
        
        # Try to get API version
        if 'api' in services:
            api_version = self._get_api_version(target)
            if api_version:
                info['api_version'] = api_version
        
        return info
    
    def _get_routeros_version(self, target: str) -> Optional[str]:
        """Get RouterOS version via API"""
        try:
            # This would require actual API connection
            # For now, return None - would need full API implementation
            return None
        except:
            return None
    
    def _get_device_model(self, target: str) -> Optional[str]:
        """Get device model via HTTP"""
        try:
            response = requests.get(f"http://{target}", timeout=self.timeout, verify=False)
            text = response.text.lower()
            
            # Look for model patterns
            for pattern in self.fingerprints['mikrotik_models']:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    return match.group(1)
        except:
            pass
        
        return None
    
    def _get_api_version(self, target: str) -> Optional[str]:
        """Get API version"""
        try:
            # This would require actual API connection
            return None
        except:
            return None
    
    def _assess_vulnerabilities(self, target: str, info: Dict) -> List[str]:
        """Assess device vulnerabilities"""
        vulnerabilities = []
        
        # Check for exposed services
        exposed_services = ['telnet', 'ftp', 'winbox']
        for service in exposed_services:
            if service in info.get('services', []):
                vulnerabilities.append(f"Exposed {service.upper()} service")
        
        # Check for default credentials (would need actual testing)
        if 'api' in info.get('services', []):
            vulnerabilities.append("API service exposed - test for default credentials")
        
        # Check for HTTP without HTTPS
        if 'http' in info.get('services', []) and 'https' not in info.get('services', []):
            vulnerabilities.append("HTTP service without HTTPS encryption")
        
        return vulnerabilities
    
    def _calculate_risk_score(self, info: Dict) -> float:
        """Calculate risk score (0-10)"""
        score = 0.0
        
        # Base score for being Mikrotik
        if info.get('is_mikrotik'):
            score += 2.0
        
        # Exposed services
        exposed_services = ['telnet', 'ftp', 'winbox', 'api']
        for service in exposed_services:
            if service in info.get('services', []):
                score += 1.5
        
        # Vulnerabilities
        vulnerabilities = info.get('vulnerabilities', [])
        score += len(vulnerabilities) * 0.5
        
        # No HTTPS
        if 'http' in info.get('services', []) and 'https' not in info.get('services', []):
            score += 1.0
        
        return min(score, 10.0)
    
    def generate_fingerprint_report(self, info: Dict) -> str:
        """Generate human-readable fingerprint report"""
        report = f"""
MIKROTIK DEVICE FINGERPRINT REPORT
==================================

Target: {info.get('target', 'Unknown')}
Fingerprint Time: {info.get('fingerprint_time', 'Unknown')}
Is Mikrotik: {'YES' if info.get('is_mikrotik') else 'NO'}

DEVICE INFORMATION:
------------------
RouterOS Version: {info.get('routeros_version', 'Unknown')}
Model: {info.get('model', 'Unknown')}
API Version: {info.get('api_version', 'Unknown')}

OPEN PORTS:
-----------
{', '.join(map(str, info.get('open_ports', [])))}

SERVICES DETECTED:
-----------------
{', '.join(info.get('services', []))}

VULNERABILITIES:
---------------
{chr(10).join(f'- {vuln}' for vuln in info.get('vulnerabilities', []))}

RISK SCORE: {info.get('risk_score', 0):.1f}/10
"""
        return report
