#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Smart Wordlists Module - MikrotikAPI-BF v2.1

This module provides intelligent wordlist management for Mikrotik pentesting:
- Mikrotik-specific wordlists
- Smart combination generation
- Target-based wordlist customization
- Version-specific patterns
- Brazilian wordlists integration

Author: André Henrique (@mrhenrike)
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from datetime import datetime

class SmartWordlistManager:
    """
    Intelligent wordlist management for Mikrotik pentesting
    """
    
    def __init__(self, wordlists_dir="wordlists"):
        self.wordlists_dir = Path(wordlists_dir)
        self.mikrotik_defaults = [
            'admin', 'mikrotik', 'routeros', 'user', 'manager',
            'support', 'guest', 'operator', 'tech', 'root'
        ]
        
        self.mikrotik_passwords = [
            '', 'admin', 'password', 'mikrotik', 'routeros',
            '123456', 'password123', 'admin123', 'mikrotik123',
            'routeros123', '12345678', 'qwerty', 'abc123'
        ]
        
        # Version-specific patterns
        self.version_patterns = {
            '6.x': ['admin', 'mikrotik', 'routeros'],
            '7.x': ['admin', 'mikrotik', 'routeros', 'user'],
            '7.1+': ['admin', 'mikrotik', 'routeros', 'user', 'manager']
        }
        
        # Brazilian wordlists
        self.brazilian_wordlists = {
            'usernames': 'username_br.lst',
            'passwords': 'labs_passwords.lst',
            'users': 'labs_users.lst',
            'mikrotik_pass': 'labs_mikrotik_pass.lst'
        }
    
    def load_wordlist(self, filename: str) -> List[str]:
        """
        Load wordlist from file
        
        Args:
            filename: Name of wordlist file
            
        Returns:
            List of words from file
        """
        filepath = self.wordlists_dir / filename
        if not filepath.exists():
            return []
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                words = [line.strip() for line in f if line.strip()]
            return words
        except Exception as e:
            print(f"Error loading wordlist {filename}: {e}")
            return []
    
    def get_mikrotik_wordlist(self, wordlist_type: str = "combined") -> List[str]:
        """
        Get Mikrotik-specific wordlist
        
        Args:
            wordlist_type: Type of wordlist (usernames, passwords, combined)
            
        Returns:
            List of Mikrotik-specific words
        """
        if wordlist_type == "usernames":
            return self.mikrotik_defaults.copy()
        elif wordlist_type == "passwords":
            return self.mikrotik_passwords.copy()
        elif wordlist_type == "combined":
            return self.mikrotik_defaults + self.mikrotik_passwords
        else:
            return []
    
    def get_brazilian_wordlist(self, wordlist_type: str) -> List[str]:
        """
        Get Brazilian wordlist
        
        Args:
            wordlist_type: Type of wordlist (usernames, passwords, users, mikrotik_pass)
            
        Returns:
            List of Brazilian words
        """
        if wordlist_type not in self.brazilian_wordlists:
            return []
        
        filename = self.brazilian_wordlists[wordlist_type]
        return self.load_wordlist(filename)
    
    def generate_smart_combinations(self, target_info: Dict) -> List[Tuple[str, str]]:
        """
        Generate smart combinations based on target information
        
        Args:
            target_info: Target device information
            
        Returns:
            List of (username, password) tuples
        """
        combinations = []
        
        # Get base wordlists
        usernames = self.get_mikrotik_wordlist("usernames")
        passwords = self.get_mikrotik_wordlist("passwords")
        
        # Add Brazilian wordlists if available
        br_usernames = self.get_brazilian_wordlist("usernames")
        br_passwords = self.get_brazilian_wordlist("passwords")
        br_users = self.get_brazilian_wordlist("users")
        br_mikrotik_pass = self.get_brazilian_wordlist("mikrotik_pass")
        
        # Combine wordlists
        usernames.extend(br_usernames)
        usernames.extend(br_users)
        passwords.extend(br_passwords)
        passwords.extend(br_mikrotik_pass)
        
        # Remove duplicates
        usernames = list(set(usernames))
        passwords = list(set(passwords))
        
        # Generate combinations
        for username in usernames:
            for password in passwords:
                combinations.append((username, password))
        
        # Add target-specific combinations
        target_combinations = self._generate_target_specific_combinations(target_info)
        combinations.extend(target_combinations)
        
        return combinations
    
    def _generate_target_specific_combinations(self, target_info: Dict) -> List[Tuple[str, str]]:
        """
        Generate combinations specific to target
        
        Args:
            target_info: Target device information
            
        Returns:
            List of target-specific combinations
        """
        combinations = []
        
        # Extract target information
        target_ip = target_info.get('target', '')
        hostname = target_info.get('hostname', '')
        version = target_info.get('routeros_version', '')
        model = target_info.get('model', '')
        
        # IP-based combinations
        if target_ip:
            ip_parts = target_ip.split('.')
            if len(ip_parts) == 4:
                # Use last octet as password
                combinations.append(('admin', ip_parts[-1]))
                combinations.append(('mikrotik', ip_parts[-1]))
                
                # Use IP as password
                combinations.append(('admin', target_ip))
                combinations.append(('mikrotik', target_ip))
        
        # Hostname-based combinations
        if hostname:
            hostname_lower = hostname.lower()
            combinations.append(('admin', hostname_lower))
            combinations.append(('mikrotik', hostname_lower))
            
            # Extract company name from hostname
            if '.' in hostname:
                company = hostname.split('.')[0]
                combinations.append(('admin', company))
                combinations.append(('mikrotik', company))
        
        # Version-based combinations
        if version:
            version_clean = re.sub(r'[^\d.]', '', version)
            combinations.append(('admin', version_clean))
            combinations.append(('mikrotik', version_clean))
        
        # Model-based combinations
        if model:
            model_lower = model.lower()
            combinations.append(('admin', model_lower))
            combinations.append(('mikrotik', model_lower))
        
        return combinations
    
    def get_version_specific_wordlist(self, version: str) -> List[str]:
        """
        Get version-specific wordlist
        
        Args:
            version: RouterOS version
            
        Returns:
            List of version-specific words
        """
        if version.startswith('6.'):
            return self.version_patterns.get('6.x', [])
        elif version.startswith('7.0'):
            return self.version_patterns.get('7.x', [])
        elif version.startswith('7.1'):
            return self.version_patterns.get('7.1+', [])
        else:
            return self.mikrotik_defaults.copy()
    
    def create_custom_wordlist(self, target_info: Dict, output_file: str = None) -> str:
        """
        Create custom wordlist for specific target
        
        Args:
            target_info: Target device information
            output_file: Output file path
            
        Returns:
            Path to created wordlist file
        """
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_ip = target_info.get('target', 'unknown').replace('.', '_')
            output_file = f"custom_wordlist_{target_ip}_{timestamp}.txt"
        
        # Generate combinations
        combinations = self.generate_smart_combinations(target_info)
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            for username, password in combinations:
                f.write(f"{username}:{password}\n")
        
        return output_file
    
    def get_wordlist_stats(self) -> Dict:
        """
        Get wordlist statistics
        
        Returns:
            Dictionary with wordlist statistics
        """
        stats = {
            'mikrotik_defaults': len(self.mikrotik_defaults),
            'mikrotik_passwords': len(self.mikrotik_passwords),
            'brazilian_wordlists': {},
            'total_combinations': 0
        }
        
        # Count Brazilian wordlists
        for wordlist_type, filename in self.brazilian_wordlists.items():
            words = self.get_brazilian_wordlist(wordlist_type)
            stats['brazilian_wordlists'][wordlist_type] = len(words)
        
        # Calculate total combinations
        usernames = self.get_mikrotik_wordlist("usernames")
        passwords = self.get_mikrotik_wordlist("passwords")
        stats['total_combinations'] = len(usernames) * len(passwords)
        
        return stats
    
    def optimize_wordlist(self, wordlist: List[str], max_size: int = 1000) -> List[str]:
        """
        Optimize wordlist by removing duplicates and limiting size
        
        Args:
            wordlist: Original wordlist
            max_size: Maximum size of optimized wordlist
            
        Returns:
            Optimized wordlist
        """
        # Remove duplicates while preserving order
        seen = set()
        optimized = []
        
        for word in wordlist:
            if word not in seen and len(optimized) < max_size:
                seen.add(word)
                optimized.append(word)
        
        return optimized
