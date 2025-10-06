#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Stealth Mode Module - MikrotikAPI-BF v2.1

This module implements stealth capabilities to avoid detection during pentests:
- Fibonacci delays to avoid IDS/IPS detection
- User-Agent rotation
- Jitter application
- Proxy rotation
- Traffic obfuscation

Author: André Henrique (@mrhenrike)
"""

import random
import time
import threading
from typing import List, Optional

class StealthMode:
    """
    Implements stealth capabilities for pentesting
    """
    
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36'
        ]
        
        # Fibonacci sequence for delays (more natural)
        self.fibonacci_delays = [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144]
        
        # Current state
        self.current_user_agent = 0
        self.delay_history = []
        self.lock = threading.Lock()
    
    def get_random_delay(self, base_delay: float = 5.0) -> float:
        """
        Get randomized delay using Fibonacci sequence
        
        Args:
            base_delay: Base delay in seconds
            
        Returns:
            Randomized delay in seconds
        """
        if not self.enabled:
            return base_delay
        
        with self.lock:
            # Choose Fibonacci delay
            fib_delay = random.choice(self.fibonacci_delays)
            
            # Apply jitter (0.5 to 1.5 multiplier)
            jitter = random.uniform(0.5, 1.5)
            
            # Combine with base delay
            final_delay = (base_delay + fib_delay) * jitter
            
            # Store for pattern analysis
            self.delay_history.append(final_delay)
            if len(self.delay_history) > 10:
                self.delay_history.pop(0)
            
            return final_delay
    
    def get_user_agent(self) -> str:
        """
        Get rotated user agent
        
        Returns:
            User agent string
        """
        if not self.enabled:
            return self.user_agents[0]
        
        with self.lock:
            user_agent = self.user_agents[self.current_user_agent]
            self.current_user_agent = (self.current_user_agent + 1) % len(self.user_agents)
            return user_agent
    
    def apply_stealth_delay(self, base_delay: float = 5.0):
        """
        Apply stealth delay
        
        Args:
            base_delay: Base delay in seconds
        """
        if not self.enabled:
            time.sleep(base_delay)
            return
        
        delay = self.get_random_delay(base_delay)
        time.sleep(delay)
    
    def get_stealth_headers(self) -> dict:
        """
        Get stealth headers for HTTP requests
        
        Returns:
            Dictionary of stealth headers
        """
        headers = {
            'User-Agent': self.get_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # Add random headers occasionally
        if random.random() < 0.3:  # 30% chance
            headers['Cache-Control'] = 'no-cache'
            headers['Pragma'] = 'no-cache'
        
        return headers
    
    def obfuscate_request(self, request_data: str) -> str:
        """
        Obfuscate request data to avoid detection
        
        Args:
            request_data: Original request data
            
        Returns:
            Obfuscated request data
        """
        if not self.enabled:
            return request_data
        
        # Add random whitespace
        if random.random() < 0.2:  # 20% chance
            request_data = request_data.replace(' ', '  ')
        
        return request_data
    
    def get_stealth_stats(self) -> dict:
        """
        Get stealth statistics
        
        Returns:
            Dictionary with stealth statistics
        """
        with self.lock:
            return {
                'enabled': self.enabled,
                'user_agent_rotations': self.current_user_agent,
                'delay_history': self.delay_history[-5:],  # Last 5 delays
                'avg_delay': sum(self.delay_history) / len(self.delay_history) if self.delay_history else 0
            }
    
    def reset_stealth(self):
        """Reset stealth state"""
        with self.lock:
            self.current_user_agent = 0
            self.delay_history.clear()


class StealthManager:
    """
    Manages stealth operations across multiple threads
    """
    
    def __init__(self, enabled=True):
        self.stealth_mode = StealthMode(enabled)
        self.thread_stealth = {}
        self.lock = threading.Lock()
    
    def get_thread_stealth(self, thread_id: int) -> StealthMode:
        """
        Get stealth mode for specific thread
        
        Args:
            thread_id: Thread identifier
            
        Returns:
            StealthMode instance for thread
        """
        with self.lock:
            if thread_id not in self.thread_stealth:
                self.thread_stealth[thread_id] = StealthMode(self.stealth_mode.enabled)
            return self.thread_stealth[thread_id]
    
    def apply_stealth_for_thread(self, thread_id: int, base_delay: float = 5.0):
        """
        Apply stealth delay for specific thread
        
        Args:
            thread_id: Thread identifier
            base_delay: Base delay in seconds
        """
        stealth = self.get_thread_stealth(thread_id)
        stealth.apply_stealth_delay(base_delay)
    
    def get_stealth_headers_for_thread(self, thread_id: int) -> dict:
        """
        Get stealth headers for specific thread
        
        Args:
            thread_id: Thread identifier
            
        Returns:
            Dictionary of stealth headers
        """
        stealth = self.get_thread_stealth(thread_id)
        return stealth.get_stealth_headers()
    
    def get_global_stats(self) -> dict:
        """
        Get global stealth statistics
        
        Returns:
            Dictionary with global stealth statistics
        """
        with self.lock:
            stats = {
                'total_threads': len(self.thread_stealth),
                'stealth_enabled': self.stealth_mode.enabled
            }
            
            # Aggregate thread stats
            for thread_id, stealth in self.thread_stealth.items():
                thread_stats = stealth.get_stealth_stats()
                stats[f'thread_{thread_id}'] = thread_stats
            
            return stats
