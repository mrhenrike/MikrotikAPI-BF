#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)

"""
Stealth Mode Module — MikrotikAPI-BF
=======================================
Implements evasion capabilities to reduce detection probability:
- Fibonacci-based delays with jitter (avoids IDS pattern recognition)
- User-Agent rotation for HTTP requests
- Thread-local stealth state
"""

import random
import threading
import time
from typing import Dict, List, Optional


class StealthMode:
    """
    Per-thread stealth context.

    Args:
        enabled: When ``False`` the stealth logic is bypassed and plain
                 ``time.sleep(base_delay)`` is used instead.
    """

    _USER_AGENTS: List[str] = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0 Safari/537.36",
    ]

    # Fibonacci numbers used as delay multipliers (in seconds)
    _FIBONACCI: List[int] = [1, 1, 2, 3, 5, 8, 13, 21, 34, 55]

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._ua_index = 0
        self._delay_history: List[float] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Delay
    # ------------------------------------------------------------------

    def get_delay(self, base: float = 5.0) -> float:
        """Return a randomised delay combining base + Fibonacci jitter."""
        if not self.enabled:
            return base
        with self._lock:
            fib = random.choice(self._FIBONACCI)
            jitter = random.uniform(0.5, 1.5)
            delay = (base + fib) * jitter
            self._delay_history.append(delay)
            if len(self._delay_history) > 10:
                self._delay_history.pop(0)
            return delay

    def sleep(self, base: float = 5.0) -> None:
        """Block for a stealth-aware duration."""
        time.sleep(self.get_delay(base))

    # ------------------------------------------------------------------
    # HTTP headers
    # ------------------------------------------------------------------

    def get_user_agent(self) -> str:
        """Return the next User-Agent in rotation."""
        with self._lock:
            ua = self._USER_AGENTS[self._ua_index]
            self._ua_index = (self._ua_index + 1) % len(self._USER_AGENTS)
            return ua

    def get_headers(self) -> Dict[str, str]:
        """Return a realistic-looking set of HTTP headers."""
        headers = {
            "User-Agent": self.get_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        if random.random() < 0.3:
            headers["Cache-Control"] = "no-cache"
        return headers

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> Dict:
        with self._lock:
            avg = sum(self._delay_history) / len(self._delay_history) if self._delay_history else 0.0
            return {
                "enabled": self.enabled,
                "ua_rotations": self._ua_index,
                "avg_delay": avg,
                "last_delays": list(self._delay_history[-5:]),
            }


class StealthManager:
    """
    Manages per-thread StealthMode instances across a thread pool.

    Args:
        enabled: Passed through to each StealthMode instance.
    """

    def __init__(self, enabled: bool = True) -> None:
        self._enabled = enabled
        self._threads: Dict[int, StealthMode] = {}
        self._lock = threading.Lock()
        # Shared instance for non-threaded use
        self.stealth_mode = StealthMode(enabled)

    def _get(self, thread_id: int) -> StealthMode:
        with self._lock:
            if thread_id not in self._threads:
                self._threads[thread_id] = StealthMode(self._enabled)
            return self._threads[thread_id]

    def apply_stealth_for_thread(self, thread_id: int, base_delay: float = 5.0) -> None:
        """Apply stealth delay for *thread_id*."""
        self._get(thread_id).sleep(base_delay)

    def get_stealth_headers_for_thread(self, thread_id: int) -> Dict[str, str]:
        """Return HTTP headers for *thread_id*."""
        return self._get(thread_id).get_headers()

    def get_global_stats(self) -> Dict:
        """Aggregate stealth statistics across all threads."""
        with self._lock:
            return {
                "total_threads": len(self._threads),
                "stealth_enabled": self._enabled,
                "threads": {tid: sm.stats() for tid, sm in self._threads.items()},
            }
