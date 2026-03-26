#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)

"""
Retry & Circuit Breaker — MikrotikAPI-BF
==========================================
Decorators and helpers for fault-tolerant network operations.
"""

import functools
import time
import threading
from typing import Callable, Optional, Tuple, Type


def retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
) -> Callable:
    """
    Retry decorator with exponential back-off.

    Args:
        max_attempts: Maximum number of attempts (including the first).
        delay:        Initial delay between retries in seconds.
        backoff:      Multiplier applied to *delay* on each retry.
        exceptions:   Exception types that trigger a retry.

    Returns:
        Decorator function.
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            current_delay = delay
            last_exc: Optional[Exception] = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if attempt < max_attempts:
                        time.sleep(current_delay)
                        current_delay *= backoff
            raise last_exc  # type: ignore[misc]

        return wrapper

    return decorator


class CircuitBreaker:
    """
    Simple circuit-breaker that opens after *threshold* consecutive failures
    and resets after *timeout* seconds.

    States:
        CLOSED  – requests pass through normally.
        OPEN    – requests are rejected immediately.
        HALF    – one probe is allowed to test recovery.

    Args:
        threshold: Number of consecutive failures before opening.
        timeout:   Seconds to wait in OPEN state before moving to HALF.
    """

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF = "HALF-OPEN"

    def __init__(self, threshold: int = 5, timeout: float = 30.0) -> None:
        self.threshold = threshold
        self.timeout = timeout
        self._failures = 0
        self._state = self.CLOSED
        self._opened_at: Optional[float] = None
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        with self._lock:
            if self._state == self.OPEN:
                if time.time() - (self._opened_at or 0) >= self.timeout:
                    self._state = self.HALF
            return self._state

    def record_success(self) -> None:
        """Reset failure counter and close the circuit."""
        with self._lock:
            self._failures = 0
            self._state = self.CLOSED
            self._opened_at = None

    def record_failure(self) -> None:
        """Record a failure; open the circuit if threshold is reached."""
        with self._lock:
            if self._state == self.HALF:
                self._state = self.OPEN
                self._opened_at = time.time()
                return
            self._failures += 1
            if self._failures >= self.threshold:
                self._state = self.OPEN
                self._opened_at = time.time()

    def allow_request(self) -> bool:
        """Return ``True`` if a request may proceed."""
        return self.state in (self.CLOSED, self.HALF)

    def __call__(self, func: Callable) -> Callable:
        """Use as a decorator."""

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not self.allow_request():
                raise RuntimeError("CircuitBreaker is OPEN — request rejected")
            try:
                result = func(*args, **kwargs)
                self.record_success()
                return result
            except Exception as exc:
                self.record_failure()
                raise exc

        return wrapper
