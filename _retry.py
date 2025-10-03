#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Retry and Circuit Breaker Module - MikrotikAPI-BF v2.0

This module implements resilience patterns:
- RetryStrategy: Retry with exponential backoff for network failures
- CircuitBreaker: Prevent cascading failures with circuit breaker pattern

Author: André Henrique (@mrhenrike)
"""

import time
import functools
from typing import Callable, Any, Type, Tuple

class RetryStrategy:
    """
    Implements retry logic with exponential backoff
    """
    
    def __init__(
        self,
        max_attempts=3,
        initial_delay=1,
        max_delay=60,
        exponential_base=2,
        exceptions=(Exception,)
    ):
        """
        Initialize retry strategy
        
        Args:
            max_attempts: Maximum number of retry attempts
            initial_delay: Initial delay in seconds
            max_delay: Maximum delay in seconds
            exponential_base: Base for exponential backoff
            exceptions: Tuple of exceptions to catch
        """
        self.max_attempts = max_attempts
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.exceptions = exceptions
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator to add retry logic to a function"""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return self.execute(func, *args, **kwargs)
        return wrapper
    
    def execute(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with retry logic
        
        Returns:
            Result of the function
            
        Raises:
            Last exception if all retries fail
        """
        attempt = 0
        last_exception = None
        
        while attempt < self.max_attempts:
            try:
                return func(*args, **kwargs)
            except self.exceptions as e:
                attempt += 1
                last_exception = e
                
                if attempt >= self.max_attempts:
                    raise last_exception
                
                # Calculate delay with exponential backoff
                delay = min(
                    self.initial_delay * (self.exponential_base ** (attempt - 1)),
                    self.max_delay
                )
                
                time.sleep(delay)
        
        # Should never reach here, but just in case
        if last_exception:
            raise last_exception


class CircuitBreaker:
    """
    Implements circuit breaker pattern to prevent cascading failures
    """
    
    STATE_CLOSED = "closed"  # Normal operation
    STATE_OPEN = "open"      # Too many failures, stop trying
    STATE_HALF_OPEN = "half_open"  # Testing if service recovered
    
    def __init__(
        self,
        failure_threshold=5,
        success_threshold=2,
        timeout=60
    ):
        """
        Initialize circuit breaker
        
        Args:
            failure_threshold: Number of failures before opening circuit
            success_threshold: Number of successes needed to close circuit
            timeout: Seconds to wait before trying again (half-open)
        """
        self.failure_threshold = failure_threshold
        self.success_threshold = success_threshold
        self.timeout = timeout
        
        self.failure_count = 0
        self.success_count = 0
        self.state = self.STATE_CLOSED
        self.opened_at = None
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator to add circuit breaker to a function"""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return self.execute(func, *args, **kwargs)
        return wrapper
    
    def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker logic"""
        
        # Check if circuit is open
        if self.state == self.STATE_OPEN:
            if self._should_try_again():
                self.state = self.STATE_HALF_OPEN
            else:
                raise Exception("Circuit breaker is OPEN")
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
            
        except Exception as e:
            self._on_failure()
            raise e
    
    def _should_try_again(self) -> bool:
        """Check if enough time has passed to try again"""
        if self.opened_at is None:
            return True
        
        elapsed = time.time() - self.opened_at
        return elapsed >= self.timeout
    
    def _on_success(self):
        """Handle successful execution"""
        self.failure_count = 0
        
        if self.state == self.STATE_HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.success_threshold:
                self.state = self.STATE_CLOSED
                self.success_count = 0
    
    def _on_failure(self):
        """Handle failed execution"""
        self.failure_count += 1
        self.success_count = 0
        
        if self.failure_count >= self.failure_threshold:
            self.state = self.STATE_OPEN
            self.opened_at = time.time()
    
    def reset(self):
        """Reset circuit breaker to initial state"""
        self.state = self.STATE_CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.opened_at = None


# Convenience decorators
def retry(
    max_attempts=3,
    initial_delay=1,
    max_delay=60,
    exponential_base=2,
    exceptions=(Exception,)
):
    """
    Decorator for retry with exponential backoff
    
    Usage:
        @retry(max_attempts=5, initial_delay=2)
        def my_function():
            # code that might fail
            pass
    """
    strategy = RetryStrategy(
        max_attempts=max_attempts,
        initial_delay=initial_delay,
        max_delay=max_delay,
        exponential_base=exponential_base,
        exceptions=exceptions
    )
    return strategy


def circuit_breaker(failure_threshold=5, success_threshold=2, timeout=60):
    """
    Decorator for circuit breaker pattern
    
    Usage:
        @circuit_breaker(failure_threshold=10, timeout=120)
        def my_function():
            # code that might fail
            pass
    """
    breaker = CircuitBreaker(
        failure_threshold=failure_threshold,
        success_threshold=success_threshold,
        timeout=timeout
    )
    return breaker

