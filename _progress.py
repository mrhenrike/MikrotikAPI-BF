#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Progress Tracking Module - MikrotikAPI-BF v2.0

This module provides visual progress tracking for brute-force operations:
- ProgressBar: Full-featured progress bar with ETA, speed, and success counter
- SpinnerProgress: Simple spinner for indeterminate operations

Author: André Henrique (@mrhenrike)
"""

import sys
import threading
import time
from datetime import datetime, timedelta

class ProgressBar:
    """
    Thread-safe progress bar for tracking brute force progress
    """
    
    def __init__(self, total, width=50, show_eta=True, show_speed=True):
        self.total = total
        self.current = 0
        self.width = width
        self.show_eta = show_eta
        self.show_speed = show_speed
        self.start_time = datetime.now()
        self.lock = threading.Lock()
        self.success_count = 0
        self.running = True
        
    def update(self, n=1, success=False):
        """Update progress bar by n steps"""
        with self.lock:
            self.current += n
            if success:
                self.success_count += 1
            self._render()
    
    def _render(self):
        """Render the progress bar"""
        if not self.running:
            return
        
        # Calculate progress
        if self.total > 0:
            progress = self.current / self.total
        else:
            progress = 0
        
        # Calculate bar
        filled = int(self.width * progress)
        bar = '#' * filled + '.' * (self.width - filled)
        
        # Calculate percentage
        percent = progress * 100
        
        # Build progress string
        progress_str = f"\r[{bar}] {percent:>5.1f}% ({self.current}/{self.total})"
        
        # Add success count
        if self.success_count > 0:
            progress_str += f" | OK {self.success_count}"
        
        # Calculate and show speed
        if self.show_speed and self.current > 0:
            elapsed = (datetime.now() - self.start_time).total_seconds()
            if elapsed > 0:
                speed = self.current / elapsed
                progress_str += f" | {speed:.1f} attempts/s"
        
        # Calculate and show ETA
        if self.show_eta and self.current > 0 and self.current < self.total:
            elapsed = (datetime.now() - self.start_time).total_seconds()
            if elapsed > 0:
                rate = self.current / elapsed
                remaining = (self.total - self.current) / rate
                eta = timedelta(seconds=int(remaining))
                progress_str += f" | ETA: {eta}"
        
        # Write to stdout
        sys.stdout.write(progress_str)
        sys.stdout.flush()
        
        # Newline if complete
        if self.current >= self.total:
            sys.stdout.write("\n")
            sys.stdout.flush()
    
    def finish(self):
        """Mark progress as complete"""
        with self.lock:
            self.current = self.total
            self.running = False
            self._render()
    
    def reset(self):
        """Reset progress bar"""
        with self.lock:
            self.current = 0
            self.success_count = 0
            self.start_time = datetime.now()
            self.running = True


class SpinnerProgress:
    """
    Simple spinner for indeterminate progress
    """
    
    def __init__(self, message="Processing"):
        self.message = message
        self.running = False
        self.thread = None
        self.frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.current_frame = 0
    
    def start(self):
        """Start the spinner"""
        self.running = True
        self.thread = threading.Thread(target=self._spin, daemon=True)
        self.thread.start()
    
    def stop(self, final_message=None):
        """Stop the spinner"""
        self.running = False
        if self.thread:
            self.thread.join()
        sys.stdout.write('\r' + ' ' * (len(self.message) + 10) + '\r')
        if final_message:
            print(final_message)
        sys.stdout.flush()
    
    def _spin(self):
        """Spinner animation loop"""
        while self.running:
            frame = self.frames[self.current_frame % len(self.frames)]
            sys.stdout.write(f'\r{frame} {self.message}...')
            sys.stdout.flush()
            self.current_frame += 1
            time.sleep(0.1)

