#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)

"""
Progress Tracking Module — MikrotikAPI-BF
==========================================
Thread-safe progress bar and spinner for long-running brute-force operations.
"""

import sys
import threading
import time
from datetime import datetime, timedelta


class ProgressBar:
    """
    Thread-safe console progress bar with ETA, speed, and success counter.

    Args:
        total:      Total number of attempts.
        width:      Width of the bar in characters.
        show_eta:   Whether to show estimated time remaining.
        show_speed: Whether to show attempts-per-second.
    """

    def __init__(
        self,
        total: int,
        width: int = 50,
        show_eta: bool = True,
        show_speed: bool = True,
    ) -> None:
        self.total = total
        self.width = width
        self.show_eta = show_eta
        self.show_speed = show_speed
        self.current = 0
        self.success_count = 0
        self.start_time = datetime.now()
        self._lock = threading.Lock()
        self._finished = False

    def update(self, n: int = 1, success: bool = False) -> None:
        """Advance the counter by *n* and optionally record a success."""
        with self._lock:
            self.current = min(self.current + n, self.total)
            if success:
                self.success_count += 1
            self._render()

    def finish(self) -> None:
        """Force the bar to 100 % and print a newline."""
        with self._lock:
            self._finished = True
            self.current = self.total
            self._render()
            sys.stdout.write("\n")
            sys.stdout.flush()

    def interrupt(self) -> None:
        """Leave partial progress and newline (Ctrl+C)."""
        with self._lock:
            sys.stdout.write("\n")
            sys.stdout.flush()

    def reset(self) -> None:
        """Reset all counters."""
        with self._lock:
            self.current = 0
            self.success_count = 0
            self.start_time = datetime.now()
            self._finished = False

    # ------------------------------------------------------------------
    # Internal rendering
    # ------------------------------------------------------------------

    def _render(self) -> None:
        if self._finished and self.current < self.total:
            return

        pct = (self.current / self.total * 100) if self.total else 0
        filled = int(self.width * self.current / self.total) if self.total else 0
        try:
            from core.console import ok, dim, _HAS_COLOR

            if _HAS_COLOR:
                bar_fill = ok("█" * filled)
                bar_empty = dim("░" * (self.width - filled))
                bar = f"{bar_fill}{bar_empty}"
            else:
                bar = "█" * filled + "░" * (self.width - filled)
        except ImportError:
            bar = "█" * filled + "░" * (self.width - filled)

        parts = [f"\r[{bar}] {pct:>5.1f}% ({self.current}/{self.total})"]

        if self.success_count:
            try:
                from core.console import ok
                parts.append(ok(f"✓ {self.success_count}"))
            except ImportError:
                parts.append(f"✓ {self.success_count}")

        elapsed = (datetime.now() - self.start_time).total_seconds()
        if self.show_speed and self.current > 0 and elapsed > 0:
            speed = self.current / elapsed
            parts.append(f"{speed:.1f} att/s")

        if self.show_eta and 0 < self.current < self.total and elapsed > 0:
            rate = self.current / elapsed
            remaining = (self.total - self.current) / rate
            parts.append(f"ETA {timedelta(seconds=int(remaining))}")

        sys.stdout.write(" │ ".join(parts))
        sys.stdout.flush()

        if self.current >= self.total and not self._finished:
            sys.stdout.write("\n")
            sys.stdout.flush()


class QuietActivity:
    """Single-line status when verbose is off and progress bar is disabled."""

    def __init__(self, total: int, threads: int = 1) -> None:
        self.total = max(total, 1)
        self.threads = threads
        self.current = 0
        self._start = time.time()
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def update(self, n: int = 1) -> None:
        with self._lock:
            self.current = min(self.current + n, self.total)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.5)
        sys.stdout.write("\r" + " " * 90 + "\r")
        sys.stdout.flush()

    def _loop(self) -> None:
        tick = 0
        while self._running:
            with self._lock:
                cur = self.current
            elapsed = int(time.time() - self._start)
            tick = (tick + 1) % 4
            dots = "." * tick
            speed = cur / elapsed if elapsed > 0 and cur else 0.0
            try:
                from core.console import info, dim

                msg = (
                    f"\r{info('[*]')} Testing {cur}/{self.total} "
                    f"| {self.threads} thr | {elapsed}s "
                    f"| {speed:.1f} att/s{dim(dots):<4}"
                )
            except ImportError:
                msg = (
                    f"\r[*] Testing {cur}/{self.total} "
                    f"| {self.threads} thr | {elapsed}s "
                    f"| {speed:.1f} att/s{dots:<4}"
                )
            sys.stdout.write(msg)
            sys.stdout.flush()
            time.sleep(0.35)


class SpinnerProgress:
    """
    Indeterminate spinner for operations with an unknown total.

    Args:
        message: Label displayed next to the spinner.
    """

    _FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, message: str = "Processing") -> None:
        self.message = message
        self._running = False
        self._thread: threading.Thread = None  # type: ignore[assignment]
        self._frame_idx = 0

    def start(self) -> None:
        """Start the spinner in a daemon thread."""
        self._running = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self, final_message: str = "") -> None:
        """Stop the spinner and optionally print *final_message*."""
        self._running = False
        if self._thread:
            self._thread.join()
        sys.stdout.write("\r" + " " * (len(self.message) + 10) + "\r")
        if final_message:
            print(final_message)
        sys.stdout.flush()

    def _spin(self) -> None:
        while self._running:
            frame = self._FRAMES[self._frame_idx % len(self._FRAMES)]
            sys.stdout.write(f"\r{frame} {self.message}…")
            sys.stdout.flush()
            self._frame_idx += 1
            time.sleep(0.1)
