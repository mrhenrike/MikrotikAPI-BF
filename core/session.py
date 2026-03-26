#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)

"""
Session Management — MikrotikAPI-BF
======================================
Persistent sessions similar to John The Ripper's --session mechanism.
Each session is stored as a JSON file under ``sessions/`` so that a
brute-force run can be interrupted and resumed without losing progress.
"""

import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class SessionManager:
    """Manage persistent brute-force sessions on disk."""

    def __init__(self, sessions_dir: str = "sessions") -> None:
        self.sessions_dir = Path(sessions_dir)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # ID / hash helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _wordlist_hash(wordlist: List[Tuple[str, str]]) -> str:
        raw = "|".join(f"{u}:{p}" for u, p in wordlist)
        return hashlib.md5(raw.encode()).hexdigest()[:8]

    @staticmethod
    def _session_id(target: str, services: List[str], wl_hash: str) -> str:
        payload = f"{target}:{':'.join(sorted(services))}:{wl_hash}"
        return hashlib.md5(payload.encode()).hexdigest()[:12]

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create_session(
        self,
        target: str,
        services: List[str],
        wordlist: List[Tuple[str, str]],
        config: Dict,
    ) -> str:
        """Create and persist a new session, returning its ID."""
        wl_hash = self._wordlist_hash(wordlist)
        sid = self._session_id(target, services, wl_hash)

        data: Dict = {
            "session_id": sid,
            "target": target,
            "services": services,
            "wordlist_hash": wl_hash,
            "wordlist": [list(c) for c in wordlist],
            "total_combinations": len(wordlist),
            "tested_combinations": 0,
            "successful_credentials": [],
            "failed_combinations": [],
            "current_progress": 0.0,
            "start_time": datetime.now().isoformat(),
            "last_update": datetime.now().isoformat(),
            "config": config,
            "status": "running",
            "estimated_completion": None,
            "average_time_per_attempt": None,
        }

        self._write(sid, data)
        return sid

    def load_session(self, session_id: str) -> Optional[Dict]:
        """Load a session by ID, returning ``None`` if not found."""
        path = self.sessions_dir / f"{session_id}.json"
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return None

    def find_existing_session(
        self,
        target: str,
        services: List[str],
        wordlist: List[Tuple[str, str]],
    ) -> Optional[Dict]:
        """Return the first matching session for target+services+wordlist."""
        wl_hash = self._wordlist_hash(wordlist)
        for path in self.sessions_dir.glob("*.json"):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if (
                    data.get("target") == target
                    and set(data.get("services", [])) == set(services)
                    and data.get("wordlist_hash") == wl_hash
                ):
                    return data
            except Exception:
                continue
        return None

    def update_session(
        self,
        session_id: str,
        tested_count: int,
        successful_creds: List[Dict],
        failed_combos: List[Tuple[str, str]],
        current_combo: Optional[Tuple[str, str]] = None,
    ) -> None:
        """Update progress counters and ETA for a running session."""
        path = self.sessions_dir / f"{session_id}.json"
        if not path.exists():
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            data["tested_combinations"] = tested_count
            data["successful_credentials"] = successful_creds
            data["failed_combinations"] = [[u, p] for u, p in failed_combos]
            total = data.get("total_combinations", 1) or 1
            data["current_progress"] = (tested_count / total) * 100
            data["last_update"] = datetime.now().isoformat()

            if tested_count > 0:
                start = datetime.fromisoformat(data["start_time"])
                elapsed = (datetime.now() - start).total_seconds()
                avg = elapsed / tested_count
                data["average_time_per_attempt"] = avg
                remaining = (total - tested_count) * avg
                data["estimated_completion"] = (
                    datetime.now() + timedelta(seconds=remaining)
                ).isoformat()

            if current_combo:
                data["current_combination"] = f"{current_combo[0]}:{current_combo[1]}"

            self._write(session_id, data)
        except Exception:
            pass

    def complete_session(
        self, session_id: str, successful_creds: List[Dict], final_status: str = "completed"
    ) -> None:
        """Mark a session as finished."""
        path = self.sessions_dir / f"{session_id}.json"
        if not path.exists():
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            data["status"] = final_status
            data["successful_credentials"] = successful_creds
            data["end_time"] = datetime.now().isoformat()
            data["last_update"] = datetime.now().isoformat()
            self._write(session_id, data)
        except Exception:
            pass

    def list_sessions(self) -> List[Dict]:
        """Return all sessions sorted by most recently updated."""
        sessions: List[Dict] = []
        for path in self.sessions_dir.glob("*.json"):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    sessions.append(json.load(fh))
            except Exception:
                continue
        return sorted(
            sessions,
            key=lambda x: x.get("last_update", x.get("start_time", "")),
            reverse=True,
        )

    def get_session_stats(self, session_id: str) -> Optional[Dict]:
        """Return a summary dict for a session."""
        data = self.load_session(session_id)
        if not data:
            return None
        return {
            "session_id": session_id,
            "target": data.get("target"),
            "status": data.get("status"),
            "progress": data.get("current_progress", 0.0),
            "tested": data.get("tested_combinations", 0),
            "total": data.get("total_combinations", 0),
            "successful": len(data.get("successful_credentials", [])),
            "average_time": data.get("average_time_per_attempt"),
            "estimated_completion": data.get("estimated_completion"),
            "start_time": data.get("start_time"),
            "last_update": data.get("last_update"),
        }

    def should_resume(self, session_data: Dict) -> bool:
        """Return ``True`` if the session can be meaningfully resumed."""
        if session_data.get("status") == "completed":
            return False
        if session_data.get("current_progress", 0) >= 100:
            return False
        last_raw = session_data.get("last_update") or session_data.get("start_time", "")
        try:
            last = datetime.fromisoformat(last_raw)
            return (datetime.now() - last).total_seconds() < 86400  # 24 h
        except Exception:
            return True

    def format_eta(self, session_data: Dict) -> str:
        """Return a human-readable ETA string."""
        raw = session_data.get("estimated_completion")
        if not raw:
            return "Calculating..."
        try:
            eta = datetime.fromisoformat(raw)
            remaining = eta - datetime.now()
            if remaining.total_seconds() < 0:
                return "Overdue"
            h, rem = divmod(int(remaining.total_seconds()), 3600)
            m, s = divmod(rem, 60)
            if h:
                return f"{h}h {m}m {s}s"
            if m:
                return f"{m}m {s}s"
            return f"{s}s"
        except Exception:
            return "Unknown"

    def cleanup_old_sessions(self, days: int = 7) -> int:
        """Remove sessions older than *days* days.  Returns count removed."""
        cutoff = datetime.now() - timedelta(days=days)
        removed = 0
        for path in self.sessions_dir.glob("*.json"):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                raw = data.get("last_update") or data.get("start_time", "")
                last = datetime.fromisoformat(raw)
                if last < cutoff:
                    path.unlink()
                    removed += 1
            except Exception:
                continue
        return removed

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _write(self, session_id: str, data: Dict) -> None:
        path = self.sessions_dir / f"{session_id}.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
