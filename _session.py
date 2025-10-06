#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import hashlib
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from _log import Log

class SessionManager:
    """
    Manages persistent sessions for MikrotikAPI-BF v2.1.
    Similar to John The Ripper's session management.
    """
    
    def __init__(self, sessions_dir: str = "sessions"):
        self.sessions_dir = Path(sessions_dir)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.log = Log(verbose=True, verbose_all=False)
        
    def _generate_session_id(self, target: str, services: List[str], wordlist_hash: str) -> str:
        """Generate a unique session ID based on target, services, and wordlist."""
        session_data = f"{target}:{':'.join(sorted(services))}:{wordlist_hash}"
        return hashlib.md5(session_data.encode()).hexdigest()[:12]
    
    def _get_wordlist_hash(self, wordlist: List[Tuple[str, str]]) -> str:
        """Generate hash of wordlist for session identification."""
        wordlist_str = "|".join([f"{u}:{p}" for u, p in wordlist])
        return hashlib.md5(wordlist_str.encode()).hexdigest()[:8]
    
    def create_session(self, target: str, services: List[str], wordlist: List[Tuple[str, str]], 
                      config: Dict) -> str:
        """Create a new session."""
        wordlist_hash = self._get_wordlist_hash(wordlist)
        session_id = self._generate_session_id(target, services, wordlist_hash)
        
        session_data = {
            'session_id': session_id,
            'target': target,
            'services': services,
            'wordlist_hash': wordlist_hash,
            'total_combinations': len(wordlist),
            'tested_combinations': 0,
            'successful_credentials': [],
            'failed_combinations': [],
            'current_progress': 0.0,
            'start_time': datetime.now().isoformat(),
            'last_update': datetime.now().isoformat(),
            'config': config,
            'status': 'running',
            'estimated_completion': None,
            'average_time_per_attempt': None
        }
        
        session_file = self.sessions_dir / f"{session_id}.json"
        with open(session_file, 'w', encoding='utf-8') as f:
            json.dump(session_data, f, indent=2, ensure_ascii=False)
        
        self.log.info(f"[SESSION] Created session: {session_id}")
        return session_id
    
    def load_session(self, session_id: str) -> Optional[Dict]:
        """Load an existing session."""
        session_file = self.sessions_dir / f"{session_id}.json"
        if not session_file.exists():
            return None
        
        try:
            with open(session_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self.log.error(f"[SESSION] Failed to load session {session_id}: {e}")
            return None
    
    def find_existing_session(self, target: str, services: List[str], 
                            wordlist: List[Tuple[str, str]]) -> Optional[Dict]:
        """Find existing session for the same target, services, and wordlist."""
        wordlist_hash = self._get_wordlist_hash(wordlist)
        
        for session_file in self.sessions_dir.glob("*.json"):
            try:
                with open(session_file, 'r', encoding='utf-8') as f:
                    session_data = json.load(f)
                
                if (session_data.get('target') == target and 
                    set(session_data.get('services', [])) == set(services) and
                    session_data.get('wordlist_hash') == wordlist_hash):
                    return session_data
            except Exception:
                continue
        
        return None
    
    def update_session(self, session_id: str, tested_count: int, successful_creds: List[Dict],
                      failed_combinations: List[Tuple[str, str]], current_combination: Tuple[str, str] = None):
        """Update session progress."""
        session_file = self.sessions_dir / f"{session_id}.json"
        if not session_file.exists():
            return
        
        try:
            with open(session_file, 'r', encoding='utf-8') as f:
                session_data = json.load(f)
            
            # Update progress
            session_data['tested_combinations'] = tested_count
            session_data['successful_credentials'] = successful_creds
            session_data['failed_combinations'] = failed_combinations
            session_data['current_progress'] = (tested_count / session_data['total_combinations']) * 100
            session_data['last_update'] = datetime.now().isoformat()
            
            # Calculate average time per attempt
            if tested_count > 0:
                start_time = datetime.fromisoformat(session_data['start_time'])
                elapsed_time = (datetime.now() - start_time).total_seconds()
                session_data['average_time_per_attempt'] = elapsed_time / tested_count
                
                # Estimate completion time
                remaining_attempts = session_data['total_combinations'] - tested_count
                if session_data['average_time_per_attempt']:
                    estimated_remaining = remaining_attempts * session_data['average_time_per_attempt']
                    session_data['estimated_completion'] = (datetime.now() + timedelta(seconds=estimated_remaining)).isoformat()
            
            # Update current combination being tested
            if current_combination:
                session_data['current_combination'] = f"{current_combination[0]}:{current_combination[1]}"
            
            with open(session_file, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            self.log.error(f"[SESSION] Failed to update session {session_id}: {e}")
    
    def complete_session(self, session_id: str, successful_creds: List[Dict], final_status: str = "completed"):
        """Mark session as completed."""
        session_file = self.sessions_dir / f"{session_id}.json"
        if not session_file.exists():
            return
        
        try:
            with open(session_file, 'r', encoding='utf-8') as f:
                session_data = json.load(f)
            
            session_data['status'] = final_status
            session_data['successful_credentials'] = successful_creds
            session_data['end_time'] = datetime.now().isoformat()
            session_data['last_update'] = datetime.now().isoformat()
            
            with open(session_file, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, indent=2, ensure_ascii=False)
                
            self.log.info(f"[SESSION] Completed session: {session_id}")
                
        except Exception as e:
            self.log.error(f"[SESSION] Failed to complete session {session_id}: {e}")
    
    def get_session_stats(self, session_id: str) -> Optional[Dict]:
        """Get session statistics."""
        session_data = self.load_session(session_id)
        if not session_data:
            return None
        
        stats = {
            'session_id': session_id,
            'target': session_data.get('target'),
            'status': session_data.get('status'),
            'progress': session_data.get('current_progress', 0.0),
            'tested': session_data.get('tested_combinations', 0),
            'total': session_data.get('total_combinations', 0),
            'successful': len(session_data.get('successful_credentials', [])),
            'average_time': session_data.get('average_time_per_attempt'),
            'estimated_completion': session_data.get('estimated_completion'),
            'start_time': session_data.get('start_time'),
            'last_update': session_data.get('last_update')
        }
        
        return stats
    
    def format_time_estimate(self, session_data: Dict) -> str:
        """Format time estimate for display."""
        if not session_data.get('estimated_completion'):
            return "Calculating..."
        
        try:
            estimated_time = datetime.fromisoformat(session_data['estimated_completion'])
            remaining = estimated_time - datetime.now()
            
            if remaining.total_seconds() < 0:
                return "Overdue"
            
            hours, remainder = divmod(int(remaining.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            
            if hours > 0:
                return f"{hours}h {minutes}m {seconds}s"
            elif minutes > 0:
                return f"{minutes}m {seconds}s"
            else:
                return f"{seconds}s"
        except Exception:
            return "Unknown"
    
    def should_resume(self, session_data: Dict) -> bool:
        """Determine if session should be resumed."""
        if session_data.get('status') == 'completed':
            return False
        
        # Resume if less than 100% complete and not too old (24 hours)
        if session_data.get('current_progress', 0) < 100:
            last_update = datetime.fromisoformat(session_data.get('last_update', session_data.get('start_time')))
            if (datetime.now() - last_update).total_seconds() < 86400:  # 24 hours
                return True
        
        return False
    
    def cleanup_old_sessions(self, days: int = 7):
        """Clean up sessions older than specified days."""
        cutoff_time = datetime.now() - timedelta(days=days)
        cleaned = 0
        
        for session_file in self.sessions_dir.glob("*.json"):
            try:
                with open(session_file, 'r', encoding='utf-8') as f:
                    session_data = json.load(f)
                
                last_update = datetime.fromisoformat(session_data.get('last_update', session_data.get('start_time')))
                if last_update < cutoff_time:
                    session_file.unlink()
                    cleaned += 1
            except Exception:
                continue
        
        if cleaned > 0:
            self.log.info(f"[SESSION] Cleaned up {cleaned} old sessions")
    
    def list_sessions(self) -> List[Dict]:
        """List all available sessions."""
        sessions = []
        
        for session_file in self.sessions_dir.glob("*.json"):
            try:
                with open(session_file, 'r', encoding='utf-8') as f:
                    session_data = json.load(f)
                sessions.append(session_data)
            except Exception:
                continue
        
        return sorted(sessions, key=lambda x: x.get('last_update', x.get('start_time', '')), reverse=True)
