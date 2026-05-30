"""
OzyRecon Learning Engine (v8.3.2 - Idea 6)
Persists long-term insights and detects surface drift.
"""

import logging
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from typing import List, Dict, Any, Optional
from src.storage.queries import DBQueries
from src.storage.models import Scan, Subdomain, Port, Vulnerability, AgentMemory, AgentLock
from src.agent.config_writer import save_scoring_weights

MIN_OBSERVATIONS = 5

logger = logging.getLogger("intelligence.learning")

class LearningEngine:
    def __init__(self, db_session):
        self.db = DBQueries(db_session)
        self.db_session = db_session

    def acquire_lock(self, mode: str, timeout_mins: int = 60) -> bool:
        now = datetime.now(timezone.utc)
        lock = self.db_session.query(AgentLock).filter(AgentLock.mode == mode).first()
        if lock and lock.expires_at:
            expires_at = lock.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at > now:
                return False

        if lock:
            self.db_session.delete(lock)

        self.db_session.add(AgentLock(mode=mode, locked_at=now, expires_at=now + timedelta(minutes=timeout_mins)))
        self.db_session.commit()
        return True

    def release_lock(self, mode: str):
        lock = self.db_session.query(AgentLock).filter(AgentLock.mode == mode).first()
        if lock:
            self.db_session.delete(lock)
            self.db_session.commit()

    def analyze_and_update(self) -> Dict[str, Any]:
        if not self.acquire_lock("aprendizaje", timeout_mins=60):
            return {}

        try:
            memories = self.db_session.query(AgentMemory).filter(AgentMemory.key == "tech_stack").all()
            if len(memories) < MIN_OBSERVATIONS:
                return {}

            grouped: Dict[str, int] = defaultdict(int)
            for mem in memories:
                value = mem.value or []
                if isinstance(value, list):
                    for tech in value:
                        grouped[str(tech)] += 1

            results: Dict[str, Dict[str, float]] = {}
            for tech, count in grouped.items():
                if count < MIN_OBSERVATIONS:
                    continue
                tech_key = tech.strip()
                results[tech_key] = {
                    "nuclei": 0.9,
                    "dalfox": 0.8 if tech_key.lower() in {"wordpress", "wp", "wordpress core"} else 0.4,
                }

            if results:
                confidence = min(1.0, len(memories) / 10.0)
                save_scoring_weights(results, confidence=confidence)

            return results
        finally:
            self.release_lock("aprendizaje")

    def process_scan_completion(self, target: str, scan_id: int):
        """
        Analyzes a finished scan and updates long-term memory.
        """
        scan = self.db_session.get(Scan, scan_id)
        if not scan: return

        logger.info(f"🧠 Learning Engine processing scan {scan_id} for {target}")

        # 1. Update Host Reputation (Frequency of findings)
        vulns = self.db_session.query(Vulnerability).filter_by(scan_id=scan_id).all()
        vuln_list = [{"host": v.host, "severity": v.severity} for v in vulns]
        
        from src.intelligence.priority import PriorityEngine
        pe = PriorityEngine(self.db_session)
        pe.update_reputation(target, vuln_list)

        # 2. Track Technology Drift
        self._learn_tech_stack(target, scan_id)

        # 3. Identify "Gold Assets" (Static, high-value assets)
        self._identify_gold_assets(target, scan_id)

    def _learn_tech_stack(self, target: str, scan_id: int):
        """Remembers what technologies were seen on which hosts."""
        assets = self.db_session.query(Subdomain).filter_by(scan_id=scan_id).all()
        
        memory_key = "known_tech_stack"
        existing_mem = self.db.get_agent_memory(target, memory_key)
        stack = existing_mem.value if existing_mem else {}

        changes = []
        for asset in assets:
            host = asset.domain
            new_tech = asset.technologies or []
            
            if host in stack:
                old_tech = stack[host]
                if set(new_tech) != set(old_tech):
                    changes.append(f"Tech shift on {host}: {old_tech} -> {new_tech}")
            
            stack[host] = new_tech

        self.db.set_agent_memory(target, memory_key, stack)
        if changes:
            logger.info(f"Detected {len(changes)} tech stack shifts.")
            self.db.set_agent_memory(target, "last_drift_report", {"timestamp": datetime.now().isoformat(), "changes": changes})

    def _identify_gold_assets(self, target: str, scan_id: int):
        """Identifies assets that are always live and have high impact."""
        # Simple heuristic: live assets with 'gate_admin' or 'api_surface'
        assets = self.db_session.query(Subdomain).filter_by(scan_id=scan_id, is_live=1).all()
        
        gold_assets = []
        for asset in assets:
            labels = asset.semantic_labels or []
            if any(l in ["gate_admin", "api_surface", "leaked_data_surface"] for l in labels):
                gold_assets.append(asset.domain)

        if gold_assets:
            self.db.set_agent_memory(target, "gold_assets", list(set(gold_assets)))

# Global Instance helper
def run_learning(db_session, target: str, scan_id: int):
    le = LearningEngine(db_session)
    le.process_scan_completion(target, scan_id)
