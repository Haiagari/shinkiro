"""
Safe Phase 4 Autonomy Planner.

This module turns the phase 4 roadmap into a bounded, non-exploitative
autonomy layer:
- prioritizes hosts with existing signal
- correlates local findings into review prompts
- emits lab-only decoy ideas as metadata
- keeps execution human-visible and non-destructive
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.core.logging import get_logger
from src.intelligence.scoring.priority import PriorityEngine
from src.intelligence.autonomy.recommendations import generate_arch_recommendations
from src.storage.queries import DBQueries
from src.storage.models import Scan, Subdomain, Port, Vulnerability
from src.intelligence.learning.learning_orchestrator import learning_orchestrator

logger = get_logger("autonomy_planner")


@dataclass
class AutonomyPlan:
    target: str
    session_id: str = ""
    phase: str = "phase4-safe"
    host_rankings: List[Dict[str, Any]] = field(default_factory=list)
    priority_targets: List[str] = field(default_factory=list)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    analysis_prompts: List[Dict[str, str]] = field(default_factory=list)
    lab_decoys: List[Dict[str, str]] = field(default_factory=list)
    work_units: List[Dict[str, str]] = field(default_factory=list)
    summary: str = ""
    feedback: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase,
            "target": self.target,
            "session_id": self.session_id,
            "host_rankings": self.host_rankings,
            "priority_targets": self.priority_targets,
            "recommendations": self.recommendations,
            "analysis_prompts": self.analysis_prompts,
            "lab_decoys": self.lab_decoys,
            "work_units": self.work_units,
            "summary": self.summary,
            "feedback": self.feedback,
        }


class AutonomyPlanner:
    """
    Produces a bounded autonomy plan from existing telemetry.
    """

    def __init__(self, db_session):
        self.db = DBQueries(db_session)
        self.priority_engine = PriorityEngine(db_session)

    def build_plan(self, target: str, limit: int = 5) -> AutonomyPlan:
        target_obj = self.db.get_target(target)
        if not target_obj:
            raise ValueError(f"Target not found: {target}")

        latest_scan = self._get_latest_scan(target)
        if latest_scan:
            session_id = latest_scan.session_id or ""
        else:
            session_id = ""

        hosts = self._collect_hosts(latest_scan, target_obj.domain)
        host_rankings = self.priority_engine.score_hosts(target, hosts)
        priority_targets = [str(h["host"]) for h in host_rankings[:limit]]

        context = self._build_context(latest_scan, target_obj.domain)
        recommendations = generate_arch_recommendations(target, context)

        analysis_prompts = self._build_analysis_prompts(target, host_rankings, recommendations)
        lab_decoys = self._build_lab_decoys(recommendations, context)
        work_units = self._build_work_units(priority_targets, recommendations)
        feedback = learning_orchestrator.get_full_feedback()

        summary = self._build_summary(priority_targets, recommendations, context)

        logger.info(
            f"Safe autonomy plan built for {target} with {len(priority_targets)} priority targets"
        )

        return AutonomyPlan(
            target=target,
            session_id=session_id,
            host_rankings=host_rankings,
            priority_targets=priority_targets,
            recommendations=recommendations,
            analysis_prompts=analysis_prompts,
            lab_decoys=lab_decoys,
            work_units=work_units,
            summary=summary,
            feedback=feedback,
        )

    def _get_latest_scan(self, target: str) -> Optional[Scan]:
        scans = self.db.get_scans_for_target(target, limit=1)
        return scans[0] if scans else None

    def _collect_hosts(self, scan: Optional[Scan], fallback_host: str) -> List[str]:
        if not scan:
            return [fallback_host]

        live_hosts = [s.domain for s in scan.subdomains if s.is_live]
        if live_hosts:
            return live_hosts

        subdomains = [s.domain for s in scan.subdomains]
        return subdomains or [fallback_host]

    def _build_context(self, scan: Optional[Scan], target: str) -> Dict[str, Any]:
        if not scan:
            return {
                "phases": {
                    "recon": {"all_subdomains": [], "live_hosts": []},
                    "ports": {"open_ports": []},
                    "vulns": {"findings": []},
                }
            }

        return {
            "phases": {
                "recon": {
                    "all_subdomains": [s.domain for s in scan.subdomains],
                    "live_hosts": [s.domain for s in scan.subdomains if s.is_live],
                },
                "ports": {
                    "open_ports": list(scan.ports),
                },
                "vulns": {
                    "findings": [
                        {
                            "name": v.name,
                            "type": v.type,
                            "severity": v.severity,
                            "host": v.host,
                            "url": getattr(v, "url", None) or v.path or "",
                            "path": v.path,
                        }
                        for v in scan.vulnerabilities
                    ]
                },
            }
        }

    def _build_analysis_prompts(
        self,
        target: str,
        host_rankings: List[Dict[str, Any]],
        recommendations: List[Dict[str, Any]],
    ) -> List[Dict[str, str]]:
        prompts: List[Dict[str, str]] = []
        for host in host_rankings[:3]:
            reasons = "; ".join(host.get("reasons", [])) or "No extra signals yet"
            prompts.append(
                {
                    "title": f"Review host {host['host']}",
                    "prompt": (
                        f"Summarize why {host['host']} is prioritized for {target}. "
                        f"Reasons: {reasons}. "
                        "Suggest safe follow-up validation or reporting steps only."
                    ),
                }
            )

        for rec in recommendations[:3]:
            prompts.append(
                {
                    "title": rec["title"],
                    "prompt": (
                        f"Review recommendation: {rec['description']} "
                        f"for target {target}. Keep the response strictly defensive and non-exploitative."
                    ),
                }
            )

        return prompts

    def _build_lab_decoys(
        self,
        recommendations: List[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> List[Dict[str, str]]:
        decoys: List[Dict[str, str]] = []
        open_ports = context.get("phases", {}).get("ports", {}).get("open_ports", [])

        if open_ports:
            decoys.append(
                {
                    "name": "lab_surface_snapshot",
                    "type": "lab-only",
                    "purpose": "Simulated monitoring target for training and reporting flows",
                }
            )

        if recommendations:
            decoys.append(
                {
                    "name": "review_queue_decoy",
                    "type": "lab-only",
                    "purpose": "Metadata placeholder for dashboards that need a decoy workflow node",
                }
            )

        return decoys

    def _build_work_units(
        self,
        priority_targets: List[str],
        recommendations: List[Dict[str, Any]],
    ) -> List[Dict[str, str]]:
        units = [
            {
                "step": "prioritize",
                "status": "ready",
                "description": "Review the ranked target list and confirm the next safe validation step.",
            },
            {
                "step": "summarize",
                "status": "ready",
                "description": "Generate a concise intelligence brief from the latest scan and diff context.",
            },
        ]

        if priority_targets:
            units.append(
                {
                    "step": "focus",
                    "status": "ready",
                    "description": f"Focus analysis on: {', '.join(map(str, priority_targets[:3]))}",
                }
            )

        if recommendations:
            units.append(
                {
                    "step": "review_recommendations",
                    "status": "ready",
                    "description": "Turn architecture recommendations into defensive action items.",
                }
            )

        return units

    def _build_summary(
        self,
        priority_targets: List[str],
        recommendations: List[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> str:
        subdomains = len(context.get("phases", {}).get("recon", {}).get("all_subdomains", []))
        open_ports = len(context.get("phases", {}).get("ports", {}).get("open_ports", []))
        rec_count = len(recommendations)
        return (
            f"Safe phase 4 autonomy prepared {len(priority_targets)} priority targets, "
            f"{subdomains} subdomains, {open_ports} open ports and {rec_count} defensive recommendations."
        )


def build_autonomy_plan(db_session, target: str, limit: int = 5) -> Dict[str, Any]:
    planner = AutonomyPlanner(db_session)
    return planner.build_plan(target, limit=limit).to_dict()
