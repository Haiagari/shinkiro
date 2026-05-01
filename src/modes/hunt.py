"""
Modo HUNT - Caza Inteligente v5.0
Establece línea base y genera hipótesis para validación asistida.
"""

from typing import List, Dict, Any
from pathlib import Path
from src.modes.base import BaseMode
from src.core.tool_manager import tool_manager
from src.core.logging import get_logger
from src.intelligence.intelligence import run_intelligence
from src.intelligence.planner import recon_planner
from src.opsec.kill_switch import kill_switch

logger = get_logger('mode.hunt')

class HuntMode(BaseMode):
    def __init__(self, target: str, options: Dict[str, Any] = None):
        super().__init__(target, "hunt", options)

    def validate_preconditions(self):
        if not self.target:
            raise ValueError("Target domain is required for HUNT mode")

    def execute(self) -> Dict[str, Any]:
        logger.info(f"[HUNT v7.0] Starting intelligent adaptive hunt on {self.target}")
        
        # 0. Adaptive Planning (v7 - Phase 8)
        plan = recon_planner.generate_plan(self.target, intent=self.options.get("intent", "balanced"))
        logger.info(f"[HUNT] Plan generated: {plan['type']} target, capabilities: {plan['capabilities']}")

        # 1. Reset Kill-Switch for a fresh run
        kill_switch.reset()
        
        # 2. OPSEC Check
        from src.opsec.manager import OPSECManager
        opsec = OPSECManager(self.target, self.db_session)
        opsec.pre_flight_check()
        
        intent = self.get_operational_intent()
        intent.update(opsec.get_operational_params())

        # 3. Discovery & Analysis Phase (Adaptive Orchestration)
        from src.intelligence.orchestrator import DiscoveryOrchestrator
        orchestrator = DiscoveryOrchestrator(
            self.db_session,
            scan_id=self.runtime_scan.id if self.runtime_scan else None,
        )
        
        passive_subdomains = []
        if "asset_discovery" in plan["capabilities"]:
            passive_subdomains = orchestrator.passive_discovery(self.target) or []
        
        active_hosts = []
        if "live_detection" in plan["capabilities"]:
            active_hosts = orchestrator.active_resolution() or []
        
        if "service_discovery" in plan["capabilities"]:
            orchestrator.service_analysis()

        # Phase 3.5: Takeover Detection (v7.3)
        if "takeover_detection" in plan["capabilities"] or plan["intent"] == "aggressive":
            orchestrator.takeover_detection()

        # Phase 4: Scoring & Prioritization (v6.0)
        logger.info("[HUNT] Phase 4: Asset Scoring & Prioritization")
        from src.storage.models import Port
        from rich.table import Table
        from rich.panel import Panel
        from src.core.logging import console
        
        top_critical = self.db_session.query(Port).order_by(Port.criticality_index.desc()).limit(5).all()
        
        if top_critical:
            table = Table(title="[bold red]Top 5 Critical Targets Identified[/bold red]", show_header=True, header_style="bold magenta")
            table.add_column("Target (Host:Port)", style="dim")
            table.add_column("Service/Product", style="cyan")
            table.add_column("Criticality", justify="center")
            table.add_column("Severity", justify="center")
            table.add_column("Key Recommendation", style="italic")

            for p in top_critical:
                score_color = "red" if p.criticality_index >= 80 else "yellow" if p.criticality_index >= 60 else "blue"
                sev_map = {"CRITICAL": "[bold red]CRITICAL[/bold red]", "HIGH": "[bold orange1]HIGH[/bold orange1]", "MEDIUM": "[bold yellow]MEDIUM[/bold yellow]", "LOW": "[bold green]LOW[/bold green]", "INFO": "[bold blue]INFO[/bold blue]"}
                
                # Obtener recomendación de los detalles guardados
                rec = "-"
                if p.scoring_details and "recommendations" in p.scoring_details:
                    recs = p.scoring_details["recommendations"]
                    rec = recs[0] if recs else "-"

                table.add_row(
                    f"{p.host}:{p.port}",
                    f"{p.service or 'unknown'} ({p.product or '?'})",
                    f"[{score_color}]{p.criticality_index}[/{score_color}]",
                    sev_map.get(p.severity, p.severity),
                    rec
                )
            console.print(Panel(table, expand=False, border_style="red"))
        
        # 4.5. v6.0 Logic Pattern Analysis
        logger.info("[HUNT] Phase 2.5: v6.0 Logic Pattern Analysis")
        from src.intelligence.logic_analyzer import LogicAnalyzer
        logic_brain = LogicAnalyzer()
        
        # Mapear datos para el cerebro usando los activos ya persistidos
        graph_data = {"nodes": []}
        for subdomain in passive_subdomains:
            graph_data["nodes"].append({
                "type": "subdomain",
                "name": subdomain,
                "ip": None,
            })

        # Si hubo hosts confirmados como vivos, los priorizamos para el análisis
        if active_hosts:
            live_set = {host.lower().strip() for host in active_hosts if host}
            graph_data["nodes"] = [
                node for node in graph_data["nodes"]
                if node.get("name", "").lower().strip() in live_set or not live_set
            ]

        logic_hypotheses = logic_brain.analyze_graph(graph_data)
        if logic_hypotheses:
            logger.info(f"🔥 v6.0 Brain found {len(logic_hypotheses)} logical attack paths!")

        # 5. Intelligence Correlation & Hypothesis Generation
        logger.info("[HUNT] Phase 4: Intelligence & Hypothesis Generation")
        out_dir = Path(self.options.get("output") or f"runtime/scans/{self.target}/{self.session_id}")
        
        # Recuperar datos de la DB para el motor de inteligencia (ya persistidos por el orquestador)
        from src.storage.models import Subdomain, Port
        db_subdomains = self.db_session.query(Subdomain).all()
        db_ports = self.db_session.query(Port).all()
        
        intel_context = {
            "config": self.options,
            "phases": {
                "recon": {
                    "all_subdomains": [s.domain for s in db_subdomains],
                    "live_hosts": [s.domain for s in db_subdomains if s.is_live]
                },
                "ports": {
                    "open_ports": [
                        {"host": p.host, "port": p.port, "service": p.service, "version": p.version}
                        for p in db_ports
                    ]
                },
                "vulns": {"findings": []}
            }
        }
        
        # run_intelligence will handle internal persistence to Hypothesis table
        intel_results = run_intelligence(self.target, out_dir, self.options, context=intel_context)

        # 6. Final Status Update & Artifact Generation (v7.7.2 Handled in BaseMode finally)
        self.context.mark_completed()
        
        logger.info(f"[HUNT] Discovery and Intelligence phase completed.")
        logger.info(f"Generated {len(intel_results.get('hypotheses', []))} hypotheses. Run 'ozy gate list' to review.")

        return self.build_output_envelope(
            "completed",
            subdomains=len(db_subdomains),
            active_hosts=len(active_hosts),
            hypotheses=len(intel_results.get("hypotheses", [])),
        )

def run_hunt(target: str, **options) -> Dict[str, Any]:
    return HuntMode(target, options).run()
