"""
BugBounty Agent — El Cerebro
Orquestador inteligente que decide qué módulos lanzar basándose en el contexto de la DB.
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

# Asegurar que el root esté en el path para imports
sys.path.insert(0, str(Path(__file__).parent.parent))

ROOT_DIR = Path(__file__).resolve().parents[2]
RUNTIME_DIR = ROOT_DIR / "runtime"

from modules.llm_router import LLMRouter
from modules.database import SessionLocal, init_db
from modules.utils import log, load_config
import modules.db_queries as queries

# Configuración de los 6 Modos
MODE_CONFIGS = {
    "hunt": {
        "objective": "Modo HUNT: Encuentra vulnerabilidades reportables en {target} nuevo",
        "allowed_tools": ["recon", "ports", "urls", "vulns", "intelligence", "js_analyzer", "fuzzer"],
        "max_steps": 10
    },
    "continuo": {
        "objective": "Modo CONTINUO: Detecta y prioriza cambios en {target} vs sesiones anteriores",
        "allowed_tools": ["recon", "diff", "notifier"],
        "max_steps": 5
    },
    "servicio": {
        "objective": "Genera reporte semanal legible para cliente no técnico",
        "allowed_tools": ["report"],
        "max_steps": 2
    },
    "campaña": {
        "objective": "Aplica un patrón específico en targets con stack determinado",
        "allowed_tools": ["recon", "vulns"],
        "max_steps": 5
    },
    "investigacion": {
        "objective": "Busca un CVE o técnica específica en superficie conocida",
        "allowed_tools": ["vulns"],
        "max_steps": 3
    },
    "forense": {
        "objective": "Analiza brecha de detección y ajusta scoring",
        "allowed_tools": ["report"],
        "max_steps": 2
    },
    "aprendizaje": {
        "objective": "Extrae patrones de éxito del historial y actualiza scoring",
        "allowed_tools": ["config_writer"],
        "max_steps": 5
    }
}

class BugBountyAgent:
    def __init__(self, db_session=None, notifier=None, config=None):
        self.config = config or load_config()
        self.db = db_session or SessionLocal()
        self.notifier = notifier
        self.router = LLMRouter(self.config)
        self.history = []

    def run(self, mode: str, target: Optional[str] = None) -> Dict[str, Any]:
        """Loop principal con Persistencia de Razonamiento y Salida Enriquecida."""
        if mode not in MODE_CONFIGS:
            mode = "hunt"

        # Caso especial: CAMPAÑA
        if mode == "campaña" and not target:
            targets = self._find_campaign_targets()
            return {"mode": "campaña", "multi_results": [self.run("campaña", t) for t in targets]}

        log(f"--- AGENTE INICIADO [{mode.upper()}] PARA {target} ---", "info")
        
        self.internal_context = {
            "mode": mode, "target": target, "start_time": datetime.now().isoformat(),
            "out_dir": str(RUNTIME_DIR / "output" / target / "agent"), "phases": {}
        }

        # 1. Cargar Contexto + Memoria previa
        context = self._load_context(target)
        memory = self._load_agent_memory(target)
        context["agent_memory"] = memory
        
        mode_cfg = MODE_CONFIGS[mode]
        stop_reason = "max_steps_reached"

        # 2. Loop de razonamiento
        for step in range(mode_cfg["max_steps"]):
            log(f"Paso {step+1} - Pensando...", "info")
            
            decision = self.router.think(
                objective=mode_cfg["objective"].format(target=target, X="{X}", Y="{Y}"),
                tools=mode_cfg["allowed_tools"],
                context=context,
                history=self.history
            )

            # --- LOGGING ESTRUCTURADO DE RAZONAMIENTO ---
            self._log_reasoning(step+1, mode, target, decision, context)

            if decision.get("action") == "STOP":
                stop_reason = decision.get("reason", "agent_decision")
                break

            # 3. Ejecutar y persistir razonamiento
            result = self._execute(decision.get("action"), target, decision.get("params", {}))
            
            # Guardar en AgentMemory si la confianza es alta
            if decision.get("confidence", 0) > 0.7:
                self._save_reasoning(target, mode, "tactical_decision", decision, confidence=decision.get("confidence", 1.0))

            self.history.append({
                "step": step + 1,
                "decision": decision,
                "result": result,
                "useful": self._was_useful(result),
                "timestamp": datetime.now().isoformat()
            })
            
            # Persistencia incremental
            if decision.get("action") in ["recon", "ports", "vulns", "urls"]:
                self.internal_context["phases"][decision["action"]] = result
                from modules.database import save_scan_to_db
                save_scan_to_db(self.internal_context)
            
            context = self._load_context(target)

        return self._generate_output(mode, target, stop_reason)

    def _log_reasoning(self, step: int, mode: str, target: str, decision: dict, context: dict):
        """Registra el proceso de pensamiento en un archivo de log persistente."""
        log_file = RUNTIME_DIR / "logs" / "agent_reasoning.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        entry = {
            "timestamp": ts,
            "step": step,
            "mode": mode,
            "target": target,
            "decision": decision.get("action"),
            "confidence": decision.get("confidence"),
            "reason": decision.get("reason"),
            "tech_stack": context.get("tech_stack", []),
            "findings_count": len(context.get("findings", []))
        }
        
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def _save_reasoning(self, target: str, mode: str, key: str, value: Any, confidence: float = 1.0):
        """Guarda un razonamiento específico en la tabla AgentMemory."""
        try:
            from .models import AgentMemory
            mem = AgentMemory(
                target=target,
                mode=mode,
                key=key,
                value=value,
                confidence=confidence
            )
            self.db.add(mem)
            self.db.commit()
        except Exception as e:
            log(f"Error guardando memoria: {e}", "error")

    def _load_agent_memory(self, target: str) -> List[dict]:
        """Carga razonamientos previos de la DB."""
        try:
            from .models import AgentMemory
            mems = self.db.query(AgentMemory).filter(AgentMemory.target == target).order_by(AgentMemory.created_at.desc()).limit(20).all()
            return [{"mode": m.mode, "key": m.key, "value": m.value, "at": m.created_at.isoformat()} for m in mems]
        except: return []

    def _was_useful(self, result: dict) -> bool:
        """Determina si un paso aportó información nueva."""
        if not result: return False
        if result.get("status") == "error": return False
        return True

    def _generate_output(self, mode: str, target: str, stop_reason: str) -> Dict[str, Any]:
        """Genera el resumen ejecutivo del Agente."""
        useful_steps = [h for h in self.history if h["useful"]]
        
        # Lógica de recomendación simple (puede ser potenciada por IA luego)
        next_mode = "continuo"
        if any("vuln" in h["decision"]["action"] for h in useful_steps):
            next_mode = "forense"

        return {
            "mode": mode,
            "target": target,
            "stop_reason": stop_reason,
            "steps_taken": len(self.history),
            "useful_steps": len(useful_steps),
            "next_recommended": next_mode,
            "history": self.history
        }

    def _load_context(self, target: str) -> Dict[str, Any]:
        """
        Usa EXCLUSIVAMENTE las funciones de db_queries.py.
        Independiza al agente de la implementación de la DB.
        """
        # Obtenemos datos crudos de las queries existentes
        try:
            latest_scan = queries.get_latest_scan(self.db, target)
            diff = queries.get_scan_diff(self.db, target) if latest_scan else {"is_first_run": True}
            
            # Construimos el diccionario de contexto para el LLM
            return {
                "target": target,
                "subdomains": [s.domain for s in latest_scan.subdomains] if latest_scan else [],
                "live_hosts": [s.domain for s in latest_scan.subdomains if s.is_live] if latest_scan else [],
                "open_ports": [{"host": p.host, "port": p.port, "service": p.service} for p in latest_scan.ports] if latest_scan else [],
                "findings": [{"type": v.type, "severity": v.severity} for v in latest_scan.vulnerabilities] if latest_scan else [],
                "diff": diff,
                "tech_stack": list(set([s.web_server for s in latest_scan.subdomains if s.web_server])) if latest_scan else []
            }
        except Exception as e:
            log(f"Error cargando contexto: {e}", "error")
            return {"target": target, "error": str(e)}

    def _execute(self, action: str, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Llama a los módulos existentes. En INVESTIGACIÓN/FORENSE, las acciones
        suelen ser más quirúrgicas o de reporte.
        """
        log(f"Lanzando acción: {action} sobre {target}...", "info")
        
        try:
            # --- ACCIONES DE SCAN (HUNT / INVESTIGACIÓN) ---
            if action == "recon":
                from modules.recon import run_recon
                out_dir = RUNTIME_DIR / "output" / target / "agent" / "recon"
                class Args: pass
                args_obj = Args(); args_obj.target = target; args_obj.recon = True; args_obj.full = False
                return run_recon(target, out_dir, args_obj)
            
            elif action == "ports":
                from modules.ports import run_ports
                out_dir = RUNTIME_DIR / "output" / target / "agent" / "ports"
                latest = queries.get_latest_scan(self.db, target)
                hosts = [s.domain for s in latest.subdomains if s.is_live] if latest else [target]
                class Args: pass
                args_obj = Args(); args_obj.target = target; args_obj.ports = True
                return run_ports(hosts, out_dir, args_obj, {})

            elif action == "vulns":
                from modules.vuln import run_vulns
                out_dir = RUNTIME_DIR / "output" / target / "agent" / "vulns"
                
                # Si hay un CVE específico (INVESTIGACIÓN)
                cve = params.get("cve")
                if cve:
                    log(f"Escaneo quirúrgico para {cve}...", "warn")
                
                class Args: pass
                args_obj = Args(); args_obj.target = target; args_obj.vulns = True
                return run_vulns([target], out_dir, args_obj, {})

            # --- ACCIONES DE ANÁLISIS (FORENSE / SERVICIO) ---
            elif action == "report":
                log("Generando reporte profundo con IA...", "warn")
                
                # Persona del Agente según el modo
                persona = "Analista técnico Senior"
                if self.internal_context["mode"] == "servicio":
                    persona = "Consultor de Ciberseguridad para Clientes No Técnicos (Lenguaje Ejecutivo)"
                
                # Cargamos contexto fresco
                fresh_context = self._load_context(target)
                prompt = f"Actúa como {persona}. Analiza los siguientes datos de {target} y genera un reporte accionable: {json.dumps(fresh_context)}"
                analysis = self.router.call(prompt, task_type="heavy")
                
                out_dir = RUNTIME_DIR / "output" / target / "agent" / "reports"
                out_dir.mkdir(parents=True, exist_ok=True)
                report_path = out_dir / f"agent_{self.internal_context['mode']}_{datetime.now().strftime('%H%M%S')}.md"
                report_path.write_text(analysis)
                
                log(f"Reporte generado en {report_path}", "success")
                return {"status": "success", "report_path": str(report_path)}

            # --- ACCIONES DE APRENDIZAJE ---
            elif action == "config_writer":
                log("Ejecutando motor de aprendizaje estadístico...", "warn")
                from modules.learning_engine import LearningEngine
                engine = LearningEngine(self.db)
                analysis_results = engine.analyze_and_update()
                return {"status": "success", "action": "config_writer", "results": analysis_results}

            return {"status": "executed", "action": action}
            
        except Exception as e:
            log(f"Error ejecutando acción {action}: {e}", "error")
            return {"status": "error", "error": str(e)}

    def _find_campaign_targets(self) -> List[str]:
        """Busca targets en la DB que coincidan con el patrón deseado."""
        try:
            from .models import Target
            targets = self.db.query(Target).all()
            return [t.domain for t in targets[:5]] # Limitamos a los primeros 5 para el test
        except:
            return []

if __name__ == "__main__":
    init_db()
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    agent = BugBountyAgent()
    result = agent.run("hunt", target)
    print(json.dumps(result, indent=2))
