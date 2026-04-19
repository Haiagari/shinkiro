"""
Simulación de aprendizaje para demostración del Dashboard.
"""

from src.intelligence.learning_orchestrator import learning_orchestrator
from src.intelligence.dashboard import show_dashboard
from src.intelligence.decision_log import DecisionRepository
from src.storage.database import SessionLocal, init_db

def simulate():
    init_db()
    db = SessionLocal()
    
    print("[*] Simulando ciclo de aprendizaje...")
    
    # 1. Decisión Acertada
    did1 = learning_orchestrator.record_decision(
        session_id="sim-001",
        decision_type="prioritize_host",
        target="api.target.com",
        reason="high_reputation",
        context={"reputation": 8.5}
    )
    # Resultado: Hallazgo crítico
    learning_orchestrator.evaluate_priority_decision(
        decision_id=did1,
        host="api.target.com",
        host_reputation=8.5,
        has_critical=True,
        has_high=False,
        has_findings=True
    )
    
    # 2. Decisión Fallida
    did2 = learning_orchestrator.record_decision(
        session_id="sim-001",
        decision_type="prioritize_host",
        target="dev-server.internal",
        reason="novelty",
        context={"novelty": True}
    )
    # Resultado: Nada encontrado, tiempo perdido
    learning_orchestrator.evaluate_priority_decision(
        decision_id=did2,
        host="dev-server.internal",
        host_reputation=2.0,
        has_critical=False,
        has_high=False,
        has_findings=False
    )
    
    # 3. Decisión Diferencial exitosa
    did3 = learning_orchestrator.record_decision(
        session_id="sim-001",
        decision_type="trigger_scan_on_diff",
        target="target.com",
        reason="version_change",
        context={"changed": "nginx/1.14->1.18"}
    )
    # Resultado: Hallazgo high
    learning_orchestrator.evaluate_decision(
        decision_id=did3,
        findings=[{"severity": "high", "name": "Misconfiguration"}],
        time_spent=45.0
    )
    
    print("[+] Simulación completada.\n")
    show_dashboard()
    
    db.close()

if __name__ == "__main__":
    simulate()
