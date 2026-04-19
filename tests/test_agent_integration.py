import sys
import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from modules.agent import BugBountyAgent
from modules.database import SessionLocal, init_db
from modules.llm_router import LLMRouter

def test_memoria_persiste_entre_modos():
    """Problema 1: lo que guarda HUNT lo lee INVESTIGACIÓN"""
    db = SessionLocal()
    agent = BugBountyAgent(db_session=db)
    
    target = "integration-test.com"
    
    # Simula que HUNT guardó un razonamiento
    agent._save_reasoning(target, "hunt", "tech_stack", 
                          {"framework": "laravel"}, confidence=0.9)
    
    # Verifica que INVESTIGACIÓN lo carga
    memory = agent._load_agent_memory(target)
    assert any(m["key"] == "tech_stack" for m in memory), \
        "FALLO: INVESTIGACIÓN no ve lo que guardó HUNT"
    
    val = next(m for m in memory if m["key"] == "tech_stack")
    assert val["value"]["framework"] == "laravel"
    
    db.close()
    print("✅ Memoria entre modos: OK")

def test_fallback_no_rompe_daemon():
    """Problema 2: con todas las APIs caídas el daemon sigue vivo"""
    # Config sin llaves y budget 0 para forzar fallback
    router = LLMRouter(config={"agent": {"daily_budget_usd": 0}, "ai": {}})
    
    # Simula check de modo continuo con subdominio nuevo
    decision = router.think(
        objective = "Detecta y prioriza cambios en test.com",
        tools     = ["recon", "diff"],
        context   = {"diff": {"new_subdomains": ["new.test.com"]}},
        history   = []
    )
    
    assert decision["action"] == "recon", f"FALLO: fallback no sugirió recon ante subdominio nuevo. Obtuve: {decision['action']}"
    assert "reason" in decision, "FALLO: fallback sin reason"
    print("✅ Fallback determinista: OK")

def test_output_siempre_tiene_next_recommended():
    """Problema 3: aunque no haya bug, siempre hay output útil"""
    agent = BugBountyAgent()
    
    # Fuerza parada por max_steps
    output = agent._generate_output("hunt", "test.com", 
                                     stop_reason="max_steps_reached")
    
    assert "next_recommended" in output, "FALLO: sin recomendación"
    assert "stop_reason" in output, "FALLO: sin stop_reason"
    assert output["stop_reason"] == "max_steps_reached"
    print("✅ Output enriquecido: OK")

if __name__ == "__main__":
    init_db()
    try:
        test_memoria_persiste_entre_modos()
        test_fallback_no_rompe_daemon()
        test_output_siempre_tiene_next_recommended()
        print("\n🏆 Los 3 fixes integrados correctamente. Listo para APRENDIZAJE.")
    except Exception as e:
        print(f"\n❌ ERROR EN EL TEST: {e}")
        sys.exit(1)
