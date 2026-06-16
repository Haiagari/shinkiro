"""
OzyRecon Intelligence Dashboard (CLI)
Visualiza métricas de aprendizaje y evolución de pesos.
"""

from sqlalchemy import text

from src.intelligence.learning.learning_orchestrator import learning_orchestrator
from src.intelligence.scoring.feedback_engine import feedback_engine
from src.utils import log

class IntelligenceDashboard:
    """
    Dashboard simple por consola para ver la salud del aprendizaje.
    """
    
    def show_metrics(self):
        from src.intelligence.learning.decision_log import DecisionRepository
        from src.storage.database import SessionLocal
        
        # Obtener datos de la DB directamente (persistente)
        db = SessionLocal()
        repo = DecisionRepository(db)
        
        # Contar decisiones desde la DB
        total_decisions = db.execute(text("SELECT COUNT(*) FROM decisions")).fetchone()[0]
        
        # Calcular accuracy desde la DB
        total_with_result = db.execute(text(
            "SELECT COUNT(*) FROM decisions WHERE result IS NOT NULL"
        )).fetchone()[0]
        successes = db.execute(text(
            "SELECT COUNT(*) FROM decisions WHERE result IN ('success', 'critical')"
        )).fetchone()[0]
        
        accuracy_rate = (successes / total_with_result * 100) if total_with_result > 0 else 0.0
        signal_to_noise = (successes / total_with_result) if total_with_result > 0 else 0.0
        
        # Avg value
        avg_value = db.execute(text(
            "SELECT AVG(value_score) FROM decisions WHERE value_score IS NOT NULL"
        )).fetchone()[0] or 0.0
        
        db.close()
        
        weights = learning_orchestrator.feedback.get_adjusted_weights()
        
        print("\n" + "="*60)
        print("   OZYRECON INTELLIGENCE DASHBOARD (v4.0)")
        print("="*60)
        
        if total_decisions == 0:
            print(f"\n[📊] MÉTRICAS GLOBALES:")
            print(f"  • Total Decisiones     : 0")
            print(f"  • Accuracy Rate        : 0.0%")
            print(f"  • Signal-to-Noise Ratio: 0.00")
            print(f"  • Avg Value per Scan   : 0.00")
            print(f"\n[ℹ️] Ejecutá un scan (modo hunt) para generar decisiones.")
            print(f"[ℹ️] El sistema registrará cada priorización y evaluará resultados.")
            print("\n" + "="*50 + "\n")
            return
        
        print(f"\n[📊] MÉTRICAS GLOBALES:")
        print(f"  • Total Decisiones     : {total_decisions}")
        print(f"  • Accuracy Rate        : {accuracy_rate:.1f}%")
        print(f"  • Signal-to-Noise Ratio: {signal_to_noise:.2f}")
        print(f"  • Avg Value per Scan   : {avg_value:.2f}")
        
        # Top Decisiones
        db = SessionLocal()
        repo = DecisionRepository(db)
        
        print(f"\n[🏆] TOP DECISIONES ACERTADAS:")
        successes = repo.get_top_decisions(limit=3, success=True)
        if successes:
            for d in successes:
                print(f"  ✅ {d.decision_type} on {d.target} ({d.result}) - Score: {d.value_score:.2f}")
        else:
            print("  (sin decisiones exitosas aún)")
            
        print(f"\n[❌] DECISIONES FALLIDAS:")
        failures = repo.get_top_decisions(limit=3, success=False)
        if failures:
            for d in failures:
                print(f"  ⚠️  {d.decision_type} on {d.target} ({d.result}) - Score: {d.value_score:.2f}")
        else:
            print("  (sin decisiones fallidas aún)")
        
        db.close()

        print(f"\n[⚖️ ] PESOS ACTUALES (FeedbackEngine):")
        print(f"  • Reputation Weight    : {weights['reputation']:.2f}")
        print(f"  • Novelty Weight       : {weights['novelty']:.2f}")
        print(f"  • Diff Signal Weight   : {weights['diff_signal']:.2f}")
        
        print(f"\n[🧠] INSIGHTS DEL SISTEMA:")
        feedback_insights = learning_orchestrator.feedback.get_insights()
        insights = feedback_insights.get('insights', [])
        for i in insights:
            print(f"  → {i}")
            
        print(f"\n[⚠️] RECOMENDACIONES:")
        recs = learning_orchestrator.get_recommendations()
        for r in recs:
            print(f"  ! {r}")
            
        print("\n" + "="*50 + "\n")

def show_dashboard():
    dash = IntelligenceDashboard()
    dash.show_metrics()
