"""
OzyRecon Intelligence Dashboard (CLI)
Visualiza métricas de aprendizaje y evolución de pesos.
"""

from src.intelligence.learning_orchestrator import learning_orchestrator
from src.intelligence.feedback_engine import feedback_engine
from src.utils import log

class IntelligenceDashboard:
    """
    Dashboard simple por consola para ver la salud del aprendizaje.
    """
    
    def show_metrics(self):
        data = learning_orchestrator.get_full_feedback()
        metrics = data['metrics']
        weights = data['weights']
        
        print("\n" + "="*50)
        print("   OZYRECON INTELLIGENCE DASHBOARD (v4.0)")
        print("="*50)
        
        print(f"\n[📊] MÉTRICAS GLOBALES:")
        print(f"  • Total Decisiones     : {metrics['total_decisions']}")
        print(f"  • Accuracy Rate        : {metrics['decision_accuracy_rate']:.1%}")
        print(f"  • Signal-to-Noise Ratio: {metrics['signal_to_noise_ratio']:.2f}")
        print(f"  • Avg Value per Scan   : {metrics['avg_value_per_scan']:.2f}")
        
        print(f"\n[⚖️ ] PESOS ACTUALES (FeedbackEngine):")
        print(f"  • Reputation Weight    : {weights['reputation']:.2f}")
        print(f"  • Novelty Weight       : {weights['novelty']:.2f}")
        print(f"  • Diff Signal Weight   : {weights['diff_signal']:.2f}")
        
        print(f"\n[🧠] INSIGHTS DEL SISTEMA:")
        insights = data['feedback_insights']['insights']
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
