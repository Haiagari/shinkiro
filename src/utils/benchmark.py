"""
PromptWall Benchmark Utility
Compara el performance con Feedback ON vs OFF.
"""

import time
from typing import Dict, Any, List
from src.modes.hunt import HuntMode
from src.intelligence.scoring.feedback_engine import feedback_engine
from src.utils import log

class LearningBenchmark:
    """
    Utility para medir la efectividad del ciclo de aprendizaje.
    """
    
    def __init__(self, target: str):
        self.target = target
        self.results = {}

    def run_benchmark(self):
        log.info(f"=== INICIANDO BENCHMARK PromptWall en {self.target} ===")
        
        # 1. Ejecución con Feedback OFF (Pesos estáticos)
        log.info("[BENCHMARK] Corriendo con Feedback OFF (Static Weights)")
        feedback_engine.reset_to_defaults()
        
        start_static = time.time()
        mode_static = HuntMode(self.target)
        res_static = mode_static.run()
        end_static = time.time()
        
        self.results['static'] = {
            'duration': end_static - start_static,
            'findings': res_static.get('findings', 0),
            'accuracy': res_static.get('intelligence_accuracy', 0.0)
        }
        
        # 2. Ejecución con Feedback ON (Pesos evolucionados)
        # Simulamos una segunda ejecución después de haber aprendido
        log.info("[BENCHMARK] Corriendo con Feedback ON (Evolving Weights)")
        
        start_evolved = time.time()
        mode_evolved = HuntMode(self.target)
        res_evolved = mode_evolved.run()
        end_evolved = time.time()
        
        self.results['evolved'] = {
            'duration': end_evolved - start_evolved,
            'findings': res_evolved.get('findings', 0),
            'accuracy': res_evolved.get('intelligence_accuracy', 0.0)
        }
        
        self._print_comparison()
        return self.results

    def _print_comparison(self):
        s = self.results['static']
        e = self.results['evolved']
        
        log.info("=== RESULTADOS DEL BENCHMARK ===")
        log.info(f"Metrica           | Static       | Evolved      | Cambio")
        log.info(f"------------------|--------------|--------------|-------")
        log.info(f"Duración (s)      | {s['duration']:>12.2f} | {e['duration']:>12.2f} | {((e['duration']/s['duration'])-1)*100:>+6.1f}%")
        log.info(f"Hallazgos         | {s['findings']:>12} | {e['findings']:>12} | {((e['findings']/max(1,s['findings']))-1)*100:>+6.1f}%")
        log.info(f"Precisión (%)     | {s['accuracy']*100:>11.1f}% | {e['accuracy']*100:>11.1f}% | {((e['accuracy']/max(0.01,s['accuracy']))-1)*100:>+6.1f}%")

def run_bench(target: str):
    bench = LearningBenchmark(target)
    return bench.run_benchmark()
