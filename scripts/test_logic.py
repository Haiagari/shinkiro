#!/usr/bin/env python3
"""
Test de Laboratorio: PromptWall v6.0 Logic Analyzer
Simula un Knowledge Graph poblado y verifica que el motor encuentre el Attack Path.
"""

from src.intelligence.analysis.logic_analyzer import LogicAnalyzer
import json

def test_logic_brain():
    print("🧠 Iniciando Análisis de Lógica v6.0...")
    print("-" * 50)
    
    # Simulamos el Knowledge Graph que Ozy recolectó
    mock_graph = {
        "nodes": [
            {"id": 1, "type": "subdomain", "name": "api.target.com", "ip": "INTERNAL_NET_A"},
            {"id": 2, "type": "subdomain", "name": "dev-api.target.com", "ip": "INTERNAL_NET_A"},
            {"id": 3, "type": "subdomain", "name": "blog.target.com", "ip": "EXTERNAL_NET_B"},
            {"id": 4, "type": "vulnerability", "name": "Session Cookie Leak", "target": "dev-api.target.com"}
        ]
    }
    
    analyzer = LogicAnalyzer()
    hypotheses = analyzer.analyze_graph(mock_graph)
    
    if hypotheses:
        print(f"🔥 ¡SE ENCONTRARON {len(hypotheses)} HIPÓTESIS DE ATAQUE LÓGICO!\n")
        for h in hypotheses:
            print(f"🆔 ID: {h['id']}")
            print(f"⚠️ Tipo: {h['type']}")
            print(f"💪 Confianza: {int(h['confidence']*100)}%")
            print(f"📝 Descripción: {h['description']}")
            print(f"🎯 Acción Sugerida: {h['action']}")
            print("-" * 30)
    else:
        print("🤔 No se detectaron patrones lógicos obvios.")

if __name__ == "__main__":
    test_logic_brain()
