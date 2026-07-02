#!/usr/bin/env python3
"""
Test de Laboratorio: PromptWall v6.0 Surgical Prober
Simula vulnerabilidades y verifica que el motor las valide con precisión.
"""

import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from src.validation.surgical import surgical_prober

class MockVulnerableServer(BaseHTTPRequestHandler):
    def do_GET(self):
        # Escenario 1: Un .env real con secretos
        if self.path == "/.env-real":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DB_PASSWORD=super_secret_123\nAPP_KEY=ozy_v6_key\n")
            
        # Escenario 2: Un .env falso (falso positivo común)
        elif self.path == "/.env-fake":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"This is just a README file named .env for testing.\nNothing sensitive here.")

        # Escenario 3: Path Traversal simulado
        elif self.path == "/view?file=/etc/passwd":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"root:x:0:0:root:/root:/bin/bash\n")
            
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args): return # Silenciar logs del server

def run_server():
    server = HTTPServer(('127.0.0.1', 9999), MockVulnerableServer)
    server.serve_forever()

def test_probes():
    print("🩺 Iniciando Operación Quirúrgica v6.0...")
    print("-" * 50)
    
    base_url = "http://127.0.0.1:9999"
    
    # 1. Validando el .env real
    print(f"🔍 Probando .env REAL...")
    res1 = surgical_prober.validate_env_exposure(f"{base_url}/.env-real")
    print(f"   Resultado: {res1['status'].upper()} | Evidencia: {res1.get('evidence_sample')}")
    
    # 2. Validando el .env falso
    print(f"\n🔍 Probando .env FALSO (Falso Positivo)...")
    res2 = surgical_prober.validate_env_exposure(f"{base_url}/.env-fake")
    print(f"   Resultado: {res2['status'].upper()} | Evidencia: {res2.get('evidence_sample')}")
    
    # 3. Validando Path Traversal
    print(f"\n🔍 Probando Path Traversal...")
    res3 = surgical_prober.validate_path_traversal(f"{base_url}/view?file=", "/etc/passwd")
    print(f"   Resultado: {res3['status'].upper()}")

if __name__ == "__main__":
    # Levantar server en un hilo aparte
    threading.Thread(target=run_server, daemon=True).start()
    time.sleep(1) # Esperar a que el server suba
    
    test_probes()
