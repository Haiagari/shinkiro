#!/usr/bin/env python3
"""
Test de Laboratorio: PromptWall v6.0 Chameleon Engine
Verifica que las identidades sintéticas y la firma TLS sean consistentes.
"""

import sys
import json
from src.core.providers.http_clients import http_client

def test_stealth():
    url = "https://httpbin.org/headers"
    print(f"🚀 Iniciando prueba de sigilo contra: {url}")
    print(f"🎭 Identidad actual: {http_client.identity.name}")
    print("-" * 50)
    
    try:
        # Hacemos el pedido usando el cliente de la v6.0
        response = http_client.get(url)
        
        if response.status_code == 200:
            data = response.json()
            headers_received = data.get("headers", {})
            
            print("✅ Headers recibidos por el servidor:")
            print(json.dumps(headers_received, indent=2))
            
            # Verificación de consistencia
            ua = headers_received.get("User-Agent", "")
            if "curl" in ua.lower() or "python" in ua.lower():
                print("\n❌ FALLO DE SIGILO: El servidor detectó el motor real.")
            else:
                print("\n💎 ÉXITO: El servidor cree que somos un navegador real.")
                
        else:
            print(f"❌ Error de conexión: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error durante el test: {e}")

if __name__ == "__main__":
    test_stealth()
