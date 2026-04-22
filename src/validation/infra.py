"""
Infra Validator - Validación de servicios de infraestructura (DBs, Caches) v5.2
"""

import socket
from typing import Dict, Any
from src.validation.base import BaseValidator, ValidationResult
from src.core.logging import get_logger

logger = get_logger('validation.infra')

class InfraValidator(BaseValidator):
    def validate(self, hypothesis: Dict[str, Any]) -> ValidationResult:
        hypo_id = hypothesis.get("id")
        url_raw = hypothesis.get("url", "")
        
        # Parsear host y puerto
        if ":" in url_raw:
            host, port = url_raw.split(":")
            port = int(port)
        else:
            host = url_raw
            port = hypothesis.get("signals", {}).get("port", 0)

        logger.info(f"Validating Infrastructure exposure on {host}:{port}")
        
        evidence = []
        status = "inconclusive"
        confidence = hypothesis.get("confidence", 0.0)
        notes = ""

        try:
            # Prueba de conexión via socket (TCP Handshake)
            with socket.create_connection((host, port), timeout=5) as sock:
                evidence.append(self.create_evidence(
                    "tcp_handshake", 
                    f"Connection successful to {host}:{port}", 
                    {"protocol": "tcp"}
                ))
                
                # Proba específica para Redis
                if port == 6379:
                    sock.sendall(b"PING\r\n")
                    response = sock.recv(1024).decode(errors='ignore')
                    evidence.append(self.create_evidence("service_response", response))
                    
                    if "+PONG" in response:
                        status = "confirmed"
                        confidence = 0.99
                        notes = "Redis is exposed WITHOUT authentication (received PONG)."
                    elif "NOAUTH" in response:
                        status = "confirmed"
                        confidence = 0.85
                        notes = "Redis is exposed but requires authentication."

                # Handshake para PostgreSQL (v5.4)
                elif port == 5432:
                    # Enviar SSLRequest packet (8 bytes)
                    sock.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
                    resp = sock.recv(1)
                    if resp == b"S":
                        evidence.append(self.create_evidence("infra_fingerprint", "PostgreSQL supports SSL", {"port": 5432}))
                        notes = "PostgreSQL detected with SSL support."
                    else:
                        notes = "PostgreSQL detected (SSL not forced)."
                    status = "confirmed"
                    confidence = 0.95

                # Handshake para MySQL (v5.4)
                elif port == 3306:
                    banner = sock.recv(1024)
                    if banner:
                        # El banner de MySQL suele tener la versión al principio
                        version_info = banner[5:].split(b"\x00")[0].decode(errors='ignore')
                        evidence.append(self.create_evidence("infra_fingerprint", f"MySQL Version: {version_info}", {"raw": str(banner)}))
                        notes = f"MySQL version {version_info} confirmed via handshake."
                        status = "confirmed"
                        confidence = 0.98
                
                # Si llegamos acá y es otro puerto, al menos confirmamos que el puerto está abierto
                if status == "inconclusive":
                    status = "confirmed"
                    confidence = 0.90
                    notes = f"Service on port {port} is reachable and responding."

        except Exception as e:
            logger.error(f"Infra validation error: {str(e)}")
            notes = f"Connection failed or refused: {str(e)}"
            status = "refuted"
            confidence = 0.1

        return ValidationResult(hypo_id, status, confidence, evidence, notes)
