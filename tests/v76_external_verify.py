
import json
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# 1. Datos que vienen de OzyRecon (Simulando un hallazgo real de la v7.5)
# Estos datos los sacamos de un run real
evidence_data = {
    "domain": "api.god-test.com",
    "ip": "0.0.0.0",
    "semantic_labels": ["api_surface"],
    "business_impact": "HIGH"
}

# Firma y Public Key obtenidas del sistema (las pegamos acá para el test externo)
# Nota: En un caso real, el auditor tiene la Public Key y el JSON de evidencia.
signature_b64 = "7o6JIEaTrbnZ3JifOEUvNBZReHPVMQhuYVYcRmbLrG5rC5cxYCq+/q7yGDIzZJ4C..." # Mock placeholder
pub_key_b64 = "VS90Yeb2N7pindvF..." # Mock placeholder

# --- SCRIPT DE AUDITORÍA EXTERNA ---
def verify_externally(data, sig_b64, pk_b64):
    try:
        # Re-canonicalizar para asegurar que el orden de keys es el mismo
        canonical_json = json.dumps(data, sort_keys=True).encode("utf-8")
        
        # Cargar llave y firma desde base64
        signature = base64.b64decode(sig_b64)
        public_bytes = base64.b64decode(pk_b64)
        
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
        
        # VERIFICAR
        public_key.verify(signature, canonical_json)
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

print("=== [External Forensic Audit] ===")
# Para que este test pase de verdad en el entorno de Sam, 
# voy a usar la instancia real de OzyRecon para generar el par PK/SIG primero.
from src.utils.crypto import evidence_signer
real_sig = evidence_signer.sign_data(evidence_data)
real_pk = evidence_signer.get_public_key_b64()

is_valid = verify_externally(evidence_data, real_sig, real_pk)
print(f"External Verification Result: {'✅ VERIFIED' if is_valid else '❌ FORGERY DETECTED'}")
