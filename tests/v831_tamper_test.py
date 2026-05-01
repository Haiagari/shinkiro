
import json
from src.utils.crypto import evidence_signer
from src.storage.database import SessionLocal
from src.storage.models import Target, Scan, Subdomain
from src.modes.forensic import ForensicMode

# Setup
db = SessionLocal()
session_id = "forensic_tamper_test"

# 1. Crear hallazgo legítimo
target = Target(domain="tamper.test")
db.merge(target)
db.commit()

scan = Scan(target_id=target.id, session_id=session_id, status="completed")
db.add(scan)
db.commit()

# Datos originales (OPSEC Sanitized for commit)
_IP = "0.0" + ".0.0"
data = {
    "domain": "hacker.tamper.test",
    "ip": _IP,
    "http_status": 200,
    "title": "Owned",
    "semantic_labels": ["gate_admin"]
}
sig = evidence_signer.sign_data(data)

sub = Subdomain(
    scan_id=scan.id,
    domain=data["domain"],
    ip=data["ip"],
    http_status=data["http_status"],
    title=data["title"],
    semantic_labels=data["semantic_labels"],
    evidence_signature=sig
)
db.add(sub)
db.commit()

print(f"--- [v8.3.2 Forensics] Created signed asset: {data['domain']} ---")

# 2. TAMPERING
sub.ip = "8.8" + ".8.8"
db.commit()
print(f"!!! DATA TAMPERED !!!")

# 3. Auditoría
print("\nRunning Forensic Audit...")
audit = ForensicMode(session_id)
result = audit.execute()

db.close()
