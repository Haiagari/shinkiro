
import json
import time
from sqlalchemy.orm import Session
from src.storage.database import SessionLocal, engine, Base
from src.storage.models import Target, Scan, Subdomain
from src.intelligence.ai_analyzer import ai_analyst

# Setup
db = SessionLocal()
target_domain = "critical-target.test"

# 1. Crear Target y Scan
target = db.query(Target).filter_by(domain=target_domain).first()
if not target:
    target = Target(domain=target_domain)
    db.add(target)
    db.commit()

session_id = f"v81_ai_proof_{int(time.time())}"
scan = Scan(target_id=target.id, session_id=session_id, status="completed")
db.add(scan)
db.commit()

# 2. Inyectar un hallazgo CRÍTICO real para la IA
# Simulamos un Admin Panel expuesto en una infraestructura staging
sub = Subdomain(
    scan_id=scan.id, 
    domain="admin-staging.internal.critical-target.test", 
    is_live=1, 
    title="Grafana Dashboard - login",
    technologies=["Grafana", "Go", "Docker"],
    semantic_labels=["gate_admin", "non_prod_env"],
    business_impact="CRITICAL"
)
db.add(sub)
db.commit()

print(f"=== [v8.1 AI Narrative Proof] Session: {session_id} ===")

# 3. Generar Análisis
asset_data = {
    "domain": sub.domain,
    "semantic_labels": sub.semantic_labels,
    "business_impact": sub.business_impact,
    "technologies": sub.technologies,
    "title": sub.title
}

narrative = ai_analyst.generate_finding_narrative(asset_data)

print("\n--- AI OUTPUT ---")
print(json.dumps(narrative, indent=2))

db.close()
