
import os
import json
from pathlib import Path
from sqlalchemy.orm import Session
from src.storage.database import SessionLocal, engine, Base
from src.storage.models import Target, Scan, Subdomain
from src.intelligence.pipeline.orchestrator import DiscoveryOrchestrator

# Setup DB
Base.metadata.create_all(bind=engine)
db = SessionLocal()

# 1. Create Mock Session
target = db.query(Target).filter_by(domain="artifact.test").first()
if not target:
    target = Target(domain="artifact.test")
    db.add(target)
    db.commit()

import time
session_id = f"test_session_v75_{int(time.time())}"
scan = Scan(target_id=target.id, session_id=session_id, status="completed")
db.add(scan)
db.commit()

# Add a mock subdomain
sub = Subdomain(scan_id=scan.id, domain="api.artifact.test", is_live=1, business_impact="HIGH", semantic_labels=["api_surface"])
db.add(sub)
db.commit()

print(f"=== [Artifact Generation Test] Session: {session_id} ===")

# 2. Trigger Finalize
orchestrator = DiscoveryOrchestrator(db, scan_id=scan.id)
orchestrator.finalize_session()

# 3. Verify Folders
base_path = Path("runs") / session_id
expected_dirs = ["normalized", "graph", "trace.json"]
all_ok = True

print("\n--- Verifying Artifacts ---")
for d in expected_dirs:
    p = base_path / d
    exists = p.exists()
    print(f" - {d}: {'✅ EXISTS' if exists else '❌ MISSING'}")
    if not exists: all_ok = False

if all_ok:
    print("\n[SUCCESS] Artifact structure compliant with v7.5 Anti-Humo Checklist.")
else:
    print("\n[FAILED] Artifact structure incomplete.")

db.close()
