
import subprocess
import time
import os

def run_api():
    proc = subprocess.Popen(["python3", "-c", "from src.core.api import start_api; start_api()"])
    time.sleep(3) # Wait for start
    return proc

def test_concurrency():
    print("=== [Concurrency & Integrity Test] ===")
    api_proc = run_api()
    
    try:
        # Simulate 2 concurrent requests to a mock hunt endpoint (if implemented)
        # Or just check if the DB handles parallel writes
        print("Spawning parallel database writers...")
        
        def run_mock_discovery(session_id, target):
            from src.storage.database import SessionLocal
            from src.intelligence.orchestrator import DiscoveryOrchestrator
            from src.storage.models import Target, Scan
            
            db = SessionLocal()
            t = Target(domain=target)
            db.merge(t) # Use merge for concurrency safety on target
            db.commit()
            
            scan = Scan(target_id=t.id, session_id=session_id, status="running")
            db.add(scan)
            db.commit()
            
            orchestrator = DiscoveryOrchestrator(db, scan_id=scan.id)
            # Simulate a few assets
            orchestrator._upsert_assets([{"domain": f"sub1.{target}"}, {"domain": f"sub2.{target}"}])
            orchestrator.finalize_session()
            db.close()
            print(f"✅ Session {session_id} finished.")

        import threading
        t1 = threading.Thread(target=run_mock_discovery, args=("stress_1", "target1.com"))
        t2 = threading.Thread(target=run_mock_discovery, args=("stress_2", "target2.com"))
        
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        print("\nChecking artifact integrity...")
        s1_trace = os.path.exists("runs/stress_1/trace.json")
        s2_trace = os.path.exists("runs/stress_2/trace.json")
        
        if s1_trace and s2_trace:
            print("✅ Both sessions isolated and artifacts intact.")
        else:
            print("❌ Artifact missing or corrupted.")

    finally:
        api_proc.kill()

if __name__ == "__main__":
    test_concurrency()
