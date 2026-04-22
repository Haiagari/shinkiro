import sys
import os
import yaml
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from modules.database import SessionLocal, init_db
from modules.learning_engine import LearningEngine
from modules.models import AgentMemory

def test_aprendizaje_respeta_min_observaciones():
    """Verifica que NO toca scoring.yaml si hay menos de 5 obs."""
    db = SessionLocal()
    scoring_file = ROOT_DIR / "config" / "scoring.yaml"
    
    # Limpieza TOTAL: scoring y datos existentes
    if scoring_file.exists(): scoring_file.unlink()
    db.query(AgentMemory).delete()
    db.commit()
    
    # Crear solo 2 observaciones (menos de 5 = no debe escribir)
    target = "test-low.com"
    m1 = AgentMemory(target=target, mode="hunt", key="tech_stack", value=["WordPress"])
    m2 = AgentMemory(target=target, mode="hunt", key="tech_stack", value=["WordPress"])
    db.add(m1)
    db.add(m2)
    db.commit()
    
    engine = LearningEngine(db)
    res = engine.analyze_and_update()
    
    # Con menos de 5 obs, no debería existir scoring.yaml
    assert not scoring_file.exists(), "FALLO: Creó scoring.yaml sin suficiente data"
    
    db.close()
    print("✅ Restricción Min Observations: OK")

def test_aprendizaje_escribe_con_data_suficiente():
    """Verifica que SÍ actualiza con 5+ observaciones."""
    db = SessionLocal()
    scoring_file = ROOT_DIR / "config" / "scoring.yaml"
    
    # Limpiar scoring
    if scoring_file.exists(): scoring_file.unlink()
    
    # Limpiar observaciones de target.unique.com
    db.query(AgentMemory).filter(AgentMemory.target.like("target.unique%")).delete()
    db.commit()
    
    # Crear 6 observaciones para Laravel
    for i in range(6):
        m = AgentMemory(target=f"target.unique-{i}.com", mode="hunt", key="tech_stack", value=["Laravel"])
        db.add(m)
    db.commit()
    
    engine = LearningEngine(db)
    res = engine.analyze_and_update()
    
    assert "Laravel" in res, "FALLO: No procesó stack con data suficiente"
    assert scoring_file.exists(), "FALLO: No generó el archivo scoring.yaml"
    
    # Verificar contenido
    with open(scoring_file, "r") as f:
        data = yaml.safe_load(f)
        assert data["weights"]["Laravel"]["nuclei"] == 0.9
    
    db.close()
    print("✅ Escritura Segura Scoring: OK")

if __name__ == "__main__":
    init_db()
    try:
        test_aprendizaje_respeta_min_observaciones()
        test_aprendizaje_escribe_con_data_suficiente()
        print("\n🏆 Modo APRENDIZAJE validado con las 3 restricciones core.")
    except Exception as e:
        print(f"\n❌ ERROR EN EL TEST: {e}")
        sys.exit(1)
