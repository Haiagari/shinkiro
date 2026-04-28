"""
Tests para la nueva arquitectura de OzyRecon v5.7
Reemplaza los tests legacy de backend/
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from src.storage.database import SessionLocal, init_db
from src.storage.models import AgentMemory, AgentLock
from src.intelligence.learning_engine import LearningEngine, MIN_OBSERVATIONS
from src.agent.config_writer import save_scoring_weights, load_effective_weights, SCORING_FILE

# Initialize DB for tests
init_db()


class TestLearningEngine:
    """Tests para src/intelligence/learning_engine.py"""

    def setup_method(self):
        """Limpia DB antes de cada test"""
        db = SessionLocal()
        db.query(AgentMemory).delete()
        db.query(AgentLock).delete()
        db.commit()
        db.close()
        # Limpiar scoring.yaml
        if SCORING_FILE.exists():
            SCORING_FILE.unlink()

    def test_min_observations_respected(self):
        """Verifica que NO escribe scoring.yaml con menos de 5 obs."""
        db = SessionLocal()
        engine = LearningEngine(db)
        
        # Crear solo 2 observaciones (menos de 5 = no debe escribir)
        target = "test-low.com"
        for i in range(2):
            mem = AgentMemory(
                target=target, mode="hunt",
                key="tech_stack", value=["WordPress"]
            )
            db.add(mem)
        db.commit()
        
        result = engine.analyze_and_update()
        
        # Con menos de 5 obs, no debería escribir scoring.yaml
        assert not SCORING_FILE.exists(), "FALLO: Creó scoring.yaml sin suficiente data"
        assert len(result) == 0
        db.close()
        print("✅ MIN_OBSERVATIONS constraint: OK")

    def test_writes_with_sufficient_data(self):
        """Verifica que SÍ actualiza con 5+ observaciones."""
        db = SessionLocal()
        engine = LearningEngine(db)
        
        # Crear 6 observaciones para Laravel
        for i in range(6):
            mem = AgentMemory(
                target=f"target-{i}.com", mode="hunt",
                key="tech_stack", value=["Laravel"]
            )
            db.add(mem)
        db.commit()
        
        result = engine.analyze_and_update()
        
        assert "Laravel" in result, "FALLO: No procesó stack con data suficiente"
        assert SCORING_FILE.exists(), "FALLO: No generó scoring.yaml"
        
        # Verificar contenido
        weights = load_effective_weights({})
        assert "Laravel" in weights
        assert weights["Laravel"]["nuclei"] == 0.9
        
        db.close()
        print("✅ Escritura Segura Scoring: OK")

    def test_acquire_lock_blocks_concurrent(self):
        """Verifica que el lock previene ejecuciones concurrentes."""
        db = SessionLocal()
        engine1 = LearningEngine(db)
        engine2 = LearningEngine(db)
        
        # Primer lock debe succeed
        assert engine1.acquire_lock("test_mode", timeout_mins=60)
        
        # Segundo lock debe fallar (lock activo)
        assert not engine2.acquire_lock("test_mode", timeout_mins=60)
        
        db.close()
        print("✅ Lock concurrente: OK")

    def test_lock_released_after_analysis(self):
        """Verifica que el lock se libera después de analizar."""
        db = SessionLocal()
        engine = LearningEngine(db)
        
        # Con datos suficientes para analizar
        for i in range(6):
            mem = AgentMemory(
                target=f"lock-test-{i}.com", mode="hunt",
                key="tech_stack", value=["NodeJS"]
            )
            db.add(mem)
        db.commit()
        
        engine.analyze_and_update()
        
        # Ahora otro engine debería poder adquirir el lock
        engine2 = LearningEngine(db)
        assert engine2.acquire_lock("aprendizaje", timeout_mins=60)
        
        db.close()
        print("✅ Lock liberado después de análisis: OK")


class TestConfigWriter:
    """Tests para src/agent/config_writer.py"""

    def setup_method(self):
        """Limpia scoring.yaml y AgentLock antes de cada test"""
        db = SessionLocal()
        db.query(AgentLock).filter(AgentLock.mode == "aprendizaje").delete()
        db.commit()
        db.close()
        if SCORING_FILE.exists():
            SCORING_FILE.unlink()

    def test_save_scoring_weights(self):
        """Verifica escritura atómica de pesos."""
        weights = {
            "WordPress": {"nuclei": 0.9, "dalfox": 0.8},
            "Laravel": {"nuclei": 0.9, "dalfox": 0.4}
        }
        save_scoring_weights(weights, confidence=0.85)
        
        assert SCORING_FILE.exists()
        loaded = load_effective_weights({})
        assert "WordPress" in loaded
        assert loaded["WordPress"]["nuclei"] == 0.9

    def test_load_effective_weights_with_file(self):
        """Verifica que load devuelve lo del archivo."""
        weights = {"Django": {"nuclei": 0.95}}
        save_scoring_weights(weights, confidence=0.9)
        
        loaded = load_effective_weights({"scoring": {"default": 0.5}})
        assert loaded["Django"]["nuclei"] == 0.95

    def test_load_effective_weights_without_file(self):
        """Verifica fallback a config default."""
        if SCORING_FILE.exists():
            SCORING_FILE.unlink()
        
        base = {"scoring": {"nuclei": 0.8}}
        loaded = load_effective_weights(base)
        assert loaded["nuclei"] == 0.8

    def test_atomic_write(self):
        """Verifica que usa write atómico (tmp + rename)."""
        weights = {"Test": {"nuclei": 1.0}}
        save_scoring_weights(weights, confidence=1.0)
        
        tmp_file = SCORING_FILE.with_suffix(".tmp")
        assert not tmp_file.exists(), "tmp file no fue eliminado"

    def test_wordpress_specific_dalfox_weight(self):
        """Verifica que WordPress tiene peso especial para dalfox."""
        db = SessionLocal()
        engine = LearningEngine(db)
        
        # Limpiar
        db.query(AgentMemory).delete()
        db.commit()
        
        # Agregar obs de WordPress
        for i in range(6):
            mem = AgentMemory(
                target=f"wp-test-{i}.com", mode="hunt",
                key="tech_stack", value=["WordPress"]
            )
            db.add(mem)
        db.commit()
        
        result = engine.analyze_and_update()
        assert "WordPress" in result
        assert result["WordPress"]["dalfox"] == 0.8  # Peso especial
        db.close()

    def test_non_wordpress_dalfox_weight(self):
        """Verifica que stacks no-WordPress tienen peso bajo para dalfox."""
        db = SessionLocal()
        engine = LearningEngine(db)
        
        # Limpiar
        db.query(AgentMemory).delete()
        db.commit()
        
        # Agregar obs de Django (no-WordPress)
        for i in range(6):
            mem = AgentMemory(
                target=f"django-test-{i}.com", mode="hunt",
                key="tech_stack", value=["Django"]
            )
            db.add(mem)
        db.commit()
        
        result = engine.analyze_and_update()
        assert "Django" in result
        assert result["Django"]["dalfox"] == 0.4  # Peso bajo
        db.close()


class TestModeIntegration:
    """Tests de integración para los modos operativos."""

    def test_hunt_mode_instantiation(self):
        """Verifica que HuntMode se puede instanciar."""
        from src.modes.hunt import HuntMode
        
        mode = HuntMode("example.com")
        assert mode.target == "example.com"
        assert mode.mode_name == "hunt"

    def test_continuous_mode_instantiation(self):
        """Verifica que ContinuousMode se puede instanciar."""
        from src.modes.continuous import ContinuousMode
        
        mode = ContinuousMode("example.com")
        assert mode.target == "example.com"
        assert mode.mode_name == "continuous"

    def test_workflow_orchestrator_import(self):
        """Verifica que el orquestador es importable."""
        from src.workflow.orchestrator import WorkflowOrchestrator
        
        orch = WorkflowOrchestrator()
        assert hasattr(orch, "validators")
        assert hasattr(orch, "process_approved")

    def test_hunt_mode_run_uses_discovered_subdomains(self):
        """Verifica que HUNT no dependa de una variable inexistente al analizar lógica."""
        from src.modes.hunt import HuntMode

        mode = HuntMode("example.com")

        with patch("src.intelligence.orchestrator.DiscoveryOrchestrator") as mock_orchestrator_cls, \
             patch("src.intelligence.intelligence.run_intelligence") as mock_run_intelligence, \
             patch("src.intelligence.logic_analyzer.LogicAnalyzer") as mock_logic_analyzer_cls, \
             patch("src.opsec.manager.OPSECManager") as mock_opsec_manager_cls, \
             patch("src.opsec.kill_switch.kill_switch.reset") as mock_kill_switch_reset:

            mock_orchestrator = MagicMock()
            mock_orchestrator.passive_discovery.return_value = ["sub1.example.com", "sub2.example.com"]
            mock_orchestrator.active_resolution.return_value = ["sub1.example.com"]
            mock_orchestrator.service_analysis.return_value = 1
            mock_orchestrator_cls.return_value = mock_orchestrator

            mock_opsec = MagicMock()
            mock_opsec.get_operational_params.return_value = {"noise": "low"}
            mock_opsec_manager_cls.return_value = mock_opsec

            mock_logic_analyzer = MagicMock()
            mock_logic_analyzer.analyze_graph.return_value = []
            mock_logic_analyzer_cls.return_value = mock_logic_analyzer

            mock_run_intelligence.return_value = {"hypotheses": []}

            result = mode.run()

            assert result["status"] == "completed"
            assert result["contract_version"] == "scan-result.v1"
            assert result["subdomains"] == 0 or isinstance(result["subdomains"], int)
            assert result["result"]["target"] == "example.com"
            assert result["result"]["mode"] == "hunt"
            assert "assets" in result["result"]
            mock_logic_analyzer.analyze_graph.assert_called()
            graph_data = mock_logic_analyzer.analyze_graph.call_args.args[0]
            assert "nodes" in graph_data
            assert len(graph_data["nodes"]) == 1
            assert graph_data["nodes"][0]["name"] == "sub1.example.com"
            mock_kill_switch_reset.assert_called_once()

    def test_scan_result_contract_version_present(self):
        """Verifica que el contrato normalizado expone una versión explícita."""
        from src.export.schema import ScanResult

        result = ScanResult()
        assert result.contract_version == "scan-result.v1"
        assert result.to_dict()["contract_version"] == "scan-result.v1"


class TestNewArchitectureImports:
    """Verifica que los módulos migrados son importables."""

    def test_learning_engine_import(self):
        """Verifica import del motor de aprendizaje."""
        from src.intelligence.learning_engine import LearningEngine
        assert LearningEngine is not None

    def test_config_writer_import(self):
        """Verifica import del config writer."""
        from src.agent.config_writer import save_scoring_weights, load_effective_weights
        assert save_scoring_weights is not None
        assert load_effective_weights is not None

    def test_intelligence_modules_exist(self):
        """Verifica que los módulos de inteligencia están."""
        from src.intelligence.learning_orchestrator import learning_orchestrator
        from src.intelligence.decision_log import log_decision
        from src.intelligence.feedback_engine import feedback_engine
        from src.intelligence.false_positive_memory import false_positive_memory
        from src.intelligence.outcome_evaluator import outcome_evaluator
        
        assert learning_orchestrator is not None
        assert feedback_engine is not None
        assert false_positive_memory is not None
