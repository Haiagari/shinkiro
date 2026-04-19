"""
Modo SERVICIO - Reportes Ejecutivos
Genera reportes profesionales para clientes.
"""

import uuid
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path

from src.core.config import config
from src.core.logging import get_logger
from src.core.context import ScanContext, set_context
from src.storage.database import SessionLocal, init_db
from src.storage.queries import DBQueries
from src.export.normalizer import NormalizedExporter

logger = get_logger('mode_service')


class ServiceMode:
    """
    Modo SERVICIO - Reportes Ejecutivos
    
    Objetivo: Generar reportes profesionales para clientes.
    
    Genera:
    - Resumen ejecutivo
    - Hallazgos por severidad
    - Gráficos y métricas
    - Recomendaciones
    """
    
    def __init__(self, target: str, client_name: str = "", options: Optional[Dict[str, Any]] = None):
        self.target = target
        self.client_name = client_name or target
        self.options = options or {}
        self.session_id = str(uuid.uuid4())
        
        self.context = ScanContext(
            session_id=self.session_id,
            target=target,
            mode="servicio"
        )
        set_context(self.context)
        
        self.db = None
        self.exporter = None
    
    def run(self) -> Dict[str, Any]:
        """Genera el reporte de servicio."""
        logger.info(f"[SERVICIO] Generating report for {self.target}")
        self.context.mark_running()
        
        try:
            init_db()
            db_session = SessionLocal()
            self.db = DBQueries(db_session)
            self.exporter = NormalizedExporter(db_session)
            
            # Obtener datos
            target = self.db.get_target(self.target)
            if not target:
                return {'status': 'error', 'message': 'Target not found'}
            
            scans = self.db.get_scans_for_target(self.target, limit=10)
            all_findings = self.db.get_all_findings(self.target)
            stats = self.db.get_target_stats(self.target)
            
            # Generar reporte
            report = self._generate_report(target, scans, all_findings, stats)
            
            # Guardar
            output_dir = Path(__file__).resolve().parents[3] / "runtime" / "exports" / self.target
            output_dir.mkdir(parents=True, exist_ok=True)
            
            report_file = output_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            with open(report_file, 'w') as f:
                f.write(report)
            
            self.context.mark_completed()
            
            return {
                'session_id': self.session_id,
                'target': self.target,
                'status': 'completed',
                'report_file': str(report_file),
                'total_findings': len(all_findings),
                'critical': len([f for f in all_findings if f.severity == 'critical']),
                'high': len([f for f in all_findings if f.severity == 'high'])
            }
            
        except Exception as e:
            logger.exception(f"[SERVICIO] Error: {e}")
            self.context.mark_failed(str(e))
            return {'status': 'failed', 'error': str(e)}
    
    def _generate_report(self, target, scans, findings, stats) -> str:
        """Genera el reporte en Markdown."""
        report = []
        
        # Header
        report.append(f"# Reporte de Seguridad")
        report.append(f"## {self.client_name}")
        report.append(f"")
        report.append(f"**Fecha:** {datetime.now().strftime('%Y-%m-%d')}")
        report.append(f"**Target:** {self.target}")
        report.append(f"")
        
        # Resumen Ejecutivo
        report.append("## Resumen Ejecutivo")
        report.append(f"")
        report.append(f"Se realizó una auditoría de seguridad en el dominio {self.target}.")
        report.append(f"Se identificaron **{len(findings)} hallazgos** en total.")
        report.append(f"")
        
        # Métricas
        critical = len([f for f in findings if f.severity == 'critical'])
        high = len([f for f in findings if f.severity == 'high'])
        medium = len([f for f in findings if f.severity == 'medium'])
        low = len([f for f in findings if f.severity == 'low'])
        
        report.append("### Métricas de Seguridad")
        report.append(f"")
        report.append(f"| Severidad | Cantidad |")
        report.append(f"|-----------|----------|")
        report.append(f"| 🔴 Crítica | {critical} |")
        report.append(f"| 🟠 Alta | {high} |")
        report.append(f"| 🟡 Media | {medium} |")
        report.append(f"| 🟢 Baja | {low} |")
        report.append(f"")
        
        # Hallazgos detallados
        if findings:
            report.append("## Hallazgos")
            report.append(f"")
            
            for finding in findings:
                icon = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🟢'
                }.get(finding.severity, '⚪')
                
                report.append(f"### {icon} {finding.name}")
                report.append(f"")
                report.append(f"**Severidad:** {finding.severity.upper()}")
                report.append(f"**Ubicación:** {finding.host or self.target}")
                if finding.path:
                    report.append(f"**Ruta:** {finding.path}")
                report.append(f"")
                
                if finding.description:
                    report.append(f"**Descripción:**")
                    report.append(f"{finding.description}")
                    report.append(f"")
        
        # Recomendaciones
        report.append("## Recomendaciones")
        report.append(f"")
        
        if critical > 0:
            report.append("### Acciones Prioritarias")
            report.append(f"- Corregir inmediatamente las vulnerabilidades críticas identificadas")
            report.append(f"- Implementar controles de acceso adecuados")
            report.append(f"- Revisar configuraciones de seguridad")
            report.append(f"")
        
        report.append("### Mejores Prácticas")
        report.append(f"- Mantener sistemas y dependencias actualizados")
        report.append(f"- Implementar escaneos periódicos de seguridad")
        report.append(f"- Capacitar al equipo en seguridad")
        report.append(f"")
        
        # Footer
        report.append("---")
        report.append(f"*Reporte generado por OzyRecon*")
        
        return "\n".join(report)


def run_servicio(target: str, client_name: str = "", **options) -> Dict[str, Any]:
    """Función de conveniencia para modo Servicio."""
    mode = ServiceMode(target, client_name, options)
    return mode.run()