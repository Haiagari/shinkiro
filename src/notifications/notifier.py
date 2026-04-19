"""
Notificaciones de OzyRecon
Envía alertas via Telegram y otros canales.
"""

import requests
from typing import Optional, Dict, Any
from datetime import datetime

from src.core.config import config
from src.core.logging import get_logger
from src.export.schema import ScanResult

logger = get_logger('notifier')


class Notifier:
    """
    Sistema de notificaciones.
    Envía alertas via Telegram principalmente.
    """
    
    def __init__(self):
        self.token = config.telegram_token
        self.chat_id = config.telegram_chat_id
        self.alert_level = config.alert_level
    
    def is_configured(self) -> bool:
        """Verifica si Telegram está configurado."""
        return bool(self.token and self.chat_id)
    
    def send_message(self, message: str, parse_mode: str = "Markdown") -> bool:
        """
        Envía un mensaje por Telegram.
        
        Args:
            message: Mensaje a enviar
            parse_mode: Modo de parseo (Markdown, HTML)
        
        Returns:
            True si se envió correctamente
        """
        if not self.is_configured():
            logger.warning("Telegram not configured, skipping notification")
            return False
        
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        
        data = {
            "chat_id": self.chat_id,
            "text": message,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True
        }
        
        try:
            response = requests.post(url, json=data, timeout=10)
            response.raise_for_status()
            logger.info("Notification sent successfully")
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send notification: {e}")
            return False
    
    def send_alert(self, title: str, message: str, severity: str = "info") -> bool:
        """
        Envía una alerta.
        
        Args:
            title: Título de la alerta
            message: Cuerpo del mensaje
            severity: critical, high, medium, low, info
        
        Returns:
            True si se envió
        """
        # Filtrar por nivel de alerta
        levels = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        current_level = levels.get(self.alert_level, 4)
        alert_level = levels.get(severity, 4)
        
        if alert_level > current_level:
            logger.debug(f"Alert level {severity} filtered out (config: {self.alert_level})")
            return False
        
        # Emoji según severidad
        icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵"
        }
        
        icon = icons.get(severity, "⚪")
        
        text = f"{icon} *OzyRecon Alert*\n"
        text += f"*{title}*\n\n"
        text += f"{message}"
        
        return self.send_message(text)
    
    def send_scan_summary(self, target: str, result: ScanResult) -> bool:
        """Envía un resumen del scan."""
        stats = result.stats
        findings = result.findings
        
        # Contar por severidad
        critical = len([f for f in findings if f.severity == "critical"])
        high = len([f for f in findings if f.severity == "high"])
        medium = len([f for f in findings if f.severity == "medium"])
        
        message = f"*Scan completado: {target}*\n\n"
        message += f"*Estadísticas:*\n"
        message += f"• Subdominios: {stats.get('subdomains_found', 0)}\n"
        message += f"• Hosts vivos: {stats.get('hosts_alive', 0)}\n"
        message += f"• Puertos: {stats.get('ports_found', 0)}\n"
        message += f"• Hallazgos: {stats.get('findings', 0)}\n\n"
        
        if critical > 0 or high > 0:
            message += f"*Hallazgos críticos:* {critical}\n"
            message += f"*Hallazgos altos:* {high}\n"
        elif medium > 0:
            message += f"*Hallazgos medios:* {medium}\n"
        
        severity = "critical" if critical > 0 else "high" if high > 0 else "medium" if medium > 0 else "info"
        
        return self.send_alert(f"Scan completado: {target}", message, severity)
    
    def send_finding(self, target: str, finding: Dict[str, Any]) -> bool:
        """Envía notificación de un finding."""
        severity = finding.get("severity", "info")
        
        message = f"*Nuevo hallazgo en {target}*\n\n"
        message += f"• **{finding.get('name', 'Unknown')}**\n"
        message += f"Severidad: {severity.upper()}\n"
        
        if finding.get("url"):
            message += f"URL: {finding['url']}\n"
        
        if finding.get("description"):
            desc = finding["description"][:200]
            message += f"Descripción: {desc}...\n"
        
        return self.send_alert(f"Nuevo finding: {finding.get('name')}", message, severity)
    
    def send_error(self, target: str, error: str) -> bool:
        """Envía notificación de error."""
        message = f"*Error en scan de {target}*\n\n"
        message += f"```\n{error}\n```"
        
        return self.send_alert("Error de scan", message, "high")


# Instancia global
notifier = Notifier()


def send_notification(title: str, message: str, severity: str = "info") -> bool:
    """Función de conveniencia."""
    return notifier.send_alert(title, message, severity)