"""
Notificaciones de PromptWall
Envía alertas via Telegram y otros canales.
"""

import requests
from typing import Optional, Dict, Any

from src.core.config import config
from src.core.logging import get_logger

logger = get_logger('notifier')


def _is_placeholder(value: Optional[str], placeholders: set[str]) -> bool:
    if not value:
        return True
    normalized = value.strip()
    return normalized in placeholders or normalized.upper().startswith("TU_") or normalized.upper().startswith("YOUR_")


class Notifier:
    """
    Sistema de notificaciones multi-proveedor (v8.3.3).
    """
    
    def __init__(self):
        self.alert_level = config.get("alert_level", "info")
        self.providers = []
        
        # Telegram
        token = config.telegram_token
        chat_id = config.telegram_chat_id
        
        # Detect placeholders or empty configs
        is_telegram_configured = not (
            _is_placeholder(token, {"TU_TOKEN_DE_BOT", "BOT_TOKEN", "TELEGRAM_TOKEN"})
            or _is_placeholder(chat_id, {"TU_CHAT_ID", "CHAT_ID", "TELEGRAM_CHAT_ID"})
        )

        if is_telegram_configured:
            self.providers.append({
                "type": "telegram",
                "token": token,
                "chat_id": chat_id
            })
            
        # Slack (Stub for unification)
        slack_webhook = config.get("slack.webhook_url")
        if not _is_placeholder(slack_webhook, {"TU_WEBHOOK_DE_SLACK", "SLACK_WEBHOOK_URL", "WEBHOOK_URL"}):
            self.providers.append({
                "type": "slack",
                "webhook": slack_webhook
            })

    def is_configured(self) -> bool:
        """Verifica si algún proveedor está configurado."""
        return len(self.providers) > 0
    
    def send_message(self, message: str, parse_mode: str = "Markdown") -> bool:
        """Envía un mensaje a todos los proveedores configurados."""
        if not self.is_configured():
            # Silent skip if not configured
            return False
            
        success = False
        for provider in self.providers:
            if provider["type"] == "telegram":
                success |= self._send_telegram(provider, message, parse_mode)
            elif provider["type"] == "slack":
                success |= self._send_slack(provider, message)
        return success

    def _send_telegram(self, provider: Dict, message: str, parse_mode: str) -> bool:
        url = f"https://api.telegram.org/bot{provider['token']}/sendMessage"
        data = {
            "chat_id": provider["chat_id"],
            "text": message,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True
        }
        try:
            response = requests.post(url, json=data, timeout=10)
            if getattr(response, "status_code", 0) == 200:
                return True
            if getattr(response, "status_code", 0) in (401, 404):
                logger.debug(f"Telegram integration seems unconfigured or invalid (Status {response.status_code})")
                return False
            logger.debug(f"Telegram notification skipped (status={getattr(response, 'status_code', 'unknown')})")
            return False
        except Exception as e:
            logger.debug(f"Telegram notification skipped: {e}")
            return False

    def _send_slack(self, provider: Dict, message: str) -> bool:
        # Placeholder for Slack implementation
        logger.info(f"Slack notification stub: {message}")
        return True

    def send_to_slack(self, message: str) -> bool:
        """Shortcut for Slack."""
        slack_provider = next((p for p in self.providers if p["type"] == "slack"), None)
        if slack_provider:
            return self._send_slack(slack_provider, message)
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
        
        text = f"{icon} *PromptWall Alert*\n"
        text += f"*{title}*\n\n"
        text += f"{message}"
        
        return self.send_message(text)

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
