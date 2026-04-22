"""
Telegram Notification Provider para OzyRecon
Integración limpia con el sistema de mensajería.
"""

import requests
from src.core.logging import get_logger
from src.core.config import config

logger = get_logger('notifications.telegram')

class TelegramNotifier:
    """Gestiona el envío de alertas a Telegram."""
    
    def __init__(self):
        self.token = config.notifications.get("telegram_token")
        self.chat_id = config.notifications.get("telegram_chat_id")
        self.enabled = bool(self.token and self.chat_id)

    def send_message(self, text: str):
        """Envía un mensaje formateado."""
        if not self.enabled:
            logger.debug("Telegram not configured, skipping message")
            return False

        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown"
        }

        try:
            res = requests.post(url, json=payload, timeout=10)
            if res.status_code == 200:
                logger.info("Alert sent to Telegram")
                return True
            else:
                logger.error(f"Telegram API error: {res.text}")
                return False
        except Exception as e:
            logger.error(f"Error sending Telegram alert: {e}")
            return False

    def notify_diff(self, target: str, diff_report):
        """Envía una alerta específica de cambios detectados."""
        if not diff_report.has_changes():
            return

        msg = [
            f"🎯 *{target}* - *Surface Change Detected*",
            "",
            f"✨ *Novedades:*",
        ]
        
        if diff_report.new_subdomains:
            msg.append(f"• 🌐 `{len(diff_report.new_subdomains)}` nuevos subdominios")
            for sub in diff_report.new_subdomains[:5]:
                msg.append(f"  └ `{sub}`")
        
        if diff_report.new_ports:
            msg.append(f"• 🔌 `{len(diff_report.new_ports)}` puertos nuevos")
            
        if diff_report.changed_services:
            msg.append(f"• 🔄 `{len(diff_report.changed_services)}` servicios actualizados")

        msg.append(f"\n🚀 *OzyRecon v4.0*")
        
        return self.send_message("\n".join(msg))

# Instancia global
notifier = TelegramNotifier()
