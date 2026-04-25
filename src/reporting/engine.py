import os
import json
from datetime import datetime

class ReportEngine:
    def __init__(self, template_path="resources/reports/template_v2.html"):
        self.template_path = template_path
        self.output_dir = "reports"
        os.makedirs(self.output_dir, exist_ok=True)

    def generate(self, target, findings):
        """
        Genera un reporte profesional basado en los hallazgos validados.
        """
        if not os.path.exists(self.template_path):
            raise FileNotFoundError(f"Template not found at {self.template_path}")

        with open(self.template_path, "r") as f:
            template_content = f.read()

        # Inyectar data básica
        report_date = datetime.now().strftime("%B %d, %Y — %H:%M UTC")
        template_content = template_content.replace("enterprise-target.com", target)
        template_content = template_content.replace("April 25, 2026 — 00:34 UTC", report_date)

        # Aquí iría la lógica para construir dinámicamente el sidebar y las tarjetas de findings
        # Por ahora, como es un test de Step 4, vamos a guardar el archivo listo para usar.
        
        output_file = os.path.join(self.output_dir, f"report_{target.replace('.', '_')}.html")
        with open(output_file, "w") as f:
            f.write(template_content)

        return os.path.abspath(output_file)

if __name__ == "__main__":
    # Test rápido del motor
    engine = ReportEngine()
    try:
        path = engine.generate("test_target.com", [])
        print(f"✅ Professional Report Generated: {path}")
    except Exception as e:
        print(f"❌ Error generating report: {e}")
