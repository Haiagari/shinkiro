import os
from datetime import datetime

class ReportEngine:
    """
    ReportEngine Básico - v5.7 Legacy Mode
    Simplemente guarda el reporte generado sin lógica de inteligencia v6.0.
    """
    def __init__(self, template_path="resources/reports/template_v2.html"):
        self.template_path = template_path
        self.output_dir = "reports"
        os.makedirs(self.output_dir, exist_ok=True)

    def generate(self, target, findings, v6_context=None):
        if not os.path.exists(self.template_path):
            return "Template Error"

        with open(self.template_path, "r") as f:
            content = f.read()

        report_date = datetime.now().strftime("%B %d, %Y")
        content = content.replace("{{TARGET}}", target)
        content = content.replace("{{DATE}}", report_date)
        
        # Inyección minimalista para no romper nada
        content = content.replace("<!-- EXECUTIVE_SUMMARY -->", "<p>Reporte generado por OzyRecon.</p>")
        content = content.replace("{{FINDINGS}}", f"<p>Hallazgos detectados: {len(findings)}</p>")

        output_file = os.path.join(self.output_dir, f"report_{target.replace('.', '_')}.html")
        with open(output_file, "w") as f:
            f.write(content)

        return os.path.abspath(output_file)
