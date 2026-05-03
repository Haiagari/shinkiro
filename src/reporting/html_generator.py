"""
OzyRecon Professional HTML Report Generator
Generates a standalone, beautiful HTML report for the target.
"""

import json
from pathlib import Path
from datetime import datetime
from src.core.runtime_paths import get_runtime_root

class HTMLReportGenerator:
    """
    Generates an elite security report.
    """
    
    TEMPLATE = """
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>OzyRecon Elite Report - {target}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f1f5f9; padding: 40px; }}
            .container {{ max-width: 1200px; margin: auto; }}
            h1 {{ color: #38bdf8; border-bottom: 2px solid #38bdf8; padding-bottom: 10px; }}
            .card {{ background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #334155; }}
            .severity-high {{ border-left: 5px solid #ef4444; }}
            .severity-medium {{ border-left: 5px solid #f59e0b; }}
            .tag {{ background: #334155; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; margin-right: 5px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; }}
            th {{ background: #0f172a; color: #38bdf8; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>OzyRecon Tactical Intelligence Report</h1>
            <p><strong>Target:</strong> {target} | <strong>Date:</strong> {date}</p>
            
            <div class="card">
                <h2>Executive Summary</h2>
                <p>{summary}</p>
            </div>

            <div class="card severity-high">
                <h2>Critical Findings</h2>
                <table>
                    <tr><th>Type</th><th>Source</th><th>Impact</th></tr>
                    {findings}
                </table>
            </div>

            <div class="card">
                <h2>Cloud Infrastructure</h2>
                {cloud_data}
            </div>

            <footer style="text-align: center; margin-top: 50px; opacity: 0.5;">
                Generado por OzyRecon v9.0 - Elite Edition
            </footer>
        </div>
    </body>
    </html>
    """

    def generate(self, target: str, data: dict):
        """Generates the HTML file."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        
        # Format findings table
        findings_html = ""
        for f in data.get('findings', []):
            findings_html += f"<tr><td>{f['type']}</td><td>{f['source']}</td><td>{f['impact']}</td></tr>"
            
        # Format cloud data
        cloud_html = "<ul>"
        for b in data.get('cloud_buckets', []):
            cloud_html += f"<li>[{b['provider']}] {b['url']} - <strong>{b['status']}</strong></li>"
        cloud_html += "</ul>"

        report_content = self.TEMPLATE.format(
            target=target,
            date=now,
            summary=data.get('summary', 'Análisis completado exitosamente.'),
            findings=findings_html,
            cloud_data=cloud_html
        )
        
        report_path = get_runtime_root() / f"reports/report_{target}_{datetime.now().strftime('%Y%m%d')}.html"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)
            
        return str(report_path)

# Global Instance
report_generator = HTMLReportGenerator()
