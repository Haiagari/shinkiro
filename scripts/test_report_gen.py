import os

def generate_test_report():
    report_path = "test_report.html"
    
    # Datos de prueba simulando un hallazgo real de OzyRecon v5.7
    findings = [
        {
            "id": "VAL-2026-001",
            "name": "Exposed Cloud Storage (S3 Bucket)",
            "severity": "CRITICAL",
            "confidence": "98%",
            "description": "Sensitive backup files found in a misconfigured S3 bucket with public read access.",
            "evidence_hash": "sha256:7f83b1657ff1...8a2f1c9",
            "recommendation": "Restrict bucket access to authorized IAM roles only."
        },
        {
            "id": "VAL-2026-002",
            "name": "Legacy API Endpoint (No Auth)",
            "severity": "HIGH",
            "confidence": "92%",
            "description": "Internal management endpoint /api/v1/debug found exposed through a misconfigured Nginx proxy.",
            "evidence_hash": "sha256:a1b2c3d4e5f6...g7h8i9j0",
            "recommendation": "Implement JWT authentication and restrict access by IP."
        }
    ]

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OzyRecon Executive Report - Test</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0a0f1a; color: #e0e0e0; line-height: 1.6; padding: 40px; }}
            .container {{ max-width: 900px; margin: auto; background: #161b22; padding: 30px; border-radius: 12px; border: 1px solid #30363d; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
            h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }}
            .summary {{ display: flex; justify-content: space-between; margin-bottom: 40px; background: #0d1117; padding: 20px; border-radius: 8px; }}
            .stat {{ text-align: center; }}
            .stat-value {{ font-size: 24px; font-weight: bold; color: #00ff88; }}
            .finding {{ background: #21262d; border-radius: 8px; padding: 20px; margin-bottom: 20px; border-left: 5px solid #f85149; }}
            .severity-HIGH {{ border-left-color: #f0883e; }}
            .severity-CRITICAL {{ border-left-color: #f85149; }}
            .finding-header {{ display: flex; justify-content: space-between; align-items: center; }}
            .badge {{ padding: 5px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; text-transform: uppercase; }}
            .badge-critical {{ background: #f85149; color: white; }}
            .badge-high {{ background: #f0883e; color: white; }}
            .evidence {{ font-family: 'Courier New', Courier, monospace; background: #0d1117; padding: 10px; border-radius: 4px; font-size: 13px; color: #8b949e; overflow-x: auto; }}
            .footer {{ text-align: center; margin-top: 50px; font-size: 12px; color: #8b949e; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🧠 OzyRecon Executive Intelligence</h1>
            <p><strong>Target:</strong> enterprise-target.com | <strong>Date:</strong> April 24, 2026</p>
            
            <div class="summary">
                <div class="stat"><div class="stat-value">152</div><div>Targets Scanned</div></div>
                <div class="stat"><div class="stat-value">2</div><div>Validated Risks</div></div>
                <div class="stat"><div class="stat-value">97%</div><div>Accuracy</div></div>
            </div>

            <h2>Validated Findings</h2>
    """

    for f in findings:
        badge_class = "badge-critical" if f["severity"] == "CRITICAL" else "badge-high"
        html_content += f"""
            <div class="finding severity-{f["severity"]}">
                <div class="finding-header">
                    <h3>{f["name"]}</h3>
                    <span class="badge {badge_class}">{f["severity"]}</span>
                </div>
                <p>{f["description"]}</p>
                <p><strong>Recommendation:</strong> {f["recommendation"]}</p>
                <div class="evidence">
                    <strong>Integrity Hash (SHA256):</strong> {f["evidence_hash"]}<br>
                    <strong>Confidence:</strong> {f["confidence"]}
                </div>
            </div>
        """

    html_content += """
            <div class="footer">
                Built with ❤️ by OzyRecon v5.7 - Verified Security Intelligence
            </div>
        </div>
    </body>
    </html>
    """

    with open(report_path, "w") as f:
        f.write(html_content)
    
    print(f"✅ Test Report generated: {os.path.abspath(report_path)}")

if __name__ == "__main__":
    generate_test_report()
