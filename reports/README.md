# Reports

- `generated/` — Output directory for newly generated reports (.md + .pdf)
- `archive/` — Historical generated reports (old format, kept for reference)
- `evidence/` — Captured evidence (HTTP responses + gowitness screenshots)
  - `evidence/http/` — JSON evidence from HTTP requests
  - `evidence/screenshots/` — Gowitness PNG screenshots by target
- `reales/` — Real scan session data (gitignored)
- `pruebas/` — Sample/test scan sessions

## Generate a new report

```python
from src.reporting import ProfessionalReport, generate_pdf
from pathlib import Path

report = ProfessionalReport(
    workspace_path=Path("path/to/workspace.json"),
    target="target.tld",
    screenshots_dir=Path("reports/evidence/screenshots/unitru"),
    diagram_path=Path("docs/diagrams/attack-surface.png"),
)
md_path = report.save(Path("reports/generated/report.md"))
pdf_path = generate_pdf(md_path, Path("reports/generated/report.pdf"))
```
