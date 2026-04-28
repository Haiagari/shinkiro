# OzyRecon Reporting Templates

This directory contains the modular Jinja2 templates used by the `Jinja2ReportEngine` to generate dynamic reports.

## Structure

```text
templates/
├── base.j2             # Base HTML5 boilerplate and global styles
├── layouts/
│   └── report.j2       # Main report layout (extends base.j2)
└── partials/           # Reusable components
    ├── summary.j2      # Executive summary section
    ├── findings.j2     # Grouped findings table
    ├── scoring.j2      # Top 5 Critical Assets
    ├── attack_paths.j2 # Attack path visualizations
    └── charts.j2       # Chart.js canvas elements
```

## Customization

To customize the report look and feel:

1.  **CSS**: Edit `resources/reports/static/style.css`.
2.  **Layout**: Modify `templates/layouts/report.j2`.
3.  **Sections**: Add or remove partials and update the layout to include them.

## Jinja2 Context

The following data is available in the template context:

- `scan_info`: Metadata about the target and scan time.
- `findings`: Findings grouped by severity (`critical`, `high`, `medium`, `low`).
- `scoring`: Top 5 priority assets.
- `attack_paths`: Hypothesized attack vectors.
- `summary`: Statistics and risk scores.
- `charts`: Configuration for Chart.js.
