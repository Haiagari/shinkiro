"""
PDF Export Module.
Converts professional markdown reports to PDF using WeasyPrint.
"""

import re
from pathlib import Path
from datetime import datetime

try:
    from weasyprint import HTML
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False


CSS_STYLE = """
@page {
    size: A4;
    margin: 2cm;
    @bottom-right {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 9pt;
        color: #888;
        font-family: 'DejaVu Sans Mono', monospace;
    }
}

body {
    font-family: 'DejaVu Sans Mono', 'Courier New', monospace;
    font-size: 10pt;
    line-height: 1.6;
    color: #1a1a1a;
    counter-reset: finding;
}

h1 {
    font-size: 20pt;
    border-bottom: 3px solid #c00;
    padding-bottom: 8px;
    color: #8b0000;
    margin-top: 0;
    page-break-before: avoid;
}

h2 {
    font-size: 15pt;
    border-bottom: 2px solid #ddd;
    padding-bottom: 5px;
    color: #222;
    margin-top: 30px;
    page-break-after: avoid;
}

h3 {
    font-size: 12pt;
    color: #333;
    margin-top: 25px;
    page-break-after: avoid;
}

h4 {
    font-size: 11pt;
    color: #444;
    margin-top: 15px;
}

p {
    margin: 8px 0;
    text-align: justify;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0;
    font-size: 9pt;
    page-break-inside: avoid;
}

th, td {
    border: 1px solid #ccc;
    padding: 7px 10px;
    text-align: left;
    vertical-align: top;
}

th {
    background: #2c3e50;
    color: white;
    font-weight: bold;
    font-size: 9pt;
}

tr:nth-child(even) td {
    background: #f8f9fa;
}

tr:nth-child(odd) td {
    background: #ffffff;
}

code {
    background: #f0f0f0;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 9pt;
    font-family: 'DejaVu Sans Mono', monospace;
}

pre {
    background: #1e1e1e;
    border: 1px solid #333;
    padding: 12px;
    border-radius: 5px;
    font-size: 8pt;
    color: #d4d4d4;
    overflow-x: auto;
    page-break-inside: avoid;
    line-height: 1.4;
}

blockquote {
    border-left: 4px solid #c00;
    padding: 8px 12px;
    margin: 15px 0;
    background: #fff5f5;
    color: #555;
    font-style: italic;
}

img {
    max-width: 100%;
    height: auto;
    display: block;
    margin: 15px auto;
    border: 1px solid #ddd;
    border-radius: 4px;
    page-break-inside: avoid;
}

ul, ol {
    margin: 8px 0;
    padding-left: 25px;
}

li {
    margin: 4px 0;
}

hr {
    border: none;
    border-top: 1px solid #ddd;
    margin: 25px 0;
}

.finding-severity {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 3px;
    font-weight: bold;
    font-size: 10pt;
    letter-spacing: 0.5px;
}

.critical {
    background: #dc3545;
    color: white;
}

.high {
    background: #fd7e14;
    color: white;
}

.medium {
    background: #ffc107;
    color: #333;
}

.low {
    background: #17a2b8;
    color: white;
}

.info {
    background: #6c757d;
    color: white;
}

.finding-separator {
    border: none;
    border-top: 2px solid #c00;
    margin: 30px 0;
}

.section-break {
    page-break-before: always;
}

.footer {
    margin-top: 40px;
    padding-top: 15px;
    border-top: 2px solid #ddd;
    font-size: 8pt;
    color: #999;
    text-align: center;
}

.figure-caption {
    font-size: 9pt;
    color: #666;
    text-align: center;
    font-style: italic;
    margin-top: -10px;
    margin-bottom: 15px;
}

.risk-critical {
    color: #dc3545;
    font-weight: bold;
}

.risk-high {
    color: #fd7e14;
    font-weight: bold;
}

.risk-medium {
    color: #e6a800;
    font-weight: bold;
}

.findings-summary-table td:first-child {
    font-weight: bold;
}
"""


RE_SEVERITY = re.compile(r'(CRITICAL|HIGH|MEDIUM|LOW|INFO)')
RE_IMAGE = re.compile(r'!\[([^\]]*)\]\(([^)]+)\)')
RE_LINK = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')
RE_BOLD = re.compile(r'\*\*([^*]+)\*\*')
RE_ITALIC = re.compile(r'\*([^*]+)\*')
RE_CODE_INLINE = re.compile(r'`([^`]+)`')


def _render_inline(text: str) -> str:
    text = RE_BOLD.sub(r'<strong>\1</strong>', text)
    text = RE_ITALIC.sub(r'<em>\1</em>', text)
    text = RE_CODE_INLINE.sub(r'<code>\1</code>', text)
    text = RE_LINK.sub(r'<a href="\2">\1</a>', text)
    return text


def _severity_badge(text: str) -> str:
    """Wrap severity text in a styled badge span."""
    def _replace(m: re.Match) -> str:
        sev = m.group(1).lower()
        return f'<span class="finding-severity {sev}">{m.group(1)}</span>'
    # Only match severity words NOT already inside an HTML tag
    result = []
    last_end = 0
    for m in RE_SEVERITY.finditer(text):
        pos = m.start()
        # Check if this match is inside an HTML tag
        before = text[last_end:pos]
        open_tags = before.count("<")
        close_tags = before.count(">")
        if open_tags <= close_tags:
            result.append(before)
            result.append(_replace(m))
        else:
            result.append(before + m.group(0))
        last_end = m.end()
    result.append(text[last_end:])
    return "".join(result)


def _render_text(text: str) -> str:
    """Render markdown inline formatting and apply severity badges."""
    badged = _severity_badge(text)
    return _render_inline(badged)


def md_simple_to_html(md_text: str) -> str:
    lines = md_text.split("\n")
    html_parts = []
    in_table = False
    in_code = False
    in_list = False
    in_olist = False
    table_header = False

    for line in lines:
        if line.startswith("```"):
            if in_code:
                html_parts.append("</pre>\n")
                in_code = False
            else:
                html_parts.append("<pre>")
                in_code = True
            continue

        if in_code:
            html_parts.append(line + "\n")
            continue

        stripped = line.strip()

        if not stripped:
            if in_table:
                html_parts.append("</tbody></table>\n")
                in_table = False
                table_header = False
            if in_list:
                html_parts.append("</ul>\n")
                in_list = False
            if in_olist:
                html_parts.append("</ol>\n")
                in_olist = False
            html_parts.append("<br>\n")
            continue

        # Images
        img_match = RE_IMAGE.search(stripped)
        if img_match:
            alt_text = img_match.group(1)
            src = img_match.group(2)
            html_parts.append(f'<img src="{src}" alt="{alt_text}">\n')
            if alt_text:
                html_parts.append(f'<div class="figure-caption">{alt_text}</div>\n')
            continue

        # Headers
        if stripped.startswith("#### "):
            html_parts.append(f"<h4>{_render_text(stripped[5:])}</h4>\n")
        elif stripped.startswith("### "):
            html_parts.append(f"<h3>{_render_text(stripped[4:])}</h3>\n")
        elif stripped.startswith("## "):
            html_parts.append(f"<h2>{_render_text(stripped[3:])}</h2>\n")
        elif stripped.startswith("# "):
            html_parts.append(f"<h1>{_render_text(stripped[2:])}</h1>\n")
        elif stripped.startswith("|") and stripped.endswith("|"):
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            if not in_table:
                html_parts.append("<table>\n<thead>\n<tr>")
                for c in cells:
                    html_parts.append(f"<th>{_render_text(c)}</th>")
                html_parts.append("</tr>\n</thead>\n<tbody>\n")
                in_table = True
                table_header = True
            elif table_header and all(re.match(r'^:?-+:?$', c) for c in cells):
                table_header = False
                continue
            else:
                table_header = False
                html_parts.append("<tr>")
                for c in cells:
                    html_parts.append(f"<td>{_render_text(c)}</td>")
                html_parts.append("</tr>\n")
        elif stripped.startswith("- "):
            if in_olist:
                html_parts.append("</ol>\n")
                in_olist = False
            if not in_list:
                html_parts.append("<ul>\n")
                in_list = True
            html_parts.append(f"<li>{_render_text(stripped[2:])}</li>\n")
        elif stripped.startswith("1. ") or stripped.startswith("2. ") or stripped.startswith("3. "):
            if in_list:
                html_parts.append("</ul>\n")
                in_list = False
            if not in_olist:
                html_parts.append("<ol>\n")
                in_olist = True
            html_parts.append(f"<li>{_render_text(stripped[3:])}</li>\n")
        elif stripped.startswith("---"):
            html_parts.append('<hr class="finding-separator">\n')
        else:
            html_parts.append(f"<p>{_render_text(stripped)}</p>\n")

    if in_table:
        html_parts.append("</tbody></table>\n")
    if in_list:
        html_parts.append("</ul>\n")
    if in_olist:
        html_parts.append("</ol>\n")
    if in_code:
        html_parts.append("</pre>\n")

    return "".join(html_parts)


def generate_pdf(markdown_path: Path, output_path: Path) -> Path:
    if not HAS_WEASYPRINT:
        raise RuntimeError("WeasyPrint not installed. Install with: pip install weasyprint")

    md_content = markdown_path.read_text()
    html_body = md_simple_to_html(md_content)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>{CSS_STYLE}</style>
</head>
<body>
{html_body}
<div class="footer">
<p><strong>CONFIDENTIAL — For Authorized Recipients Only</strong></p>
<p><em>Security Assessment conducted by PromptWall v9.0.1 + OzyBounty</em></p>
<p><em>Date: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}</em></p>
</div>
</body>
</html>"""

    output_path = output_path.with_suffix(".pdf")
    HTML(string=html).write_pdf(str(output_path))
    return output_path
