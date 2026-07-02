import json

def generate_mock_graph_html():
    # Estructura compatible con el formato de PromptWall v5.7
    data = {
        "nodes": [
            {"data": {"id": "root", "label": "enterprise.com", "type": "domain"}},
            {"data": {"id": "sub1", "label": "api.enterprise.com", "type": "subdomain"}},
            {"data": {"id": "sub2", "label": "vpn.enterprise.com", "type": "subdomain"}},
            {"data": {"id": "sub3", "label": "dev.enterprise.com", "type": "subdomain"}},
            {"data": {"id": "srv1", "label": "Jenkins v2.414", "type": "service"}},
            {"data": {"id": "srv2", "label": "Nginx/1.18", "type": "service"}},
            {"data": {"id": "vuln1", "label": "CRITICAL: Remote Code Execution", "type": "vulnerability"}},
            {"data": {"id": "vuln2", "label": "HIGH: S3 Bucket Exposed", "type": "vulnerability"}}
        ],
        "edges": [
            {"data": {"source": "root", "target": "sub1"}},
            {"data": {"source": "root", "target": "sub2"}},
            {"data": {"source": "root", "target": "sub3"}},
            {"data": {"source": "sub3", "target": "srv1"}},
            {"data": {"source": "sub1", "target": "srv2"}},
            {"data": {"source": "srv1", "target": "vuln1"}},
            {"data": {"source": "sub3", "target": "vuln2"}}
        ]
    }

    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>PromptWall Knowledge Graph Preview</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.26.0/cytoscape.min.js"></script>
        <style>
            body {{ background-color: #040608; color: #00d4ff; font-family: 'Segoe UI', sans-serif; margin: 0; overflow: hidden; }}
            #cy {{ width: 100vw; height: 100vh; display: block; }}
            .header {{ position: absolute; top: 20px; left: 20px; z-index: 10; pointer-events: none; }}
            .brand {{ font-size: 24px; font-weight: bold; letter-spacing: 2px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="brand">OZYRECON // KNOWLEDGE GRAPH v5.7</div>
            <div style="color: #6b7280; font-size: 12px;">Validating Attack Surface Correlations</div>
        </div>
        <div id="cy"></div>
        <script>
            var cy = cytoscape({{
                container: document.getElementById('cy'),
                elements: {json.dumps(data)},
                style: [
                    {{
                        selector: 'node',
                        style: {{
                            'background-color': '#00d4ff',
                            'label': 'data(label)',
                            'color': '#fff',
                            'font-size': '10px',
                            'text-valign': 'bottom',
                            'text-halign': 'center',
                            'width': '12px',
                            'height': '12px'
                        }}
                    }},
                    {{
                        selector: 'node[type="vulnerability"]',
                        style: {{
                            'background-color': '#ff3b5c',
                            'width': '18px',
                            'height': '18px',
                            'shape': 'diamond'
                        }}
                    }},
                    {{
                        selector: 'node[type="service"]',
                        style: {{
                            'background-color': '#00ff88',
                            'shape': 'rectangle'
                        }}
                    }},
                    {{
                        selector: 'edge',
                        style: {{
                            'width': 1,
                            'line-color': '#3d5068',
                            'curve-style': 'bezier',
                            'opacity': 0.5
                        }}
                    }}
                ],
                layout: {{
                    name: 'breadthfirst',
                    directed: true,
                    padding: 50
                }}
            }});
        </script>
    </body>
    </html>
    """
    
    with open("graph_preview.html", "w") as f:
        f.write(html_template)
    
    print("✅ Graph Preview Generated: graph_preview.html")

if __name__ == "__main__":
    generate_mock_graph_html()
