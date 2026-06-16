"""
Exporta resultados de OzyRecon al formato que OzyBounty espera.
Uso: python scripts/export_for_ozybounty.py <target> [--output DIR]

Genera:
  manifest.json   — metadatos + scope domains
  assets.json     — todos los subdominios/activos descubiertos
  endpoints.json  — servicios y puertos como endpoints
  signals.json    — señales clasificadas desde tecnologías + labels
"""

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from sqlalchemy import create_engine, text

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.storage.database import DB_PATH


TECH_SIGNALS = {
    'Express': ('nodejs_express', 'Express.js endpoint — probar rutas y middleware'),
    'Nginx': ('nginx_version', 'Nginx detectado — verificar versión y config'),
    'Apache': ('apache_version', 'Apache detectado — verificar versión y config'),
    'PHP': ('php_version', 'PHP detectado — buscar phpinfo, debug endpoints'),
    'WordPress': ('wordpress_detected', 'WordPress — enumerar plugins, users, wp-config'),
    'Joomla': ('joomla_detected', 'Joomla — enumerar extensiones, config'),
    'Moodle': ('moodle_detected', 'Moodle — enumerar plugins, users'),
    'Laravel': ('laravel_detected', 'Laravel — debug mode, env file, routes'),
    'Django': ('django_detected', 'Django — admin panel, debug mode, SECRET_KEY'),
    'Next.js': ('nextjs_detected', 'Next.js — SSRF routes, API endpoints, source maps'),
    'React': ('react_detected', 'React — source maps, API calls in JS, env vars'),
    'Node.js': ('nodejs_detected', 'Node.js — check for debug endpoints, .env exposure'),
    'Docker': ('docker_detected', 'Docker — registry API, container escape vectors'),
    'Kubernetes': ('k8s_detected', 'Kubernetes — etcd, dashboard, kubelet API'),
    'Grafana': ('grafana_detected', 'Grafana — anonymous access, datasource config'),
    'Jenkins': ('jenkins_detected', 'Jenkins — script console, /api/json, creds exposure'),
    'S3': ('s3_bucket', 'S3 bucket — list objects, check public access, CORS'),
    'CloudFront': ('cloudfront_distribution', 'CloudFront — origin exposure, misconfigs'),
    'Nginx:1.28.0': ('nginx_1_28_0', 'Nginx 1.28.0 — check for CVEs in this version'),
}

LABEL_SIGNALS = {
    'api_surface': ('api_endpoint', 'API endpoint sin autenticación visible'),
    'role:api': ('api_service', 'Servicio API — probar endpoints, auth, rate limiting'),
    'gate_admin': ('admin_panel', 'Panel de administración — probar creds default, auth bypass'),
    'role:management': ('management_console', 'Consola de gestión — verificar acceso no autorizado'),
    'gate_auth': ('auth_endpoint', 'Endpoint de autenticación — probar bruteforce, default creds'),
    'role:auth': ('auth_service', 'Servicio de autenticación — OAuth misconfig, session handling'),
    'non_prod_env': ('staging_environment', 'Entorno no-producción — puede tener datos reales, debug enabled'),
    'static_asset': ('static_asset_hosting', 'Hosting de assets estáticos — directory listing, CORS'),
    'data_storage': ('data_storage', 'Almacenamiento de datos — verificar exposición, permisos'),
    'leaked_data_surface': ('data_exposure', 'Posible fuga de datos — investigar contenido'),
    'role:commerce': ('ecommerce_endpoint', 'Endpoint de comercio — probar IDOR, price manipulation'),
    'role:development': ('dev_environment', 'Entorno dev — debug enabled, creds hardcodeadas'),
}

_TECH_PATTERNS = [
    (kind, desc, re.compile(rf'\b{re.escape(key)}\b', re.IGNORECASE))
    for key, (kind, desc) in TECH_SIGNALS.items()
]


def extract_domain(name: str) -> str:
    name = name.strip().lower()
    if '/' in name:
        name = name.rsplit('/', 1)[-1]
    return name


def _build_domain_filter(target: str) -> tuple[str, str]:
    if '*' in target:
        wild_pattern = target.replace('*', '%')
        exact = target.replace('*.', '').lstrip('.')
    else:
        wild_pattern = f'%.{target}'
        exact = target
    return exact, wild_pattern


def _build_in_scope(target: str) -> list[str]:
    if target.startswith('*.'):
        bare = target[2:]
        return [target, bare]
    parts = target.replace('*.', '').split('.')
    if len(parts) >= 3:
        return [target]
    return [f'*.{target}', target]


def _write_atomic(output_dir: Path, files: dict[str, str]) -> None:
    tmp_dir = Path(tempfile.mkdtemp(dir=output_dir.parent))
    try:
        for name, content in files.items():
            (tmp_dir / name).write_text(content)
        for name in files:
            os.replace(str(tmp_dir / name), str(output_dir / name))
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def export(target: str, output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)

    exact, wild_pattern = _build_domain_filter(target)

    engine_db = None
    try:
        engine_db = create_engine(f'sqlite:///{DB_PATH}')
        with engine_db.connect() as conn:
            rows = conn.execute(text("""
                SELECT domain, ip, http_status, title, technologies, cloud_provider, asn_organization, semantic_labels, is_live
                FROM subdomains WHERE domain = :exact OR domain LIKE :wild
            """), {'exact': exact, 'wild': wild_pattern}).fetchall()

            ports_data = conn.execute(text("""
                SELECT host, port, protocol, service, version, state
                FROM ports WHERE host = :exact OR host LIKE :wild
            """), {'exact': exact, 'wild': wild_pattern}).fetchall()
    finally:
        if engine_db:
            engine_db.dispose()

    # --- Assets (keep best row per domain: prefer live, then latest) ---
    assets = []
    best_rows = {}
    for r in rows:
        domain = r[0]
        if domain not in best_rows:
            best_rows[domain] = r
        elif r[8] and not best_rows[domain][8]:
            best_rows[domain] = r

    for r in best_rows.values():
        domain = r[0]
        techs = json.loads(r[4]) if r[4] else []
        labels = json.loads(r[7]) if r[7] else []

        notes_parts = []
        if r[3]:
            notes_parts.append(f'title="{r[3][:60]}"')
        if r[5]:
            notes_parts.append(f'cloud={r[5]}')
        if r[6]:
            notes_parts.append(f'asn={r[6][:40]}')
        if techs:
            notes_parts.append(f'tech={",".join(techs[:5])}')

        assets.append({
            'name': domain,
            'kind': 'subdomain',
            'host': domain,
            'ip': r[1] or '',
            'http_status': r[2],
            'title': r[3] or '',
            'technologies': techs,
            'cloud': r[5] or '',
            'asn': r[6] or '',
            'labels': labels,
            'is_live': bool(r[8]),
            'notes': ' | '.join(notes_parts),
        })

    # --- Endpoints from port scan ---
    endpoints = []
    seen_endpoints = set()
    for r in ports_data:
        host = r[0]
        port = r[1]
        key = f'{host}:{port}'
        if key in seen_endpoints:
            continue
        seen_endpoints.add(key)
        endpoints.append({
            'host': host,
            'method': 'GET',
            'path': f'/{port}',
            'notes': f'{r[3] or "unknown"} {r[4] or ""} state={r[5] or "open"}',
        })

    # --- Endpoints from HTTP live hosts (fallback for CDN/no-port targets) ---
    endpoint_hosts = {e['host'] for e in endpoints}
    for asset in assets:
        host = asset['name']
        if host in endpoint_hosts:
            continue
        if not asset['is_live'] and not asset.get('http_status'):
            continue
        endpoint_hosts.add(host)
        status = asset.get('http_status', '')
        title = asset.get('title', '')
        notes = f'from_http'
        if status:
            notes += f' status={status}'
        if title:
            notes += f' title="{title[:60]}"'
        endpoints.append({
            'host': host,
            'method': 'GET',
            'path': '/',
            'notes': notes,
        })

    # --- Signals ---
    signals = []
    seen_signals = set()

    for asset in assets:
        domain = asset['name']
        techs = asset['technologies']
        labels = asset['labels']

        for tech_name in techs:
            for kind, desc, pattern in _TECH_PATTERNS:
                if pattern.search(tech_name):
                    sig_key = f'{domain}:{kind}'
                    if sig_key not in seen_signals:
                        seen_signals.add(sig_key)
                        signals.append({
                            'host': domain, 'kind': kind, 'method': 'GET',
                            'path': '/', 'notes': desc,
                        })

        for label in labels:
            if label in LABEL_SIGNALS:
                kind, desc = LABEL_SIGNALS[label]
                sig_key = f'{domain}:{kind}'
                if sig_key not in seen_signals:
                    seen_signals.add(sig_key)
                    signals.append({
                        'host': domain, 'kind': kind, 'method': 'GET' if kind != 'auth_endpoint' else 'POST',
                        'path': '/login' if kind in ('auth_endpoint',) else '/',
                        'notes': desc,
                    })

    # --- Manifest ---
    in_scope = _build_in_scope(target)

    manifest = {
        'source': 'ozyrecon',
        'target': target,
        'program': target.replace('*.', ''),
        'in_scope_domains': in_scope,
        'out_of_scope_domains': [],
        'notes': f'Exportado desde OzyRecon para {target}',
    }

    # --- Atomic write ---
    _write_atomic(output_dir, {
        'manifest.json': json.dumps(manifest, indent=2),
        'assets.json': json.dumps(assets, indent=2),
        'endpoints.json': json.dumps(endpoints, indent=2),
        'signals.json': json.dumps(signals, indent=2),
    })

    return {
        'assets': len(assets),
        'endpoints': len(endpoints),
        'signals': len(signals),
        'output': str(output_dir),
    }


def main():
    parser = argparse.ArgumentParser(description='Exportar OzyRecon → OzyBounty')
    parser.add_argument('target', help='Target domain (e.g. insforge.dev)')
    parser.add_argument('--output', '-o', default='/tmp/ozybounty-import', help='Output directory')
    args = parser.parse_args()

    out = Path(args.output)
    result = export(args.target, out)

    print(f'Exportado para OzyBounty en: {result["output"]}/')
    print(f'  {result["assets"]} assets')
    print(f'  {result["endpoints"]} endpoints')
    print(f'  {result["signals"]} señales')
    print()
    print(f'Para importar en OzyBounty:')
    print(f'  cd ruta/a/ozybounty')
    print(f'  source .venv/bin/activate')
    print(f'  python scripts/import_from_ozyrecon.py {result["output"]}/')
    return 0


if __name__ == '__main__':
    sys.exit(main())
