import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime
from sqlalchemy.orm import Session
from src.storage.models import Subdomain, Port
from src.core.tool_manager import tool_manager
from src.intelligence.scoring.scoring_engine import get_scoring_engine
from src.intelligence.enrichment.infrastructure import infra_enricher
from src.intelligence.core.classifier import semantic_classifier
from src.intelligence.analysis.evidence_linker import evidence_linker
from src.intelligence.pipeline.collaboration import (
    write_collaboration_manifest,
    append_collaboration_operator,
)
from src.utils.crypto import evidence_signer
from src.utils import log
from src.scope import is_test_domain
from src.core.target_normalizer import normalize_lookup_target
from src.notifications.notifier import notifier

TOP_PORTS = "80,443,8080,8443,8000,8888,3000,4000,5000,7000,9000,9090,9200,6379,27017,3306,5432,21,22,25,53,110,143,993,995"
PORT_SCAN_WORKERS = 10


class DiscoveryOrchestrator:
    def __init__(self, db: Session, scan_id: int | None = None):
        self.db = db
        self.scan_id = scan_id
        self.scoring_engine = get_scoring_engine()
        self.scoring_engine.reset_scores()
        self.session_id = self._get_session_id()

    def _is_related_domain(self, domain: str, target: str) -> bool:
        domain = normalize_lookup_target(domain)
        target = normalize_lookup_target(target)
        return domain == target or domain.endswith(f".{target}")

    def _get_session_id(self) -> str:
        """Obtiene el session_id vinculado al scan_id."""
        from src.storage.models import Scan

        if self.scan_id is None:
            return "unknown"
        scan = self.db.get(Scan, self.scan_id)
        return scan.session_id if scan else "unknown"

    def seed_target(self, target: str):
        """
        Asegura que el target principal esté en la tabla de subdominios.
        Esto permite que el pipeline continúe incluso si no se encuentran subdominios
        (útil cuando el target es una IP directa).
        """
        is_ip = re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", target)

        analysis = semantic_classifier.classify_asset({"domain": target})
        asset_data = {
            "domain": target,
            "semantic_labels": analysis.get("labels"),
            "business_impact": analysis.get("impact"),
            "inference_trace": analysis.get("trace"),
            "is_live": 1 if is_ip else 0,
            "ip": target if is_ip else None,
            "evidence_signature": evidence_signer.sign_data(
                {
                    "domain": target,
                    "context": {
                        "session_id": self.session_id,
                        "timestamp": datetime.now().isoformat(),
                        "note": "Target seeding",
                    },
                }
            ),
        }
        self._upsert_assets([asset_data])
        log(f"Target {target} seeded into database (is_ip: {bool(is_ip)})", level="debug")

    def finalize_session(self):
        """
        Genera la estructura de artefactos en runs/{session_id}/
        v7.5 - Requerimiento Anti-Humo
        """
        log(f"Finalizing session {self.session_id} and generating artifacts", level="info")
        base_dir = Path("runs") / self.session_id
        dirs = ["raw", "normalized", "evidence", "graph", "reports"]
        for d in dirs:
            (base_dir / d).mkdir(parents=True, exist_ok=True)

        # 1. Export Normalized Findings (JSON)
        from src.export.normalizer import NormalizedExporter

        exporter = NormalizedExporter(self.db)
        # Buscar el target domain vinculado al scan
        from src.storage.models import Scan

        scan = self.db.get(Scan, self.scan_id) if self.scan_id is not None else None
        target_domain = scan.target.domain if scan and scan.target else "unknown"

        result = exporter.export_scan(self.session_id, target_domain)
        with open(base_dir / "normalized" / "findings.json", "w") as f:
            json.dump(result.to_dict(), f, indent=2, default=str)

        write_collaboration_manifest(
            self.session_id,
            target_domain,
            scan_id=self.scan_id,
            operators=["engine"],
            artifacts=dirs,
        )

        # 2. Export Graph
        from src.intelligence.analysis.graph_builder import graph_builder

        graph_data = graph_builder.build_scan_graph(self.db, self.scan_id)
        with open(base_dir / "graph" / "graph.json", "w") as f:
            json.dump(graph_data, f, indent=2)

        # 3. Export Trace
        from src.storage.queries import DBQueries

        trace = DBQueries(self.db).get_session_trace(self.session_id)
        with open(base_dir / "trace.json", "w") as f:
            json.dump(trace, f, indent=2, default=str)

        append_collaboration_operator(self.session_id, "orchestrator")

        if notifier.is_configured():
            notifier.send_scan_summary(target_domain, result)

        log(f"Artifacts generated successfully in {base_dir}", level="success")

    def _upsert_assets(self, assets: list[dict]):
        """
        Inserta activos (subdominios) vinculados al scan actual.
        """
        from src.core.context import get_context

        ctx = get_context()

        new_count = 0
        for asset_data in assets:
            domain = asset_data.get("domain")
            if not domain:
                continue

            domain = domain.lower().strip()
            asset_data["domain"] = domain
            if self.scan_id is not None:
                asset_data["scan_id"] = self.scan_id

            existing = (
                self.db.query(Subdomain).filter_by(domain=domain, scan_id=self.scan_id).first()
            )

            if existing:
                for key, value in asset_data.items():
                    if hasattr(existing, key) and value is not None:
                        setattr(existing, key, value)
            else:
                new_asset = Subdomain(**asset_data)
                self.db.add(new_asset)
                new_count += 1

        self.db.commit()

        # v8.3.2 Fix: Sync context counter for accurate reports
        if ctx:
            ctx.subdomains_found += new_count

    def _upsert_services(self, services: list[dict]):
        """
        Inserta servicios (puertos) vinculados al scan actual.
        """
        for service_data in services:
            host = service_data.get("host")
            port = service_data.get("port")
            if not host or not port:
                continue

            if self.scan_id is not None:
                service_data["scan_id"] = self.scan_id

            # Buscar si ya existe EN ESTE SCAN
            existing = (
                self.db.query(Port).filter_by(host=host, port=port, scan_id=self.scan_id).first()
            )

            # (Scoring logic keeps same)
            service_info = {
                "service_type": service_data.get("service")
                or service_data.get("product")
                or "unknown",
                "identifier": f"{host}:{port}",
                "details": {
                    "version": service_data.get("version"),
                    "product": service_data.get("product"),
                    "extra_info": service_data.get("extra_info"),
                    "state": service_data.get("state"),
                },
            }
            score_obj = self.scoring_engine.score_asset(service_info)
            service_data["criticality_index"] = score_obj.index
            service_data["severity"] = score_obj.severity
            service_data["scoring_details"] = {
                "breakdown": score_obj.score_breakdown,
                "modifiers": score_obj.modifiers,
                "recommendations": score_obj.recommendations,
            }

            if existing:
                for key, value in service_data.items():
                    if hasattr(existing, key) and value is not None:
                        setattr(existing, key, value)
            else:
                new_service = Port(**service_data)
                self.db.add(new_service)

        self.db.commit()

    def passive_discovery(self, target: str, depth: int = 1):
        """
        Fase 1: Descubrimiento pasivo con esteroides (v8.3.2).
        Soporta recursión para encontrar subdominios de subdominios.
        """
        target = normalize_lookup_target(target)
        log(f"Starting passive discovery for {target} (Depth: {depth})", level="info")

        all_found = set()
        to_scan = [target]

        for d in range(depth):
            current_level_found = set()
            for t in to_scan:
                log(f"   Scanning {t} at depth {d + 1}", level="debug")
                subdomains = tool_manager.run_capability("asset_discovery", t, all_providers=True)
                if subdomains:
                    for s in subdomains:
                        s_clean = s.lower().strip().rstrip(".")
                        # Filter test domains
                        if is_test_domain(s_clean, target):
                            log(f"Scope Guard: Discarding test domain: {s_clean}", level="debug")
                            continue
                        # Must be related to target
                        if self._is_related_domain(s_clean, target):
                            current_level_found.add(s_clean)

            # Filtrar solo nuevos y que pertenezcan al dominio principal
            new_assets_list = list(current_level_found - all_found)
            if not new_assets_list:
                break

            all_found.update(new_assets_list)

            # Guardar progreso parcial (v8.3.2 Fix: Persistence during recursion)
            partial_assets = []
            for s in new_assets_list:
                analysis = semantic_classifier.classify_asset({"domain": s})
                partial_assets.append(
                    {
                        "domain": s,
                        "semantic_labels": analysis.get("labels"),
                        "business_impact": analysis.get("impact"),
                        "inference_trace": analysis.get("trace"),
                        "evidence_signature": evidence_signer.sign_data(
                            {
                                "domain": s,
                                "context": {
                                    "session_id": self.session_id,
                                    "timestamp": datetime.now().isoformat(),
                                },
                            }
                        ),
                    }
                )
            self._upsert_assets(partial_assets)

            # Para el siguiente nivel, solo usamos los que tengan pinta de tener más hijos
            to_scan = [
                s for s in new_assets_list if len(s.split(".")) < (target.count(".") + 3 + d)
            ]

        if not all_found:
            log(f"No subdomains found for {target}", level="warn")
            return []

        log(
            f"Passive discovery finished. {len(all_found)} assets identified/updated in total.",
            level="success",
        )
        return list(all_found)

    def active_resolution(self):
        """
        Fase 2: Resolución activa.
        Usa proveedores de 'live_detection' para validar los assets encontrados.
        """
        log("Starting active resolution phase", level="info")
        # Obtener todos los subdominios conocidos que no han sido validados recientemente o todos
        assets_in_db = self.db.query(Subdomain).filter_by(scan_id=self.scan_id).all()
        if not assets_in_db:
            log("No assets in database to resolve", level="warn")
            return []

        import tempfile
        import os

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tf:
            for asset in assets_in_db:
                tf.write(f"{asset.domain}\n")
            temp_path = tf.name

        try:
            # Ejecutar live_detection (httpx)
            results = tool_manager.run_capability("live_detection", temp_path, all_providers=True)

            if not results:
                log("No resolution results found", level="warn")
                return []

            # Procesar resultados (httpx con los flags en manifest devuelve algo como "http://domain [200]")
            updated_assets = []
            resolved_domains = {}

            for line in results:
                # Parsing Estructurado Robusto v8.3.2
                from src.utils.parsers import clean_json_line, parse_duration_ms, normalize_ip

                raw_data = clean_json_line(line)
                if not raw_data:
                    continue

                # Extraer dominio del input (v8.3.2 Fix: More reliable than parsing URL)
                domain = raw_data.get("input", "").lower().strip()
                if not domain:
                    url = raw_data.get("url", "")
                    from urllib.parse import urlparse

                    parsed = urlparse(url)
                    domain = parsed.netloc.split(":")[0]

                if not domain:
                    continue

                res_data = {
                    "is_live": 1,
                    "http_status": raw_data.get("status_code"),
                    "title": raw_data.get("title"),
                    "technologies": raw_data.get("tech", []),
                    "ip": normalize_ip(raw_data.get("host_ip") or raw_data.get("ip")),
                    "cname": raw_data.get("cname", [])[0] if raw_data.get("cname") else None,
                    "http_headers": raw_data.get("header", {}),
                    "response_time_ms": parse_duration_ms(raw_data.get("time")),
                }

                # Enriquecimiento de Infraestructura
                if res_data["ip"]:
                    infra = infra_enricher.enrich_ip(res_data["ip"])
                    res_data["asn"] = infra.get("asn")
                    res_data["asn_organization"] = infra.get("asn_organization")
                    res_data["cloud_provider"] = infra.get("cloud_provider")

                # CLASIFICACIÓN SEMÁNTICA v7.5 (Trazable)
                analysis = semantic_classifier.classify_asset(
                    {
                        "domain": domain,
                        "title": res_data["title"] or "",
                        "technologies": res_data["technologies"],
                        "headers": res_data["http_headers"],
                    }
                )
                res_data["semantic_labels"] = analysis.get("labels")
                res_data["business_impact"] = analysis.get("impact")
                res_data["inference_trace"] = analysis.get("trace")

                # v9.0.1: Link evidence for traceability
                evidence_linker.link_subdomain_to_httpx(
                    domain=domain,
                    http_status=res_data.get("http_status", 0),
                    technologies=res_data.get("technologies", []),
                    timestamp=datetime.now().isoformat(),
                )

                # Firmar evidencia digitalmente con contexto completo (v8.3.2)
                # Evita Replay Attacks y recontextualización
                res_data["evidence_signature"] = evidence_signer.sign_data(
                    {
                        "domain": domain,
                        "ip": res_data["ip"],
                        "http_status": res_data["http_status"],
                        "title": res_data["title"],
                        "semantic_labels": res_data["semantic_labels"],
                        "context": {
                            "session_id": self.session_id,
                            "timestamp": datetime.now().isoformat(),
                            "engine": "PromptWall v8.3.2",
                            "schema_version": "1.2",
                        },
                    }
                )

                resolved_domains[domain] = res_data

            # Mapear resultados a assets de la DB
            for domain, data in resolved_domains.items():
                updated_assets.append({"domain": domain, **data})

            if updated_assets:
                self._upsert_assets(updated_assets)

                # v9.0.1: Auto-create HTTP service from httpx confirmation (fallback when nmap fails)
                for asset in updated_assets:
                    if asset.get("is_live") and asset.get("http_status"):
                        port = (
                            443
                            if asset.get("http_headers", {}).get("location", "").startswith("https")
                            else 80
                        )
                        service_data = [
                            {
                                "host": asset.get("domain"),
                                "port": port,
                                "protocol": "tcp",
                                "service": "http",
                                "state": "open",
                                "product": asset.get("technologies", [])[0]
                                if asset.get("technologies")
                                else "unknown",
                            }
                        ]
                        self._upsert_services(service_data)

        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

        log(
            f"Active resolution finished. {len(resolved_domains)} hosts confirmed live.",
            level="success",
        )
        return list(resolved_domains.keys())

    def endpoint_recon(self, target: str):
        """
        Idea: Steroids Recon (Endpoint Discovery).
        Encuentra URLs y endpoints históricos.
        """
        log(f"Starting endpoint discovery for {target}", level="info")
        results = tool_manager.run_capability("endpoint_discovery", target, all_providers=True)
        if results:
            log(f"   Found {len(results)} historical endpoints/URLs", level="success")
            # Podríamos persistirlos en una tabla de 'endpoints' en el futuro
            return results
        return []

    def dns_bruteforce(self, target: str):
        """
        Idea: Steroids Recon (DNS Bruteforce).
        Fuerza bruta recursiva para encontrar subdominios no indexados.
        """
        log(f"Starting DNS brute-force for {target}", level="info")
        results = tool_manager.run_capability("dns_bruteforce", target, all_providers=True)
        if results:
            log(f"   DNS brute-force found {len(results)} additional subdomains", level="success")
            # Upsert found subdomains
            assets = [{"domain": s.lower().strip()} for s in results if s]
            self._upsert_assets(assets)
            return results
        return []

    def _port_scan_host(self, host: str) -> list:
        try:
            return tool_manager.run_capability("port_scan", host, ports=TOP_PORTS) or []
        except Exception as e:
            log(f"port_scan failed for {host}: {e}", level="warning")
            return []

    def _service_discover_host(self, host: str, ports: str) -> list:
        try:
            return tool_manager.run_capability("service_discovery", host, ports=ports) or []
        except Exception as e:
            log(f"service_discovery failed for {host}: {e}", level="warning")
            return []

    def _is_cdn_host(self, host: str) -> bool:
        try:
            import socket
            ip = socket.gethostbyname(host)
            return any(
                ip.startswith(prefix)
                for prefix in [
                    "104.16.", "104.17.", "104.18.", "104.19.",
                    "172.64.", "173.245.", "103.21.", "103.22.",
                    "13.32.", "13.33.", "13.34.", "13.35.",
                    "54.192.", "99.84.",
                ]
            )
        except Exception:
            return False

    def _find_origin_ips(self, hosts: list[str]) -> dict[str, list[str]]:
        log("Attempting origin IP discovery for CDN-protected hosts", level="info")
        import socket
        origins = {}

        for host in hosts:
            if not self._is_cdn_host(host):
                continue
            try:
                candidates = set()
                base = host.split(".")[-2] + "." + host.split(".")[-1] if host.count(".") >= 1 else host

                for candidate in [f"ftp.{base}", f"mail.{base}", f"direct.{base}", f"origin.{base}",
                                  f"ssh.{base}", f"webmail.{base}", base]:
                    try:
                        ip = socket.gethostbyname(candidate)
                        if not self._is_cdn_host(candidate):
                            candidates.add(ip)
                    except Exception:
                        pass

                if candidates:
                    origins[host] = list(candidates)
            except Exception:
                pass

        if origins:
            log(f"Found {sum(len(ips) for ips in origins.values())} candidate origin IPs", level="success")
        return origins

    def service_analysis(self):
        """
        Fase 3: Análisis de servicios (three-phase).
        Fase 1: Naabu (port_scan) en paralelo sobre todos los hosts vivos.
        Fase 2: Nmap (service_discovery) solo sobre hosts con puertos abiertos.
        Fase 3: Origin IP discovery + scan para hosts protegidos por CDN.
        """
        log("Starting service analysis phase", level="info")
        live_assets = self.db.query(Subdomain).filter_by(is_live=1, scan_id=self.scan_id).all()

        if not live_assets:
            log("No live assets found for service analysis", level="warn")
            return 0

        hosts = [a.domain for a in live_assets]
        log(f"Phase 1: port_scan (Naabu) on {len(hosts)} hosts with {PORT_SCAN_WORKERS} workers", level="info")

        all_open = []
        with ThreadPoolExecutor(max_workers=PORT_SCAN_WORKERS) as ex:
            futures = {ex.submit(self._port_scan_host, h): h for h in hosts}
            for f in as_completed(futures):
                all_open.extend(f.result())

        log(f"Phase 1 complete: {len(all_open)} open ports across {len(set(r.host for r in all_open))} hosts", level="success")

        host_ports = {}
        for r in all_open:
            host = getattr(r, "host", None)
            port = getattr(r, "port", None)
            if host and port:
                host_ports.setdefault(host, []).append(str(port))

        log(f"Phase 2: service_discovery (Nmap) on {len(host_ports)} hosts with open ports", level="info")
        total_ports = 0
        with ThreadPoolExecutor(max_workers=PORT_SCAN_WORKERS) as ex:
            futures = {}
            for host, ports in host_ports.items():
                ports_str = ",".join(ports)
                futures[ex.submit(self._service_discover_host, host, ports_str)] = host

            for f in as_completed(futures):
                results = f.result()
                if not results:
                    continue
                services_to_upsert = []
                for res in results:
                    if isinstance(res, dict):
                        services_to_upsert.append(res)
                    elif hasattr(res, "__dict__"):
                        services_to_upsert.append({
                            "host": getattr(res, "host", futures[f]),
                            "port": getattr(res, "port", None),
                            "protocol": getattr(res, "protocol", "tcp"),
                            "service": getattr(res, "service", None),
                            "version": getattr(res, "version", None),
                            "product": getattr(res, "product", None),
                            "state": getattr(res, "state", "open"),
                            "extra_info": getattr(res, "extra_info", None),
                        })
                if services_to_upsert:
                    self._upsert_services(services_to_upsert)
                    total_ports += len(services_to_upsert)

        # Phase 3: Origin IP bypass for CDN hosts
        if len(host_ports) < len(hosts) * 0.3:
            log("Phase 3: scanning origin IPs behind CDN", level="info")
            cdn_hosts = [h for h in hosts if h not in host_ports]
            origins = self._find_origin_ips(cdn_hosts[:20])
            for host, origin_ips in origins.items():
                for ip in origin_ips:
                    try:
                        port_results = tool_manager.run_capability("port_scan", ip, ports=TOP_PORTS)
                        if port_results:
                            port_list = ",".join(set(str(getattr(r, "port", None)) for r in port_results if getattr(r, "port", None)))
                            if port_list:
                                services = tool_manager.run_capability("service_discovery", ip, ports=port_list)
                                if services:
                                    svc_list = [{
                                        "host": host, "port": getattr(s, "port", None),
                                        "protocol": getattr(s, "protocol", "tcp"),
                                        "service": getattr(s, "service", None),
                                        "version": getattr(s, "version", None),
                                        "product": getattr(s, "product", None),
                                        "state": "open",
                                        "extra_info": f"origin_ip={ip}",
                                    } for s in services if hasattr(s, "__dict__")]
                                    if svc_list:
                                        self._upsert_services(svc_list)
                                        total_ports += len(svc_list)
                                        log(f"Found {len(svc_list)} services via origin IP {ip} for {host}", level="success")
                    except Exception:
                        pass

        log(f"Service analysis finished. {total_ports} open ports identified/updated.", level="success")
        return total_ports

    def takeover_detection(self):
        """
        Fase 4: Detección de Subdomain Takeover (v7.3).
        Usa Nuclei con el tag 'takeover' sobre los activos vivos.
        """
        log("Starting subdomain takeover detection", level="info")
        live_assets = self.db.query(Subdomain).filter_by(is_live=1, scan_id=self.scan_id).all()
        if not live_assets:
            return []

        import tempfile
        import os

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tf:
            for asset in live_assets:
                tf.write(f"{asset.domain}\n")
            temp_path = tf.name

        try:
            # Ejecutar Nuclei filtrando solo por Takeovers
            results = tool_manager.run_capability("template_scan", temp_path, tags=["takeover"])

            if not results:
                log("No takeovers detected", level="info")
                return []

            # Procesar hallazgos de Nuclei
            for res in results:
                vuln_name = res.get("info", {}).get("name", "Potential Takeover")
                severity = res.get("info", {}).get("severity", "critical")
                host = res.get("host", "")

                log(f"🔥 TAKEOVER CANDIDATE: {host} -> {vuln_name}", level="warn")

                # Persistir en la tabla de Vulnerabilidades con estado PENDING_APPROVAL
                # v7.5 - Requerimiento de Seguridad (No explotación)
                from src.storage.queries import DBQueries
                from src.workflow.states import WorkflowState

                queries = DBQueries(self.db)
                queries.add_vulnerability(
                    scan_id=self.scan_id,
                    name=vuln_name,
                    severity=severity,
                    host=host,
                    description=res.get("info", {}).get(
                        "description", "Vulnerable to subdomain takeover"
                    ),
                    payload=res.get("matched-at"),
                    evidence=res.get("template-id"),
                )

                # Actualizar el estado a PENDING_APPROVAL para el Gate Humano
                # Nota: add_vulnerability por defecto lo pone en 'open', lo movemos a 'pending_approval'
                from src.storage.models import Vulnerability

                vuln = (
                    self.db.query(Vulnerability)
                    .filter_by(scan_id=self.scan_id, host=host, name=vuln_name)
                    .first()
                )
                if vuln:
                    vuln.status = WorkflowState.PENDING_APPROVAL
                    self.db.commit()

            return results

        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def subdomain_permutations(self, target: str):
        """
        Genera permutaciones y hace DNS brute-force sobre los subdominios encontrados.
        """
        log(f"Starting subdomain permutation phase for {target}", level="info")
        assets = self.db.query(Subdomain).filter_by(scan_id=self.scan_id).all()
        if not assets:
            log("No assets to permutate", level="warn")
            return []

        seeds = [a.domain for a in assets if a.domain.endswith(f".{target}")]
        if not seeds:
            return []

        from src.discovery.services.permutator import Permutator
        p = Permutator(target)
        candidates = p.generate(seeds)
        log(f"Generated {len(candidates)} permutation candidates", level="info")

        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tf:
            for c in candidates:
                tf.write(f"{c}\n")
            temp_path = tf.name

        try:
            resolved = tool_manager.run_capability("dns_resolution", temp_path, all_providers=False)
            if resolved:
                found = [r.strip().lower() for r in resolved if r.strip()]
                assets_to_add = []
                for domain in found:
                    if self._is_related_domain(domain, target):
                        assets_to_add.append({
                            "domain": domain,
                            "is_live": 0,
                            "evidence_signature": evidence_signer.sign_data({
                                "domain": domain,
                                "context": {"session_id": self.session_id, "phase": "permutations"}
                            }),
                        })
                if assets_to_add:
                    self._upsert_assets(assets_to_add)
                log(f"Permutation phase: {len(assets_to_add)} new subdomains found", level="success")
                return [a["domain"] for a in assets_to_add]
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        return []

    def js_endpoint_extraction(self):
        """
        Descarga JS de hosts vivos y extrae endpoints ocultos.
        """
        log("Starting JS endpoint extraction", level="info")
        live = self.db.query(Subdomain).filter_by(scan_id=self.scan_id, is_live=1).all()
        if not live:
            log("No live hosts for JS extraction", level="warn")
            return []

        js_urls = []
        for asset in live:
            for scheme in ["https", "http"]:
                js_urls.append(f"{scheme}://{asset.domain}")

        from src.discovery.services.js_analyzer import JSAnalyzer
        analyzer = JSAnalyzer()
        results = analyzer.analyze(js_urls)
        log(f"JS extraction: {len(results)} endpoints found in JS files", level="success")

        if results:
            out_dir = Path("runs") / self.session_id / "js_endpoints"
            out_dir.mkdir(parents=True, exist_ok=True)
            import json
            with open(out_dir / "endpoints.json", "w") as f:
                json.dump(results, f, indent=2)
        return results

    def param_discovery(self):
        """
        Descubre parámetros en endpoints encontrados.
        """
        log("Starting parameter discovery", level="info")
        js_dir = Path("runs") / self.session_id / "js_endpoints" / "endpoints.json"
        if not js_dir.exists():
            log("No JS endpoints file found for param discovery", level="warn")
            return []

        import json
        with open(js_dir) as f:
            endpoints = json.load(f)

        unique_paths = list(set(e["path"] for e in endpoints if e.get("path", "").startswith("/")))
        if not unique_paths:
            log("No paths to test for parameters", level="warn")
            return []

        live = self.db.query(Subdomain).filter_by(scan_id=self.scan_id, is_live=1).first()
        if not live:
            return []

        from src.discovery.services.param_discovery import ParamDiscoverer
        discoverer = ParamDiscoverer(delay=0.5)
        all_params = []
        for path in unique_paths[:20]:
            url = f"https://{live.domain}{path}"
            params = discoverer.discover(url)
            if params:
                all_params.extend(params)

        log(f"Parameter discovery: {len(all_params)} parameters found across {len(unique_paths[:20])} paths", level="success")
        if all_params:
            out_dir = Path("runs") / self.session_id
            out_dir.mkdir(parents=True, exist_ok=True)
            import json
            with open(out_dir / "discovered_params.json", "w") as f:
                json.dump(all_params, f, indent=2)
        return all_params

    def s3_scan(self, target: str):
        """
        Escanea buckets S3 relacionados con el target.
        """
        log(f"Starting S3 bucket scan for {target}", level="info")
        from src.discovery.services.s3_scanner import S3Scanner
        scanner = S3Scanner()
        results = scanner.scan(target)
        public = [r for r in results if r.get("status") == "public"]
        if public:
            log(f"⚠️  {len(public)} public S3 buckets found!", level="warn")
            for b in public[:5]:
                log(f"  - {b['url']}", level="warn")
        else:
            log("No public S3 buckets found", level="info")

        if results:
            out_dir = Path("runs") / self.session_id
            out_dir.mkdir(parents=True, exist_ok=True)
            import json
            with open(out_dir / "s3_buckets.json", "w") as f:
                json.dump(results, f, indent=2)
        return results

    def google_dork(self, target: str):
        """
        Ejecuta Google Dorks contra el target.
        """
        log(f"Starting Google dorking for {target}", level="info")
        from src.discovery.services.google_dorker import GoogleDorker
        dorker = GoogleDorker()
        results = dorker.dork(target)
        if results:
            log(f"Google dorking: {len(results)} findings", level="success")
            for r in results[:5]:
                log(f"  [{r['category']}] {r['url']}", level="info")
            out_dir = Path("runs") / self.session_id
            out_dir.mkdir(parents=True, exist_ok=True)
            import json
            with open(out_dir / "google_dorks.json", "w") as f:
                json.dump(results, f, indent=2)
        else:
            log("Google dorking: no findings (or rate limited)", level="info")
        return results

    def autonomous_tactical_loop(self, max_depth: int = 2):
        """
        Idea 1: Orquestación Autónoma (Modo Piloto Automático).
        Analiza los assets actuales y dispara acciones tácticas automáticas.
        """
        from src.intelligence.autonomy.autonomy_engine import autonomy_engine

        log(f"Starting Autonomous Tactical Loop (Max Depth: {max_depth})", level="info")

        for cycle in range(max_depth):
            # 1. Obtener activos del scan actual que tengan etiquetas semánticas
            assets = (
                self.db.query(Subdomain)
                .filter(Subdomain.scan_id == self.scan_id, Subdomain.semantic_labels != None)
                .all()
            )

            assets_dicts = [
                {"domain": a.domain, "semantic_labels": a.semantic_labels} for a in assets
            ]

            # 2. Decidir acciones basadas en inteligencia
            actions = autonomy_engine.evaluate_assets(assets_dicts)

            if not actions:
                log(f"No autonomous actions recommended in cycle {cycle + 1}.", level="info")
                break

            log(
                f"🤖 Autonomous Engine recommended {len(actions)} tactical actions (Cycle {cycle + 1})",
                level="info",
            )

            new_findings_count = 0
            for action in actions:
                log(
                    f"⚡ Executing Tactical Action: {action.capability} on {action.target}",
                    level="warn",
                )
                log(f"   Reason: {action.reason}", level="debug")

                try:
                    # Ejecutar la capacidad (ej: template_scan)
                    results = tool_manager.run_capability(action.capability, action.target)

                    if results and action.capability == "template_scan":
                        for res in results:
                            # Procesar hallazgo de vulnerabilidad
                            vuln_name = res.get("info", {}).get("name", "Autonomous Finding")
                            severity = res.get("info", {}).get("severity", "medium")

                            from src.storage.queries import DBQueries

                            queries = DBQueries(self.db)
                            queries.add_vulnerability(
                                scan_id=self.scan_id,
                                name=vuln_name,
                                severity=severity,
                                host=action.target,
                                description=res.get("info", {}).get(
                                    "description", "Found via autonomous tactician"
                                ),
                                payload=res.get("matched-at"),
                                evidence=res.get("template-id"),
                            )

                            # v8.3.2 - Idea 5: Intelligent Notifications
                            if severity.lower() in ["critical", "high"]:
                                from src.notifications.notifier import notifier

                                notifier.send_alert(
                                    f"Critical Autonomous Finding: {vuln_name}",
                                    f"Target: {action.target}\nSeverity: {severity.upper()}\nDescription: {res.get('info', {}).get('description')}",
                                    severity=severity.lower(),
                                )

                            new_findings_count += 1
                except Exception as e:
                    log(f"❌ Autonomous action failed for {action.target}: {e}", level="error")

            log(
                f"Cycle {cycle + 1} completed. New findings generated: {new_findings_count}",
                level="success",
            )
            if new_findings_count == 0:
                # Si no encontramos nada nuevo que genere más bardo, cortamos
                break
