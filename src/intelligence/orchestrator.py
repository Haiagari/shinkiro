import re
import socket
import json
from sqlalchemy.orm import Session
from src.storage.models import Subdomain, Port
from src.core.tool_manager import tool_manager
from src.intelligence.scoring_engine import get_scoring_engine
from src.intelligence.infrastructure import infra_enricher
from src.intelligence.classifier import semantic_classifier
from src.utils import log

class DiscoveryOrchestrator:
    def __init__(self, db: Session, scan_id: int | None = None):
        self.db = db
        self.scan_id = scan_id
        self.scoring_engine = get_scoring_engine()

    def _upsert_assets(self, assets: list[dict]):
        """
        Inserta activos (subdominios) vinculados al scan actual.
        Para la v7, permitimos múltiples registros del mismo dominio para trackear historial.
        """
        for asset_data in assets:
            domain = asset_data.get("domain")
            if not domain:
                continue
            
            domain = domain.lower().strip()
            asset_data["domain"] = domain
            if self.scan_id is not None:
                asset_data["scan_id"] = self.scan_id

            # En la v7 buscamos si ya existe EN ESTE SCAN para evitar duplicados internos,
            # pero no pisamos los de scans anteriores.
            existing = self.db.query(Subdomain).filter_by(
                domain=domain, 
                scan_id=self.scan_id
            ).first()
            
            if existing:
                for key, value in asset_data.items():
                    if hasattr(existing, key) and value is not None:
                        setattr(existing, key, value)
            else:
                new_asset = Subdomain(**asset_data)
                self.db.add(new_asset)
        
        self.db.commit()

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
            existing = self.db.query(Port).filter_by(
                host=host, 
                port=port, 
                scan_id=self.scan_id
            ).first()

            # (Scoring logic keeps same)
            service_info = {
                "service_type": service_data.get("service") or service_data.get("product") or "unknown",
                "identifier": f"{host}:{port}",
                "details": {
                    "version": service_data.get("version"),
                    "product": service_data.get("product"),
                    "extra_info": service_data.get("extra_info"),
                    "state": service_data.get("state")
                }
            }
            score_obj = self.scoring_engine.score_asset(service_info)
            service_data["criticality_index"] = score_obj.index
            service_data["severity"] = score_obj.severity
            service_data["scoring_details"] = {
                "breakdown": score_obj.score_breakdown,
                "modifiers": score_obj.modifiers,
                "recommendations": score_obj.recommendations
            }

            if existing:
                for key, value in service_data.items():
                    if hasattr(existing, key) and value is not None:
                        setattr(existing, key, value)
            else:
                new_service = Port(**service_data)
                self.db.add(new_service)
        
        self.db.commit()

    def passive_discovery(self, target: str):
        """
        Fase 1: Descubrimiento pasivo.
        Usa ToolManager para obtener proveedores de la categoría 'asset_discovery'.
        """
        log(f"Starting passive discovery for {target}", level="info")
        # Obtener subdominios de fuentes pasivas
        subdomains = tool_manager.run_capability("asset_discovery", target, all_providers=True)
        
        if not subdomains:
            log(f"No subdomains found for {target}", level="warn")
            return []
            
        # Deduplicar y preparar para upsert
        unique_subs = list(set(s.lower().strip() for s in subdomains if s))
        assets = []
        for s in unique_subs:
            # CLASIFICACIÓN SEMÁNTICA v7 (Fase Pasiva)
            # Alta velocidad, confianza media (solo por nombre de dominio)
            analysis = semantic_classifier.classify_asset({"domain": s})
            assets.append({
                "domain": s,
                "semantic_labels": analysis.get("labels"),
                "business_impact": analysis.get("impact")
            })
        
        self._upsert_assets(assets)
        log(f"Passive discovery finished. {len(assets)} assets identified/updated.", level="success")
        return unique_subs

    def active_resolution(self):
        """
        Fase 2: Resolución activa.
        Usa proveedores de 'live_detection' para validar los assets encontrados.
        """
        log("Starting active resolution phase", level="info")
        # Obtener todos los subdominios conocidos que no han sido validados recientemente o todos
        assets_in_db = self.db.query(Subdomain).all()
        if not assets_in_db:
            log("No assets in database to resolve", level="warn")
            return []
            
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as tf:
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
                # Parsing Estructurado v7.1 (JSON)
                try:
                    raw_data = json.loads(line.strip())
                except json.JSONDecodeError:
                    continue
                
                # Extraer dominio del input o de la URL
                url = raw_data.get("url", "")
                from urllib.parse import urlparse
                parsed = urlparse(url)
                domain = parsed.netloc.split(':')[0]
                if not domain: continue

                res_data = {
                    "is_live": 1,
                    "http_status": raw_data.get("status_code"),
                    "title": raw_data.get("title"),
                    "technologies": raw_data.get("tech", []),
                    "ip": raw_data.get("ip"),
                    "cname": raw_data.get("cname", [])[0] if raw_data.get("cname") else None,
                    "http_headers": raw_data.get("header", {}),
                    "response_time_ms": int(raw_data.get("time", "0ms").replace("ms", "")) if "ms" in str(raw_data.get("time")) else 0
                }
                
                # Enriquecimiento de Infraestructura
                if res_data["ip"]:
                    infra = infra_enricher.enrich_ip(res_data["ip"])
                    res_data["asn"] = infra.get("asn")
                    res_data["asn_organization"] = infra.get("asn_organization")
                    res_data["cloud_provider"] = infra.get("cloud_provider")

                # CLASIFICACIÓN SEMÁNTICA (Enriquecida con Título y Tech reales)
                analysis = semantic_classifier.classify_asset({
                    "domain": domain,
                    "title": res_data["title"] or "",
                    "technologies": res_data["technologies"]
                })
                res_data["semantic_labels"] = analysis.get("labels")
                res_data["business_impact"] = analysis.get("impact")

                resolved_domains[domain] = res_data
            
            # Mapear resultados a assets de la DB
            for domain, data in resolved_domains.items():
                updated_assets.append({"domain": domain, **data})
            
            if updated_assets:
                self._upsert_assets(updated_assets)
                
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
        log(f"Active resolution finished. {len(resolved_domains)} hosts confirmed live.", level="success")
        return list(resolved_domains.keys())

    def service_analysis(self):
        """
        Fase 3: Análisis de servicios.
        Usa la capacidad 'service_discovery' (nmap) sobre los activos marcados como 'live'.
        """
        log("Starting service analysis phase", level="info")
        live_assets = self.db.query(Subdomain).filter_by(is_live=1).all()
        
        if not live_assets:
            log("No live assets found for service analysis", level="warn")
            return []

        total_ports = 0
        for asset in live_assets:
            log(f"Scanning services for {asset.domain}", level="debug")
            try:
                results = tool_manager.run_capability("service_discovery", asset.domain)
                
                if results and isinstance(results, list):
                    # El adaptador de Nmap puede devolver objetos Port o dicts
                    services_to_upsert = []
                    for res in results:
                        if isinstance(res, dict):
                            # Asegurar que el host está presente si el tool no lo puso
                            res.setdefault("host", asset.domain)
                            services_to_upsert.append(res)
                        elif hasattr(res, "__dict__"):
                            # Si es un objeto (modelo), convertir a dict para upsert genérico
                            # o usar sus atributos directamente.
                            services_to_upsert.append({
                                "host": getattr(res, "host", asset.domain),
                                "port": getattr(res, "port", None),
                                "protocol": getattr(res, "protocol", "tcp"),
                                "service": getattr(res, "service", None),
                                "version": getattr(res, "version", None),
                                "product": getattr(res, "product", None),
                                "state": getattr(res, "state", "open"),
                                "extra_info": getattr(res, "extra_info", None)
                            })
                    
                    if services_to_upsert:
                        self._upsert_services(services_to_upsert)
                        total_ports += len(services_to_upsert)
            except Exception as e:
                log(f"Error scanning services for {asset.domain}: {e}", level="error")
        
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
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as tf:
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
                
                log(f"🔥 TAKEOVER DETECTED: {host} -> {vuln_name}", level="critical")
                
                # Persistir en la tabla de Vulnerabilidades
                from src.storage.queries import DBQueries
                queries = DBQueries(self.db)
                queries.add_vulnerability(
                    scan_id=self.scan_id,
                    name=vuln_name,
                    severity=severity,
                    host=host,
                    description=res.get("info", {}).get("description", "Vulnerable to subdomain takeover"),
                    payload=res.get("matched-at"),
                    evidence=res.get("template-id")
                )
                
            return results

        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
