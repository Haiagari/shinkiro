import re
import socket
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
                # Parsing mejorado: httpx devuelve algo como:
                # http://domain [status] [title] [tech1,tech2]
                parts = line.strip().split(" ")
                if not parts: continue
                
                url = parts[0]
                from urllib.parse import urlparse
                parsed = urlparse(url)
                domain = parsed.netloc.split(':')[0]
                if not domain and parsed.path:
                    domain = parsed.path.split('/')[0].split(':')[0]
                
                if not domain: continue

                res_data = {"is_live": 1}
                
                # Extraer Status Code [200]
                status_match = re.search(r"\[(\d{3})\]", line)
                if status_match:
                    res_data["http_status"] = int(status_match.group(1))

                # Extraer IP (httpx con -ip devuelve [0.0.0.0])
                ip_match = re.search(r"\[(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)\]", line)
                if ip_match:
                    ip = ip_match.group(1)
                    res_data["ip"] = ip
                    
                    # ENRIQUECIMIENTO v7 (Phase 2)
                    infra = infra_enricher.enrich_ip(ip)
                    res_data["asn"] = infra.get("asn")
                    res_data["asn_organization"] = infra.get("asn_organization")
                    res_data["cloud_provider"] = infra.get("cloud_provider")

                # Extraer Título (entre los corchetes después del status/ip)
                # El formato suele ser: [status] [ip] [title] [tech]
                all_brackets = re.findall(r"\[(.*?)\]", line)
                # El título suele ser el primero que no es status ni IP
                potential_titles = [b for b in all_brackets if not re.match(r"^\d{3}$", b) and not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", b)]
                if potential_titles:
                    res_data["title"] = potential_titles[0]
                
                # Extraer Tecnologías (el último si hay varios y no es lo anterior)
                if len(potential_titles) >= 2:
                    techs = [t.strip() for t in potential_titles[-1].split(",")]
                    res_data["technologies"] = techs

                # CLASIFICACIÓN SEMÁNTICA v7 (Phase 5 & 7)
                analysis = semantic_classifier.classify_asset({
                    "domain": domain,
                    "title": res_data.get("title", ""),
                    "technologies": res_data.get("technologies", [])
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
