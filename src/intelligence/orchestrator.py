from sqlalchemy.orm import Session
from src.storage.models import Subdomain, Port
from src.core.tool_manager import tool_manager
from src.intelligence.scoring_engine import get_scoring_engine
from src.utils import log

class DiscoveryOrchestrator:
    def __init__(self, db: Session):
        self.db = db
        self.scoring_engine = get_scoring_engine()

    def _upsert_assets(self, assets: list[dict]):
        """
        Inserta o actualiza activos (subdominios) basándose en el nombre de dominio.
        """
        for asset_data in assets:
            domain = asset_data.get("domain")
            if not domain:
                continue
            
            # Normalización básica: lowercase
            domain = domain.lower().strip()
            asset_data["domain"] = domain

            existing = self.db.query(Subdomain).filter_by(domain=domain).first()
            if existing:
                # Update existing
                for key, value in asset_data.items():
                    if hasattr(existing, key) and value is not None:
                        setattr(existing, key, value)
            else:
                # Insert new
                new_asset = Subdomain(**asset_data)
                self.db.add(new_asset)
        
        self.db.commit()

    def _upsert_services(self, services: list[dict]):
        """
        Inserta o actualiza servicios (puertos) basándose en host y puerto.
        Aplica el motor de scoring si hay nuevos datos.
        """
        for service_data in services:
            host = service_data.get("host")
            port = service_data.get("port")
            if not host or not port:
                continue
            
            # Preparar info para el motor de scoring
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
            
            # Obtener score
            score_obj = self.scoring_engine.score_asset(service_info)
            service_data["criticality_index"] = score_obj.index
            service_data["severity"] = score_obj.severity
            service_data["scoring_details"] = {
                "breakdown": score_obj.score_breakdown,
                "modifiers": score_obj.modifiers,
                "recommendations": score_obj.recommendations
            }

            existing = self.db.query(Port).filter_by(host=host, port=port).first()
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
        assets = [{"domain": s} for s in unique_subs]
        
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
                # Parsing rústico: extraer dominio y status
                parts = line.split()
                if not parts: continue
                
                url = parts[0]
                from urllib.parse import urlparse
                parsed = urlparse(url)
                domain = parsed.netloc.split(':')[0]
                if not domain and parsed.path: # Fallback if URL doesn't have scheme
                    domain = parsed.path.split('/')[0].split(':')[0]
                
                if domain:
                    resolved_domains[domain] = {
                        "is_live": 1,
                    }
            
            # Mapear resultados a assets de la DB
            for domain, data in resolved_domains.items():
                updated_assets.append({"domain": domain, "is_live": 1})
            
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
