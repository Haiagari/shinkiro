# Plan Maestro de Evolución Técnica - OzyRecon (Versión Definitiva Extendida)

Este documento contiene la especificación arquitectónica profunda, exhaustiva y lista para implementación para escalar el framework OzyRecon a niveles corporativos. La premisa central se mantiene estricta e innegociable: **Preservar la pureza de la Arquitectura Hexagonal.** Ninguna regla de infraestructura debe manchar el directorio `src/domain/`.

---

## 1. De Monolito a Nodos Distribuidos (Workers)

### 1.1. Análisis Profundo del Cuello de Botella
Actualmente, `ozy hunt` y `ozy continuous` operan bajo un modelo de `ThreadPoolExecutor` y `subprocess.Popen` atado al hilo de ejecución del OS local. Esto genera los siguientes bloqueos a escala:
*   **Limitación de Descriptores de Archivos:** Las herramientas Go (`httpx`, `subfinder`) consumen miles de file descriptors (sockets TCP concurrentes). En un OS estándar, esto causa el error `Too many open files`.
*   **IP Ban / WAF Blocking:** Una sola IP de origen haciendo enumeración agresiva activa los WAFs (Cloudflare, Akamai) bloqueando al escáner en los primeros 10 minutos.
*   **Riesgo de Corrupción:** Un Out-of-Memory (OOM) en medio de la "Phase 4" corrompe el reporte final y requiere reiniciar todo el ciclo.

### 1.2. Diseño Arquitectónico (Distributed Publisher/Subscriber)

El modelo evolucionará hacia una arquitectura orientada a mensajes robusta utilizando **Redis Streams** (preferido sobre Redis Lists por la persistencia y Consumer Groups) o **NATS JetStream**.

```mermaid
graph TD
    subgraph Control Plane
    A[OzyRecon API / CLI] -->|Publica (XADD)| B[(Redis Stream: recon.tasks)]
    G[(DB Central: PostgreSQL)]
    end
    
    subgraph Data Plane (Worker Fleet)
    C[Worker Node 1 - DigitalOcean] -->|XREADGROUP| B
    D[Worker Node 2 - AWS EC2] -->|XREADGROUP| B
    E[Worker Node N - Linode] -->|XREADGROUP| B
    end
    
    C -.->|Adapters: SQL / S3| G
    C -->|Adapters: Storage| F[(S3 Bucket: ozyrecon-artifacts)]
```

### 1.3. Especificaciones a Nivel Código y Contratos

**A. El Contrato del Mensaje (Domain / Application):**
El payload distribuido no debe ser un diccionario suelto. Debe tener validación estricta usando Pydantic o Dataclasses.
```python
# src/application/dto/scan_task.py
from dataclasses import dataclass
from typing import List, Optional

@dataclass(frozen=True)
class DistributedScanTask:
    task_id: str
    target: str
    profile: str
    scope_domains: List[str]
    max_depth: int
    intent: str  # passive, balanced, aggressive
    callback_url: Optional[str] = None
```

**B. Modificación en Orquestación (`src/application/use_cases/orchestrator.py`):**
El orquestador debe poder instanciarse en "Modo Local" o "Modo Distribuido".
```python
class OzyOrchestratorV10:
    def __init__(self, publisher: IMessagePublisher, repository: IAssetRepository):
        self.publisher = publisher
        
    def dispatch_hunt(self, target: str):
        task = DistributedScanTask(task_id=generate_id(), target=target, ...)
        # Si el publisher es Redis, se encola. Si es LocalPublisher, se ejecuta sincronamente.
        self.publisher.publish(task) 
```

**C. Gestión de Estados y Fallos (Dead-Letter Queues):**
*   **Consumer Groups:** Cada worker pertenecerá al grupo `ozy_workers`. Redis se encarga de no enviar la misma tarea a dos workers.
*   **Heartbeats & ACKs:** Si un worker muere (pierde conexión o se cuelga procesando Nmap), Redis mantiene la tarea en el estado `PEL` (Pending Entries List). Un servicio de recolección (`Claimer`) reasignará la tarea a otro worker si pasan 30 minutos sin recibir el `XACK`.

**D. Solución de Artefactos (Adapter S3):**
La evidencia (`audit_bundle.tar.gz`) debe subirse vía protocolo S3.
```python
# src/adapters/storage/s3_artifact_repository.py
import boto3
from src.application.ports.artifact_repository import IArtifactRepository

class S3ArtifactRepository(IArtifactRepository):
    def __init__(self, bucket_name: str, region: str):
        self.s3 = boto3.client('s3', region_name=region)
        
    def upload_bundle(self, scan_id: str, local_filepath: str) -> str:
        s3_key = f"scans/{scan_id}/audit_bundle.tar.gz"
        self.s3.upload_file(local_filepath, self.bucket, s3_key)
        return f"s3://{self.bucket}/{s3_key}"
```

### 1.4. Infraestructura y Despliegue
*   **Dockerización Estricta:** El worker no requerirá correr `./bootstrap-ozyrecon.sh`. Se construirá una imagen `Dockerfile.worker` basada en Ubuntu/Alpine que ya contenga los binarios de Go (`subfinder`, `nuclei`) y Nmap preinstalados.
*   **Auto-Scaling:** Se podrá configurar Kubernetes (KEDA) para leer la longitud del Redis Stream `recon.tasks`. Si hay 1000 tareas en cola, KEDA levanta automáticamente 50 Pods de workers, y al vaciarse la cola, los destruye.

---

## 2. Base de Datos de Grafos (Neo4j) para la Superficie

### 2.1. Análisis Profundo del Cuello de Botella
El modelo relacional está diseñado para tablas transaccionales (CRUD). Sin embargo, el análisis de seguridad ofensivo requiere trazar vectores de ataque (Paths).
*   *Pregunta Crítica:* "¿Cuántos dominios terminan resolviendo a IPs que están alojadas en la red de AWS y tienen puertos con un certificado SSL caducado?"
*   *En SQL:* Esto implica 5 `JOINs` entre tablas enormes (Dominios, IPs, Puertos, Servicios, Certificados), destruyendo el rendimiento.
*   *En Grafos:* Las relaciones son ciudadanos de primera clase. La consulta recorre los punteros en memoria en O(1).

### 2.2. Ontología del Grafo y Restricciones (Constraints)

Para garantizar consistencia, se deben aplicar constraints a nivel de base de datos en Neo4j:
*   `CREATE CONSTRAINT ON (d:Domain) ASSERT d.name IS UNIQUE;`
*   `CREATE CONSTRAINT ON (i:IP) ASSERT i.address IS UNIQUE;`
*   `CREATE CONSTRAINT ON (v:Vulnerability) ASSERT v.cve_id IS UNIQUE;`

### 2.3. Especificaciones a Nivel Código

**A. El Adaptador Completo (`src/adapters/storage/neo4j_repository.py`):**
Se utilizará transacciones atómicas para persistir toda la topología de un Asset descubierto en un solo pase.

```python
from neo4j import GraphDatabase
from src.application.ports.asset_repository import IAssetRepository
from src.domain.models import Asset

class Neo4jAssetRepository(IAssetRepository):
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def save(self, asset: Asset) -> None:
        query = """
        MERGE (d:Domain {name: $domain})
        SET d.is_live = $is_live, d.last_seen = timestamp()
        
        FOREACH (ip_str IN $ips |
            MERGE (i:IP {address: ip_str})
            MERGE (d)-[:RESOLVES_TO]->(i)
        )
        """
        with self.driver.session() as session:
            session.run(query, domain=asset.domain, 
                               is_live=asset.is_live, 
                               ips=[ip for ip in asset.ips])
```

**B. Búsqueda de Vectores de Ataque (Lateral Movement):**
La ventaja real del grafo se implementa en la capa de Inteligencia. Se pueden crear Queries especializadas para pentesters.
```cypher
// Encontrar vulnerabilidades críticas en subdominios de staging
MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)
WHERE s.name CONTAINS 'staging' OR s.name CONTAINS 'dev'
MATCH (s)-[:RESOLVES_TO]->(i:IP)-[:EXPOSES]->(p:Port)-[:RUNS]->(srv:Service)
MATCH (srv)-[:HAS_VULNERABILITY]->(v:Vulnerability {severity: 'CRITICAL'})
RETURN s.name, i.address, p.number, v.name
```

---

## 3. Event Sourcing para el "Diff Tracking" (CQRS)

### 3.1. Análisis Profundo del Cuello de Botella
El `diff_engine` actual realiza una comparación estructural pesada (State-based Diff). Este enfoque:
1. Pierde la noción temporal exacta (sólo sabés que cambió "entre el scan 1 y el 2").
2. No permite disparar acciones en caliente durante el escaneo (hay que esperar a que termine todo el `hunt`).
3. Dificulta deshacer (rollback) falsos positivos.

### 3.2. Diseño Arquitectónico (Event-Driven & CQRS)

Se separarán estrictamente las escrituras (Command) de las lecturas (Query).

*   **Command Side:** Las herramientas (nmap, subfinder) emiten "Eventos de Dominio" puros al Event Bus. Estos eventos se guardan en un Log de Sólo Adición (Append-Only Log) en una base de datos de eventos (EventStore).
*   **Query Side (Proyecciones):** Diferentes "Proyectores" leen esos eventos y arman las tablas de lectura (ej. armar la base de datos Neo4j a partir de los eventos).

### 3.3. Especificaciones a Nivel Código

**A. El Bus de Eventos Asíncrono (`src/core/event_bus.py`):**
A diferencia de un array simple, el bus debe ser Thread-Safe y soportar concurrencia mediante `asyncio`.

```python
import asyncio
from collections import defaultdict

class AsyncEventBus:
    def __init__(self):
        self.handlers = defaultdict(list)
        
    def subscribe(self, event_type: type, handler):
        self.handlers[event_type].append(handler)
        
    async def publish(self, event):
        tasks = [handler.handle(event) for handler in self.handlers[type(event)]]
        await asyncio.gather(*tasks)
```

**B. Proyectores y Manejadores (Differs):**
El "Diff" ya no se calcula, **se detecta al vuelo**.
Si un puerto no estaba en la vista materializada actual, la proyección emite inmediatamente una alerta sin esperar a la Fase 5.

```python
# src/application/projectors/diff_projector.py
class RealTimeDiffProjector:
    def __init__(self, current_state_repo, alert_service):
        self.repo = current_state_repo
        self.alerter = alert_service

    async def handle(self, event: PortDiscoveredEvent):
        # O(1) Lookup
        if not self.repo.has_port(event.ip_address, event.port_number):
            # Es un DIFF real en tiempo real
            await self.alerter.send_critical(
                f"🚨 Nuevo puerto abierto detectado en caliente: {event.ip_address}:{event.port_number}"
            )
            # Actualizamos la vista de lectura para que no vuelva a alertar
            self.repo.add_port(event.ip_address, event.port_number)
```

**C. Auditoría Inmutable (Event Store Adapter):**
Cada evento se guarda en una tabla SQL de eventos:
`CREATE TABLE event_store (sequence_id SERIAL, event_type VARCHAR, payload JSONB, created_at TIMESTAMP);`
Esto garantiza que OzyRecon cumple con normativas estrictas de seguridad (ISO 27001 / SOC2) porque **nada se borra ni se modifica**, todo queda firmado en la cadena de eventos.

---
*Este plan técnico está diseñado para ejecutarse progresivamente. Al mantener intacto `src/domain/`, las pruebas unitarias existentes (más de 200+) garantizarán que la lógica de OzyRecon no se rompa mientras se cambia el motor por debajo.*
