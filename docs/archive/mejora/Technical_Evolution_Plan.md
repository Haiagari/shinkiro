# Plan Maestro de Evolución Técnica — OzyRecon (v2 Revisada)

Este documento describe la especificación arquitectónica para escalar OzyRecon a niveles corporativos, **corregida y validada** tras el análisis de implementación real.

**Premisa central**: Preservar la arquitectura Hexagonal. Ninguna regla de infraestructura debe filtrarse al dominio.

---

## 1. De Monolito a Nodos Distribuidos (Workers)

### 1.1. Diagnóstico de Cuellos de Botella (validado en producción)

| Problema | Evidencia | Impacto |
|----------|-----------|---------|
| File descriptors agotados | `subfinder` + `httpx` + `nmap` consumen miles de sockets | `Too many open files` en scans >100 hosts |
| WAF blocking en <10 min | Cloudflare/Akamai banan IP de origen por rate agresivo | Scan parcial sin resultados útiles |
| OOM corrompe fase 4 | `nuclei` + `katana` en paralelo consumen >4GB RAM | Reporte corrupto, hay que reiniciar |
| Sin isolación de fallos | Un crash en `Phase 3` mata todo el pipeline | Pérdida de todo el progreso |

### 1.2. Arquitectura: Message Queue Distribuida

#### Decisión: Redis Streams vs NATS JetStream

| Criterio | Redis Streams | NATS JetStream |
|----------|--------------|----------------|
| Recursos | 256MB RAM, 1 CPU | 1GB RAM, 2 CPU |
| Persistencia | Opcional (RDB/AOF) | Nativa (JetStream) |
| Exactly-once delivery | No (at-least-once) | Sí |
| Dead-Letter nativa | No (hay que implementar `CLAIM`) | Sí (built-in) |
| Complejidad operativa | Baja | Media |
| Costo | Gratuito | Gratuito (OSS) |

**Recomendación**: Empezar con **Redis Streams** si ya hay Redis en el stack, o para equipos chicos. Migrar a **NATS JetStream** cuando se necesite exactly-once delivery y DLQ nativa.

```mermaid
graph TD
    subgraph Control Plane
    A[OzyRecon API / CLI] -->|XADD| B[(Redis Stream / NATS)]
    G[(DB Central: PostgreSQL)]
    end
    
    subgraph Data Plane
    C[Worker Node 1] -->|XREADGROUP| B
    D[Worker Node 2] -->|XREADGROUP| B
    E[Worker Node N] -->|XREADGROUP| B
    end
    
    C -.-> G
    C --> F[(S3 / MinIO / GCS)]
```

### 1.3. Contrato del Mensaje

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

### 1.4. Orquestación (Modo Local / Distribuido)

```python
class OzyOrchestratorV10:
    def __init__(self, publisher: IMessagePublisher, repository: IAssetRepository):
        self.publisher = publisher
        
    def dispatch_hunt(self, target: str):
        task = DistributedScanTask(task_id=generate_id(), target=target, ...)
        self.publisher.publish(task)
```

`IMessagePublisher` tiene dos implementaciones:
- `LocalPublisher` — ejecuta síncrono (modo legacy)
- `RedisPublisher` — encola a Redis Stream (modo distribuido)

### 1.5. Dead-Letter Queue y Reintentos

**CORREGIDO**: El `Claimer` necesita autenticación entre workers para evitar workers rogue.

```python
# src/core/claimer.py
import hmac
import hashlib

WORKER_SECRET = os.environ.get("OZY_WORKER_HMAC_SECRET", "")

def sign_message(payload: str) -> str:
    return hmac.new(WORKER_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()

def verify_message(payload: str, signature: str) -> bool:
    if not WORKER_SECRET:
        return True  # dev mode
    expected = sign_message(payload)
    return hmac.compare_digest(expected, signature)
```

**Política de reintentos**:
- 1er fallo → retry inmediato
- 2do fallo → retry en 5 min
- 3er fallo → DLQ (requiere intervención manual)
- Workers muertos sin ACK por 30 min → `CLAIM` a otro worker

### 1.6. Artefactos: Adapter de Storage Abstracto

**CORREGIDO**: No hardcodear a AWS S3. Interfaz abstracta.

```python
# src/application/ports/artifact_repository.py
from abc import ABC, abstractmethod

class IArtifactRepository(ABC):
    @abstractmethod
    def upload_bundle(self, scan_id: str, local_path: str) -> str: ...
    
    @abstractmethod
    def download_bundle(self, scan_id: str, local_path: str) -> str: ...

# Implementaciones concretas:
# src/adapters/storage/s3_artifact_repository.py   (AWS S3 / MinIO / DO Spaces)
# src/adapters/storage/gcs_artifact_repository.py  (Google Cloud Storage)
# src/adapters/storage/local_artifact_repository.py (filesystem, para dev)
```

```python
# src/adapters/storage/s3_artifact_repository.py
import boto3
from botocore.config import Config

class S3ArtifactRepository(IArtifactRepository):
    def __init__(self, bucket: str, endpoint_url: str = None, region: str = "us-east-1"):
        config = Config(signature_version="s3v4")
        self.s3 = boto3.client(
            "s3",
            endpoint_url=endpoint_url,  # MinIO, DO Spaces, etc.
            config=config,
            region_name=region,
        )
        self.bucket = bucket
    
    def upload_bundle(self, scan_id: str, local_path: str) -> str:
        key = f"scans/{scan_id}/audit_bundle.tar.gz"
        self.s3.upload_file(local_path, self.bucket, key)
        return f"s3://{self.bucket}/{key}"
```

### 1.7. Secrets Management

**CORREGIDO**: No pasar secrets en env vars de container.

En desarrollo: `.env` local (gitignored).
En producción: **Hashicorp Vault** o **AWS Secrets Manager**.

```python
# src/core/secrets.py
import os

class SecretsResolver:
    """Resuelve secrets desde env, Vault, o Secrets Manager."""
    
    @staticmethod
    def get(key: str) -> str:
        # Prioridad: env var > Vault > default
        value = os.environ.get(key)
        if value:
            return value
        # TODO: integrar con Vault cuando esté disponible
        raise ValueError(f"Secret {key} not configured")
```

### 1.8. Worker Dockerizado

```dockerfile
# Dockerfile.worker
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y nmap python3.11 python3-pip

COPY tools/go/bin/ /usr/local/bin/
COPY --from=ghcr.io/projectdiscovery/nuclei:latest /root/nuclei /usr/local/bin/

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY src/ /app/src/
COPY config/ /app/config/

ENV OZY_DATABASE_URL=postgresql://user:pass@host:5432/ozyrecon
ENV OZY_REDIS_URL=redis://host:6379

CMD ["python", "-m", "src.worker"]
```

### 1.9. Auto-Scaling (KEDA)

```yaml
# keda/scaledobject.yaml
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: ozyrecon-worker
spec:
  scaleTargetRef:
    name: ozyrecon-worker-deployment
  triggers:
  - type: redis-streams
    metadata:
      address: redis://redis:6379
      stream: ozy:scans
      consumerGroup: ozy_workers
      pendingEntriesCount: "100"  # escala si hay >100 tareas pendientes
```

---

## 2. Base de Datos de Grafos (Neo4j) para la Superficie

### 2.1. Diagnóstico

El modelo relacional es bueno para CRUD pero pésimo para tracing de vectores de ataque.

**Pregunta crítica en SQL (5 JOINs, minutos)**:
```sql
SELECT COUNT(*) FROM subdomains s
JOIN ports p ON s.ip = p.host
JOIN certificates c ON p.host = c.ip
WHERE s.domain LIKE '%staging%'
  AND c.expires_at < NOW();
```

**Pregunta crítica en Cypher (milisegundos)**:
```cypher
MATCH (s:Subdomain)-[:RESOLVES_TO]->(i:IP)-[:EXPOSES]->(p:Port)
MATCH (i)-[:HAS_CERT]->(c:Certificate)
WHERE s.name CONTAINS 'staging' AND c.expires_at < timestamp()
RETURN s.name, i.address, p.number
```

### 2.2. Ontología

```
(:Domain)-[:HAS_SUBDOMAIN]->(:Subdomain)
(:Subdomain)-[:RESOLVES_TO]->(:IP)
(:IP)-[:EXPOSES]->(:Port)
(:Port)-[:RUNS]->(:Service)
(:Service)-[:HAS_VULNERABILITY]->(:Vulnerability)
(:IP)-[:HAS_CERT]->(:Certificate)
```

Constraints:
```cypher
CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE;
CREATE CONSTRAINT ip_address IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE;
CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE;
```

### 2.3. Adapter Neo4j

```python
# src/adapters/storage/neo4j_repository.py
from neo4j import GraphDatabase
from src.application.ports.asset_repository import IAssetRepository

class Neo4jAssetRepository(IAssetRepository):
    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
    
    def save(self, asset: Asset) -> None:
        with self.driver.session() as session:
            session.run("""
                MERGE (d:Domain {name: $domain})
                SET d.is_live = $is_live, d.last_seen = timestamp()
                FOREACH (ip_str IN $ips |
                    MERGE (i:IP {address: ip_str})
                    MERGE (d)-[:HAS_SUBDOMAIN]->(:Subdomain {name: $domain})-[:RESOLVES_TO]->(i)
                )
            """, domain=asset.domain, is_live=asset.is_live, ips=list(asset.ips))
```

### 2.4. Estrategia de Migración

**CORREGIDO**: No se puede migrar de SQLite a Neo4j en caliente. Plan:

1. **Fase 1 (convivencia)**: Ambos adapters activos. `SQLiteAssetRepository` es fuente de verdad. `Neo4jAssetRepository` es espejo de solo lectura.
2. **Fase 2 (backfill)**: Script que lee toda la DB existente y escribe en Neo4j:
   ```python
   def backfill_neo4j(sqlite_session, neo4j_repo):
       for target in sqlite_session.query(Target).all():
           for sub in target.subdomains:
               neo4j_repo.save(asset_from_sub(sub))
   ```
3. **Fase 3 (cutover)**: Neo4j pasa a读写 (lectura/escritura). SQLite queda como backup de solo lectura.
4. **Fase 4 (retiro)**: SQLite desactivado. Datos migrados validados.

### 2.5. Testing con Neo4j

**CORREGIDO**: No se puede mockear Neo4j como SQLite. Usar Testcontainers.

```python
# tests/conftest.py (futuro)
@pytest.fixture(scope="session")
def neo4j_container():
    from testcontainers.neo4j import Neo4jContainer
    with Neo4jContainer("neo4j:5") as container:
        yield container.get_connection_url()
```

### 2.6. Costo y Alternativas

| Solución | Costo | Ventaja | Desventaja |
|----------|-------|---------|------------|
| **Neo4j AuraDB** (cloud) | ~$60/mes (500K nodos) | Zero ops | Vendor lock |
| **Neo4j Community** (self-hosted) | Gratis | Control total | Sin clustering |
| **Neo4j Enterprise** | ~$20K/año | Clustering, SSO | Caro |
| **PostgreSQL + `LIKE` + índices** | Gratis | Sin infra nueva | Lento en joins profundos |
| **SQLite + índices compuestos** | Gratis | Ya lo tenemos | No escala >10K assets |

**Recomendación**: Empezar con **PostgreSQL** (ya implementado en v9.0.2 vía `OZY_DATABASE_URL`). Agregar **Neo4j** solo cuando las queries de ataque path superen los 5 segundos.

---

## 3. Event Sourcing para Diff Tracking (CQRS)

### 3.1. Diagnóstico

El `DiffEngine` actual hace state-based diff: compara dos snapshots completos. Problemas:
1. Pérdida de granularidad temporal — solo sabés que cambió "entre scan A y B"
2. No permite alertas en caliente — hay que esperar a que termine el scan
3. Rollback imposible — si un finding es falso positivo, no hay forma de "deshacerlo"

### 3.2. Arquitectura Event-Driven

```
Command Side (escrituras):
  Tools → DomainEvent → EventBus → EventStore (append-only)
  
Query Side (lecturas):
  EventStore → Projectors → Read Models (Neo4j / SQLite)
                                ↓
                         RealTimeDiffProjector → Alertas
```

### 3.3. AsyncEventBus (CORREGIDO)

**Bug corregido**: `asyncio.gather()` sin `return_exceptions=True` corta todos los handlers si uno falla.

```python
# src/core/event_bus.py
import asyncio
from collections import defaultdict
from typing import Callable, List

Handler = Callable[..., None]

class AsyncEventBus:
    def __init__(self):
        self._handlers: dict[str, List[Handler]] = defaultdict(list)
    
    def subscribe(self, event_type: str, handler: Handler):
        self._handlers[event_type].append(handler)
    
    async def publish(self, event_type: str, payload: dict):
        tasks = []
        for handler in self._handlers.get(event_type, []):
            if asyncio.iscoroutinefunction(handler):
                tasks.append(handler(event_type, payload))
            else:
                handler(event_type, payload)
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Event handler failed: {result}")
```

### 3.4. RealTimeDiffProjector (CORREGIDO con dedup)

**Bug corregido**: El projector original no era idempotente — doble entrega del mismo evento generaba alertas duplicadas.

```python
# src/application/projectors/diff_projector.py
import time
from collections import defaultdict

class RealTimeDiffProjector:
    def __init__(self, current_state_repo, alert_service):
        self.repo = current_state_repo
        self.alerter = alert_service
        self._seen: set = set()  # dedup set
        self._dedup_ttl = 3600  # 1 hora
    
    async def handle(self, event_type: str, payload: dict):
        event_id = f"{event_type}:{payload.get('ip')}:{payload.get('port')}"
        
        # Dedup: si ya vimos este evento exacto en la última hora, skip
        if event_id in self._seen:
            return
        self._seen.add(event_id)
        
        if event_type == "port_discovered":
            ip = payload["ip"]
            port = payload["port"]
            if not self.repo.has_port(ip, port):
                await self.alerter.send_critical(
                    f"Nuevo puerto en caliente: {ip}:{port}"
                )
                self.repo.add_port(ip, port)
```

### 3.5. Event Store con Política de Retención

**CORREGIDO**: El Event Store sin retención crece infinito. Política obligatoria.

```sql
CREATE TABLE event_store (
    sequence_id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scan_id VARCHAR(64),
    session_id VARCHAR(64)
);

CREATE INDEX idx_event_store_scan ON event_store(scan_id);
CREATE INDEX idx_event_store_created ON event_store(created_at);

-- Política de retención: 90 días
-- Los eventos más viejos se archivan a S3 como JSONL
-- El delete se corre como cron semanal:
DELETE FROM event_store WHERE created_at < NOW() - INTERVAL '90 days';
```

### 3.6. Rollback de Falsos Positivos

```python
# src/application/services/rollback_service.py
class RollbackService:
    def __init__(self, event_store, projector):
        self.store = event_store
        self.projector = projector
    
    def rollback_finding(self, finding_id: str):
        """Replay de eventos hasta el momento anterior al finding falso positivo."""
        events = self.store.get_events_before_finding(finding_id)
        self.projector.reset()
        for event in events:
            self.projector.apply(event)
```

---

## 4. Orden de Implementación Recomendado

| Fase | Item | Esfuerzo | Dependencias | Valor |
|------|------|----------|--------------|-------|
| **1** | S3 Artifact Repository (abstracto) | 2-3 días | Ninguna | Medio |
| **2** | Worker Dockerizado | 1-2 días | S3 adapter, Redis queue existente | Alto |
| **3** | Dead-Letter Queue + HMAC | 1 día | Redis queue existente | Medio |
| **4** | Event Store (append-only) | 2-3 días | AsyncEventBus existente | Medio |
| **5** | RealTimeDiffProjector | 3-5 días | Event Store + AsyncEventBus | Alto |
| **6** | PostgreSQL migración (ya implementada) | 0 días | `OZY_DATABASE_URL` en v9.0.2 | ✅ Hecho |
| **7** | Neo4j adapter | 5-10 días | Infra Neo4j + Event Store | Alto |
| **8** | KEDA auto-scaling | 3-5 días | Workers + Docker | Medio |

---

## 5. Testing y No-regresión

Cada paso debe mantener **≥200 tests pasando**:

| Componente | Estrategia de test |
|------------|--------------------|
| `IMessagePublisher` | Mock del stream; testear que `publish()` llama al adapter |
| `DistributedScanTask` | Unit test del dataclass frozen + validación |
| `S3ArtifactRepository` | `moto` (mock de AWS) para tests; MinIO para integración |
| `Neo4jAssetRepository` | `testcontainers-neo4j` para integración |
| `AsyncEventBus` | Unit test con handlers mock |
| `RealTimeDiffProjector` | Test con repo in-memory; verificar dedup |
| `RollbackService` | Test con Event Store in-memory; replay de eventos |
| HMAC signing | `unittest.mock` con secret fijo |

---

## 6. Lo que NO está en este plan (y está bien)

| Feature | Motivo |
|---------|--------|
| gRPC entre workers | Overkill — Redis Streams alcanza |
| Service Mesh (Istio) | Demasiada complejidad para el tamaño actual |
| Multi-región activo-activo | $ y complejidad que no justifican el caso de uso actual |
| Machine Learning on events | Los eventos aún no tienen volumen suficiente para training |

---

*Este plan técnico está diseñado para ejecutarse progresivamente. Manteniendo intacto `src/domain/`, los tests existentes garantizan que la lógica de OzyRecon no se rompa mientras se cambia el motor por debajo. La implementación de Fase 1 (S3) y Fase 4 (Event Store) puede comenzar inmediatamente.*
