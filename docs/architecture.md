# OzyRecon Architecture (v9.0.1)

OzyRecon v9.0.1 is built on the **Hexagonal Architecture** (Ports & Adapters) pattern. This ensures that the core security logic is independent of external tools, databases, or interfaces.

## 🏗️ Layer Structure

### 1. Domain Layer (`src/domain/`)
The "Heart" of the system. Contains pure Python entities with no external dependencies.
- **Models**: `Asset`, `Service`, `Finding`, `Evidence`, `Scan`.
- **Services**: `EvidenceService` (Hashing and Digital Signatures).
- **Events**: `AssetDiscovered`, `FindingDetected`.

### 2. Application Layer (`src/application/`)
Orchestrates the business logic by connecting the Domain Layer with the Ports.
- **Use Cases**: `OzyOrchestratorV10` (The Conductor).
- **Artifact Studio**: Packaging and compression of audit bundles.
- **Ports (Interfaces)**: 
    - `IAssetRepository`: Persistence interface.
    - `IToolProvider`: Execution interface for scanners.

### 3. Adapters Layer (`src/adapters/`)
Concrete implementations of the Ports.
- **Storage**: `SQLiteAssetRepository` (SQLAlchemy).
- **Tools**: `NmapAdapter`, `NucleiAdapter`, `SubfinderAdapter`.
- **Events**: `WebhookEventAdapter`.

## ⚡ Concurrency & Execution Model

OzyRecon optimiza las operaciones intensivas de I/O a través de paralelismo nativo en Python.

1. **Paralelismo de Red (`ThreadPoolExecutor`)**: 
   - Los módulos de escaneo intensivo (como `ffuf` y `SecretFinder`) agrupan sus cargas de trabajo.
   - Utilizan un `ThreadPoolExecutor` acotado (ej. `max_workers=3`) para ejecutar tareas concurrentemente sin sobrecargar el hardware local o generar bloqueos en la red.
2. **Subprocesos Inteligentes (`subprocess`)**:
   - Se orquestan binarios externos escritos en lenguajes de alto rendimiento (Go) como `ffuf` o `subfinder`, limitando el impacto del Global Interpreter Lock (GIL) en el proceso principal.
3. **Manejo Seguro de Estados**:
   - Se utiliza `threading.Lock()` de manera granular (ej. en `RateLimiter`) garantizando *thread-safety* al modificar estados compartidos como variables de control o colecciones (`list.extend()`).

## 🔐 Trust Layer & Security

OzyRecon v9.0.1 implements a cryptographic Trust Layer to ensure data integrity:
1. **Hashing**: Every `Evidence` content is hashed using **SHA256**.
2. **Signature**: The content hash is signed using an **RSA/ECDSA** private key.
3. **Traceability**: Findings are linked to signed evidence, providing audit-ready artifacts.

## 🔄 Execution Flow (v9.0.1)

1. `CLI` invokes `OrchestratorV10`.
2. `ToolAdapters` execute and return `Domain Entities`.
3. `EvidenceService` signs the results.
4. `Repository` persists data.
5. `EventBus` broadcasts findings to the ecosystem.
