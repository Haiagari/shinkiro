# PromptWall Intelligent Scoring System — Phase 5 Specification

## Purpose

This specification defines the intelligent scoring system that evaluates discovered assets, assigning a Criticality Index (0-100) based on heuristics, service types, and context. The system integrates post-discovery to prioritize findings and drive the validation workflow.

---

## 1. Scoring Rules File Structure

### File Location
`resources/rules/scoring_rules.yaml`

### YAML Schema

```yaml
version: "5.0"
generated_by: "sdd-phase-5"
generated_at: "2026-04-26T00:00:00Z"

# Global weights for scoring factors
weights:
  reputation: 0.30      # How known/vulnerable the service is
  novelty: 0.20         # How common vs rare the finding is
  exposure: 0.25        # Public accessibility
  context: 0.25        # Target-specific context

# Service-specific heuristics
services:
  apache_php:
    base_score: 45
    factors:
      - name: "version_detected"
        weight: 0.15
        conditions:
          - value: "EOL"
            modifier: +20
          - value: "latest"
            modifier: -10
      - name: "config_exposure"
        weight: 0.20
        conditions:
          - value: "phpinfo"
            modifier: +25
          - value: "git_exposed"
            modifier: +15
          - value: "env_file"
            modifier: +20
      - name: "module_present"
        weight: 0.10
        conditions:
          - value: "mod_rewrite"
            modifier: +5
          - value: "mod_security"
            modifier: -5

  tomcat:
    base_score: 65
    factors:
      - name: "version_detected"
        weight: 0.20
        conditions:
          - value: "EOL"
            modifier: +25
          - value: "default_creds"
            modifier: +30
      - name: "path_accessible"
        weight: 0.25
        conditions:
          - value: "/manager/html"
            modifier: +20
          - value: "/admin"
            modifier: +25
          - value: "/host-manager"
            modifier: +20
      - name: "http_method"
        weight: 0.15
        conditions:
          - value: "PUT"
            modifier: +30
          - value: "WEBDAV"
            modifier: +25

  smb:
    base_score: 50
    factors:
      - name: "version_detected"
        weight: 0.15
        conditions:
          - value: "SMB1"
            modifier: +30
          - value: "anonymous"
            modifier: +15
      - name: "share_exposure"
        weight: 0.30
        conditions:
          - value: "readable_sys"
            modifier: +25
          - value: "readable_admin"
            modifier: +30
          - value: "writable"
            modifier: +35
      - name: "signing_disabled"
        weight: 0.20
        modifier: +20

  s3_bucket:
    base_score: 55
    factors:
      - name: "acl_public"
        weight: 0.25
        conditions:
          - value: "allgetops"
            modifier: +30
          - value: "allputops"
            modifier: +35
      - name: "versioning"
        weight: 0.15
        conditions:
          - value: "enabled"
            modifier: -5
          - value: "mfa_delete"
            modifier: -10
      - name: "access_logging"
        weight: 0.10
        conditions:
          - value: "enabled"
            modifier: -5
          - value: "disabled"
            modifier: +10

  jenkins:
    base_score: 60
    factors:
      - name: "auth_disabled"
        weight: 0.25
        modifier: +25
      - name: "script_console"
        weight: 0.30
        conditions:
          - value: "accessible"
            modifier: +35
          - value: "api_exposed"
            modifier: +20
      - name: "credential_present"
        weight: 0.20
        conditions:
          - value: " Plaintext"
            modifier: +30

  redis:
    base_score: 55
    factors:
      - name: "auth_disabled"
        weight: 0.30
        modifier: +30
      - name: "protected_mode"
        weight: 0.20
        conditions:
          - value: "no"
            modifier: +20
          - value: "yes"
            modifier: -10
      - name: "module_loaded"
        weight: 0.15
        conditions:
          - value: " redsss"
            modifier: +25

# Criticality thresholds
thresholds:
  critical: 80
  high: 60
  medium: 40
  low: 20

# Integration hooks
hooks:
  post_discovery: "scoring.integrate"
  on_validation_complete: "scoring.update_after_validation"
```

---

## 2. Criticality Index Data Model

### CriticalityIndex Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Unique identifier for scoring record |
| `asset_id` | String | Reference to discovered asset (port, subdomain, etc.) |
| `service_type` | String | Detected service (apache_php, tomcat, etc.) |
| `index` | Integer | Criticality Index (0-100) |
| `score_breakdown` | JSON | Individual factor scores |
| `base_score` | Integer | Service base score |
| `modifiers` | JSON | Applied modifiers |
| `risk_level` | Enum | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| `recommendations` | List | Recommended actions |
| `scored_at` | DateTime | Timestamp |
| `source` | String | Scoring method (auto, heuristic, manual) |

### Database Schema (SQLAlchemy)

```python
class CriticalityScore(Base):
    """Criticality Index for discovered assets."""
    __tablename__ = 'criticality_scores'
    
    id = Column(String(100), primary_key=True)
    asset_type = Column(String(50))  # port, subdomain, service
    asset_identifier = Column(String(255))  # host:port, domain, etc.
    service_type = Column(String(50))
    
    index = Column(Integer)  # 0-100
    risk_level = Column(String(20))  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    
    score_breakdown = Column(JSON)  # { factor: score }
    base_score = Column(Integer)
    modifiers = Column(JSON)  # { modifier_name: value }
    
    recommendations = Column(JSON)  # List of recommended actions
    
    scored_at = Column(DateTime, default=datetime.utcnow)
    source = Column(String(50), default="heuristic")
    
    # Links to other models
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=True)
    target_id = Column(Integer, ForeignKey('targets.id'), nullable=True)
```

### Risk Level Mapping

| Index Range | Risk Level | Color | Priority |
|------------|-----------|-------|---------|
| 80-100 | CRITICAL | #dc2626 | P1 |
| 60-79 | HIGH | #f59e0b | P2 |
| 40-59 | MEDIUM | #3b82f6 | P3 |
| 20-39 | LOW | #6b7280 | P4 |
| 0-19 | INFO | #9ca3af | P5 |

---

## 3. Service-Specific Heuristic Rules

### 3.1 Apache + PHP

**Base Score**: 45

| Factor | Weight | Condition | Modifier |
|--------|--------|----------|----------|
| Version detected | 0.15 | EOL | +20 |
| Version detected | 0.15 | latest-stable | -10 |
| phpinfo() exposed | 0.20 | present | +25 |
| .git exposed | 0.20 | present | +15 |
| .env file exposed | 0.20 | present | +20 |
| mod_rewrite | 0.10 | present | +5 |
| mod_security | 0.10 | enabled | -5 |

**Recommendations**:
- If phpinfo() exposed → "Critical: Information disclosure via phpinfo()"
- If .env exposed → "Critical: Secrets exposure via .env file"
- If version EOL → "High: Outdated Apache/PHP version"

### 3.2 Apache Tomcat

**Base Score**: 65

| Factor | Weight | Condition | Modifier |
|--------|--------|----------|----------|
| Version EOL | 0.20 | yes | +25 |
| Default credentials | 0.20 | tomcat:tomcat | +30 |
| /manager/html | 0.25 | accessible | +20 |
| /admin | 0.25 | accessible | +25 |
| PUT enabled | 0.15 | yes | +30 |
| WEBDAV enabled | 0.15 | yes | +25 |

**Recommendations**:
- If /manager accessible → "High: Deployer interface exposed"
- If PUT enabled → "Critical: File upload via PUT possible"

### 3.3 SMB

**Base Score**: 50

| Factor | Weight | Condition | Modifier |
|--------|--------|----------|----------|
| SMB1 dialect | 0.15 | yes | +30 |
| Anonymous access | 0.15 | enabled | +15 |
| Readable SYSVOL | 0.30 | yes | +25 |
| Readable ADMIN$ | 0.30 | yes | +30 |
| Writable share | 0.35 | yes | +35 |
| Signing disabled | 0.20 | yes | +20 |

**Recommendations**:
- If SMB1 → "High: SMB1 vulnerable to NBSP"
- If writable share → "Critical: Code execution via writable share"

### 3.4 S3 Buckets

**Base Score**: 55

| Factor | Weight | Condition | Modifier |
|--------|--------|----------|----------|
| ACL allgetops | 0.25 | yes | +30 |
| ACL allputops | 0.25 | yes | +35 |
| Versioning enabled | 0.15 | yes | -5 |
| MFA delete | 0.15 | enabled | -10 |
| Logging disabled | 0.10 | yes | +10 |

**Recommendations**:
- If allputops → "Critical: Full bucket control"
- If allgetops → "High: Data exfiltration possible"

### 3.5 Jenkins

**Base Score**: 60

| Factor | Weight | Condition | Modifier |
|--------|--------|----------|----------|
| Authentication | 0.25 | disabled | +25 |
| Script console | 0.30 | accessible | +35 |
| API exposed | 0.30 | yes | +20 |
| Plaintext creds | 0.20 | present | +30 |

**Recommendations**:
- If auth disabled → "Critical: Unauthenticated code execution"
- If script console → "Critical: Groovy RCE via script console"

### 3.6 Redis

**Base Score**: 55

| Factor | Weight | Condition | Modifier |
|--------|--------|----------|----------|
| Authentication | 0.30 | disabled | +30 |
| Protected mode | 0.20 | no | +20 |
| Module loaded | 0.15 | yes | +25 |
| Config write | 0.15 | allowed | +30 |

**Recommendations**:
- If auth disabled → "Critical: Unauthenticated Redis access"
- If config write → "Critical: RCE via Redis CONFIG"

---

## 4. Post-Discovery Integration

### Integration Point

After discovery phase completes, the scoring engine is invoked:

```
Discovery → Scoring Engine → Criticality Index → Validation Queue
```

### API Interface

```python
class ScoringEngine:
    def __init__(self, rules_path: str = "resources/rules/scoring_rules.yaml"):
        self.rules = self._load_rules(rules_path)
    
    def score_asset(self, asset: dict) -> CriticalityScore:
        """
        Score a discovered asset.
        
        Args:
            asset: {
                "type": "port" | "subdomain",
                "identifier": "192.168.1.1:80",
                "service": "apache" | "tomcat" | "smb" | "redis",
                "details": { ... service-specific data }
            }
        
        Returns:
            CriticalityScore object
        """
        pass
    
    def score_batch(self, assets: list) -> list[CriticalityScore]:
        """Score multiple assets in batch."""
        pass
    
    def get_priority_queue(self, limit: int = 10) -> list[CriticalityScore]:
        """Get highest-priority assets for validation."""
        pass
```

### Workflow Integration

```python
# In discovery/services/ports.py - after service detection
def run_ports(hosts, out_dir, args, context={}):
    # ... existing discovery code ...
    
    # NEW: Score discovered services
    from src.scoring.engine import scoring_engine
    
    for host, services in results["services"].items():
        for service in services:
            asset = {
                "type": "port",
                "identifier": f"{host}:{service.port}",
                "service": service.product,
                "details": {
                    "version": service.version,
                    "banner": service.extra_info,
                    "http_paths": service.http_paths
                }
            }
            scoring_engine.score_asset(asset)
    
    return results
```

---

## 5. Scenario Specifications

### Scenario 5.1: Successful Scoring

- GIVEN a target "example.com" with detected Apache/2.4.41 + PHP/8.1
- AND phpinfo() page accessible at http://example.com/index.php
- WHEN the scoring engine processes the asset
- THEN the CriticalityIndex SHALL be 70 or higher
- AND the risk_level SHALL be "HIGH"
- AND recommendations SHALL include "Critical: Information disclosure via phpinfo()"

**Flow**:
```
1. Discovery finds port 80 with Apache banner
2. Active scan reveals PHP version and phpinfo() path
3. Scoring engine loads apache_php rules
4. Calculate: base_score(45) + version_latest(-10) + phpinfo(+25) = 60
5. + reputation factor based on target context
6. Final index: 70
7. Save to criticality_scores table
8. Add to validation queue with P2 priority
```

### Scenario 5.2: Insufficient Data

- GIVEN a target "example.com" with port 6379 open
- AND nmap could not determine service version
- AND no additional details available
- WHEN the scoring engine processes the asset
- THEN the index SHALL be the base_score (55 for Redis)
- AND source SHALL be "auto_minimal"
- AND recommendations SHALL include "Review required: verify service manually"

**Flow**:
```
1. Discovery finds port 6379 open
2. Service detection inconclusive
3. Scoring engine applies base_score only
4. Index = 55 (Redis default)
5. Mark for manual review
```

### Scenario 5.3: Multiple Factors

- GIVEN a target "example.com" with Jenkins discovered at /jenkins/
- AND authentication not required
- AND script console accessible
- AND credentials found in source code
- WHEN the scoring engine processes the asset
- THEN the CriticalityIndex SHALL be 95 or higher
- AND the risk_level SHALL be "CRITICAL"

**Flow**:
```
1. Discovery finds Jenkins via HTTP title
2. Auth check confirms no login required
3. Path scan finds /scriptConsole/
4. Credential scan finds API tokens
5. Scoring: base(60) + noauth(+25) + scriptconsole(+35) + creds(+30) = 150
6. Cap to 100, risk_level = CRITICAL
```

### Scenario 5.4: Low Priority Asset

- GIVEN a target "example.com" with Apache 2.4.62 (latest)
- AND up-to-date security headers only
- AND no sensitive paths found
- WHEN the scoring engine processes the asset
- THEN the index SHALL be 35 or lower
- AND the risk_level SHALL be "LOW"

---

## 6. Requirements Summary

| Requirement | Strength | Description |
|-------------|----------|-------------|
| scoring_rules_yaml | MUST |.rules.yaml file with service heuristics |
| criticality_index_0_100 | MUST | Integer index range 0-100 |
| risk_level_mapping | MUST | Map index to CRITICAL/HIGH/MEDIUM/LOW/INFO |
| service_heuristics_6 | MUST | Rules for Apache+PHP, Tomcat, SMB, S3, Jenkins, Redis |
| post_discovery_hook | MUST | Integrate after discovery phase |
| insufficient_data_handling | MUST | Handle partial data gracefully |
| priority_queue | SHOULD | Return sorted assets by priority |

---

## 7. Acceptance Criteria

- [ ] `resources/rules/scoring_rules.yaml` exists with all 6 service rules
- [ ] CriticalityIndex returns integer 0-100
- [ ] Risk level correctly mapped per thresholds
- [ ] Scoring engine callable after discovery completes
- [ ] Assets with insufficient data receive minimum base score
- [ ] Recommendations included in scoring output
- [ ] Database model persisted for future queries