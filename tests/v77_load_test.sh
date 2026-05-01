#!/usr/bin/env bash
set -euo pipefail

API="http://localhost:8000"

echo "[1] Health check"
curl -s "$API/health" | jq .

echo "[2] Lanzando 20 hunts paralelos"
for i in $(seq 1 20); do
  curl -s -X POST "$API/hunt" \
    -H "Content-Type: application/json" \
    -H "X-API-KEY: ozy-secret-key" \
    -d "{\"target\":\"test$i.example.com\",\"dry_run\":true}" \
    > "load_$i.json" &
done

wait

echo "[3] Validando respuestas"
for i in $(seq 1 20); do
  echo "load_$i.json"
  cat "load_$i.json" | jq .
done

# Wait a bit for background tasks to finish writing artifacts
echo "Waiting for background tasks to finish (10s)..."
sleep 10

echo "[4] Buscando errores"
grep -RniE "sqlite|locked|traceback|exception|database is locked|NoneType" runs/ || true

echo "[5] Validando sesiones únicas"
find runs -maxdepth 1 -type d | wc -l

echo "[6] Validando artefactos"
for d in runs/*; do
  [ -d "$d" ] || continue
  test -f "$d/trace.json" || echo "MISSING trace: $d"
  test -f "$d/graph/graph.json" || echo "MISSING graph: $d"
  test -f "$d/normalized/findings.json" || echo "MISSING findings: $d"
done

echo "[7] Validando JSON corrupto"
find runs -name "*.json" -print0 | while IFS= read -r -d '' f; do
  jq empty "$f" || echo "BROKEN JSON: $f"
done

echo "LOAD TEST DONE"
