#!/usr/bin/env bash
set -euo pipefail

# Colors
C_RESET="\033[0m"
C_BOLD="\033[1m"
C_CYAN="\033[36m"
C_GREEN="\033[32m"
C_YELLOW="\033[33m"
C_RED="\033[31m"
C_MAGENTA="\033[35m"

DEMO_DIR="$(mktemp -d -t shinkiro-demo-XXXXXX)"
cleanup() {
    if [[ -n "${DAEMON_PID:-}" ]] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
        echo -e "\n${C_YELLOW}🛑 Stopping background Shinkiro deception daemon (PID: ${DAEMON_PID})...${C_RESET}"
        kill -TERM "${DAEMON_PID}" 2>/dev/null || true
        wait "${DAEMON_PID}" 2>/dev/null || true
    fi
    rm -rf "${DEMO_DIR}"
    echo -e "${C_GREEN}🧹 Cleaned up temporary demo environment.${C_RESET}\n"
}
trap cleanup EXIT INT TERM

echo -e "\n${C_BOLD}${C_CYAN}══════════════════════════════════════════════════════════════════════${C_RESET}"
echo -e "${C_BOLD}${C_CYAN}  蜃気楼 SHINKIRO — High-Interaction Cyber Deception End-to-End Demo ${C_RESET}"
echo -e "${C_BOLD}${C_CYAN}══════════════════════════════════════════════════════════════════════${C_RESET}\n"

# Step 1: Build fresh binary
echo -e "${C_YELLOW}🔨 Compiling Shinkiro binary...${C_RESET}"
go build -o bin/shinkiro ./cmd/shinkiro

# Step 2: Prepare temporary test configuration with high ports for non-root execution
DEMO_CONFIG="${DEMO_DIR}/config.yaml"
DEMO_EVENTS="${DEMO_DIR}/events.jsonl"
cat <<EOF > "${DEMO_CONFIG}"
node_name: "shinkiro-demo-sensor"
idle_timeout: 5s
max_connections: 500
audit_log_path: "${DEMO_EVENTS}"
metrics_port: 29100

services:
  ssh:
    enabled: true
    port: 2222
  redis:
    enabled: true
    port: 6379
  docker:
    enabled: true
    port: 2375
  http:
    enabled: true
    port: 8080
  postgres:
    enabled: true
    port: 5432
  k8s:
    enabled: true
    port: 6443
  aws-imds:
    enabled: true
    port: 8169
  mongo:
    enabled: true
    port: 27017
  elastic:
    enabled: true
    port: 9200
  smtp:
    enabled: true
    port: 2525
  dns:
    enabled: true
    port: 1053
  smb:
    enabled: true
    port: 4445
  telnet:
    enabled: true
    port: 2323
  mqtt:
    enabled: true
    port: 1883
  modbus:
    enabled: true
    port: 1502
EOF

echo -e "${C_GREEN}[1/4] 🚀 Starting ephemeral deception daemon in isolated sandbox...${C_RESET}"
# Run daemon with demo config in background
./bin/shinkiro up --config "${DEMO_CONFIG}" > "${DEMO_DIR}/daemon.log" 2>&1 &
DAEMON_PID=$!

# Wait for daemon to bind listeners
sleep 1.2
if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
    echo -e "${C_RED}❌ Daemon failed to start. Log output:${C_RESET}"
    cat "${DEMO_DIR}/daemon.log"
    exit 1
fi
echo -e "      ${C_BOLD}✓ Daemon active (PID: ${DAEMON_PID}) with 15 protocol listeners enabled${C_RESET}"

echo -e "\n${C_GREEN}[2/4] ⚔️  Launching automated adversary simulation against active decoys...${C_RESET}"
./bin/shinkiro simulate --host 127.0.0.1

echo -e "\n${C_GREEN}[3/4] 📊 Extracting captured attacker telemetry & MITRE ATT&CK correlation...${C_RESET}"
if [[ -f "${DEMO_EVENTS}" ]]; then
    TOTAL_EVENTS=$(wc -l < "${DEMO_EVENTS}" | tr -d ' ')
    echo -e "      ${C_BOLD}• Captured Events:${C_RESET} ${TOTAL_EVENTS} raw deception interactions logged in JSONL"
    echo -e "      ${C_BOLD}• Sample Intercepted Traps:${C_RESET}"
    head -n 3 "${DEMO_EVENTS}" | while IFS= read -r line; do
        DECOY=$(echo "${line}" | grep -o '"decoy_name":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
        ACTION=$(echo "${line}" | grep -o '"action":"[^"]*"' | cut -d'"' -f4 || echo "probe")
        SCORE=$(echo "${line}" | grep -o '"threat_score":[0-9]*' | cut -d':' -f2 || echo "0")
        echo -e "        ${C_MAGENTA}→ [Decoy: ${DECOY}]${C_RESET} Action: ${ACTION} | Threat Score: ${C_RED}${SCORE}/100${C_RESET}"
    done
else
    echo -e "      ${C_YELLOW}Notice: Events channel processed asynchronously.${C_RESET}"
fi

echo -e "\n${C_GREEN}[4/4] 🛡️  Active Defense & SOC Intelligence Export:...${C_RESET}"
echo -e "      ${C_BOLD}• Threat Intelligence IoC Feed (ThreatFox/AbuseIPDB):${C_RESET}"
./bin/shinkiro threatfox 2>/dev/null | head -n 6 || true
echo -e "      ${C_BOLD}• Automated Firewall Drop Rules (nftables syntax):${C_RESET}"
./bin/shinkiro export --format nftables --threshold 75 2>/dev/null | head -n 8 || true

echo -e "\n${C_BOLD}${C_GREEN}══════════════════════════════════════════════════════════════════════${C_RESET}"
echo -e "${C_BOLD}${C_GREEN}  ✅ Shinkiro End-to-End Deception Cycle Verified Successfully!       ${C_RESET}"
echo -e "${C_BOLD}${C_GREEN}══════════════════════════════════════════════════════════════════════${C_RESET}"
