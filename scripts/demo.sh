#!/usr/bin/env bash
# MCPGuard 3-minute demo, CLI edition (the same flow works in the web UI).
#
#   1. clean servers      -> PASS
#   2. vuln_shell         -> FAIL (command injection, pickle)        [+ dynamic confirmation]
#   3. poisoned_weather   -> FAIL (tool poisoning, exfiltration)     [+ dynamic confirmation]
#   4. pin rugpull_todo, arm its toggle, verify -> CRITICAL rug pull with diff
#
# Usage: scripts/demo.sh [--dynamic]
set -euo pipefail
cd "$(dirname "$0")/.."

DYN=""
[[ "${1:-}" == "--dynamic" ]] && DYN="--dynamic"
MCPGUARD="${MCPGUARD:-mcpguard}"
TOGGLE=test_servers/rugpull_todo/.rugpull

step() { printf '\n\033[1;36m━━ %s\033[0m\n' "$*"; }
cleanup() { rm -f "$TOGGLE"; }
trap cleanup EXIT

step "1/4 Clean servers should PASS"
$MCPGUARD scan test_servers/clean_calc --fail-on never
$MCPGUARD scan test_servers/clean_notes --fail-on never

step "2/4 vuln_shell: vulnerable code"
$MCPGUARD scan test_servers/vuln_shell $DYN --fail-on never

step "3/4 poisoned_weather: hidden instructions in tool descriptions"
$MCPGUARD scan test_servers/poisoned_weather $DYN --fail-on never --report sarif --output poisoned_weather.sarif.json
echo "SARIF written to poisoned_weather.sarif.json"

step "4/4 Rug pull: pin, flip the toggle, verify"
rm -f "$TOGGLE"
$MCPGUARD pin test_servers/rugpull_todo
$MCPGUARD verify test_servers/rugpull_todo || true
echo "armed by demo" > "$TOGGLE"
echo "→ rugpull_todo armed: its next tools/list returns a poisoned description"
$MCPGUARD verify test_servers/rugpull_todo || true

step "Done. Open the UI with: $MCPGUARD serve"
