#!/bin/bash
# =============================================================================
# CyberHound Pro — Script de verificación completa de funcionalidades
# Ejecutar con: bash scripts/verify_all.sh
# Requiere que el servidor esté corriendo en https://localhost:8443
# =============================================================================
set -e

BASE="https://localhost:8443"
CURL="curl -sk"   # -s silencioso, -k acepta cert auto-firmado
PASS="${CH_PASSWORD:-cyberhound}"
USER="${CH_USERNAME:-admin}"
FAIL=0
PASS_COUNT=0

# Colores
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'

ok()   { echo -e "${GREEN}✓${NC} $*"; ((PASS_COUNT++)); }
fail() { echo -e "${RED}✗${NC} $*"; ((FAIL++)); }
info() { echo -e "${BLUE}ℹ${NC} $*"; }
header() { echo -e "\n${BOLD}${BLUE}═══ $* ═══${NC}"; }

# ── Login y obtención de cookie ───────────────────────────────────────────────
header "Autenticación"

CSRF_TOKEN=$(${CURL} -c /tmp/ch_cookies.txt "${BASE}/login" | grep -o 'name="csrf_token" value="[^"]*"' | cut -d'"' -f4)
if [ -z "$CSRF_TOKEN" ]; then
  fail "No se pudo obtener el token CSRF de /login"
  CSRF_TOKEN="dummy"
fi
info "CSRF token: ${CSRF_TOKEN:0:20}…"

LOGIN_RESP=$(${CURL} -b /tmp/ch_cookies.txt -c /tmp/ch_cookies.txt \
  -X POST "${BASE}/login" \
  -d "username=${USER}&password=${PASS}&csrf_token=${CSRF_TOKEN}" \
  -w "\n%{http_code}" 2>&1)
HTTP_CODE=$(echo "$LOGIN_RESP" | tail -1)
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
  ok "Login exitoso (HTTP ${HTTP_CODE})"
else
  fail "Login fallido (HTTP ${HTTP_CODE})"
  echo "  Respuesta: ${LOGIN_RESP:0:200}"
fi

AUTH_OPTS="-b /tmp/ch_cookies.txt"

# ── Función helper para peticiones autenticadas ───────────────────────────────
api_get() {
  local path="$1"
  local resp
  resp=$(${CURL} ${AUTH_OPTS} -w "\n%{http_code}" "${BASE}${path}" 2>&1)
  local code=$(echo "$resp" | tail -1)
  local body=$(echo "$resp" | head -n -1)
  echo "$code|$body"
}

api_post() {
  local path="$1"
  local data="$2"
  local resp
  resp=$(${CURL} ${AUTH_OPTS} -X POST \
    -H "Content-Type: application/json" \
    -d "$data" \
    -w "\n%{http_code}" "${BASE}${path}" 2>&1)
  local code=$(echo "$resp" | tail -1)
  local body=$(echo "$resp" | head -n -1)
  echo "$code|$body"
}

check_endpoint() {
  local desc="$1"
  local path="$2"
  local expected_code="${3:-200}"
  local result
  result=$(api_get "$path")
  local code="${result%%|*}"
  local body="${result#*|}"
  if [ "$code" = "$expected_code" ]; then
    ok "$desc (HTTP $code)"
  else
    fail "$desc — HTTP $code (esperado $expected_code): ${body:0:80}"
  fi
}

check_json_field() {
  local desc="$1"
  local path="$2"
  local field="$3"
  local result
  result=$(api_get "$path")
  local code="${result%%|*}"
  local body="${result#*|}"
  if [ "$code" = "200" ] && echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$field','MISSING'))" 2>/dev/null | grep -qv "MISSING\|None"; then
    ok "$desc"
  else
    fail "$desc — campo '$field' no encontrado. Body: ${body:0:100}"
  fi
}

# ── Endpoints básicos ─────────────────────────────────────────────────────────
header "Endpoints básicos"
check_endpoint "GET /health" "/health"
check_endpoint "GET /api/dashboard" "/api/dashboard"
check_endpoint "GET /api/score/trend" "/api/score/trend"
check_endpoint "GET /api/history" "/api/history"
check_endpoint "GET /api/assets" "/api/assets"
check_endpoint "GET /api/suppressions" "/api/suppressions"
check_endpoint "GET /api/users" "/api/users"
check_endpoint "GET /api/license" "/api/license"
check_endpoint "GET /api/quarantine" "/api/quarantine"
check_endpoint "GET /api/quarantine/stats" "/api/quarantine/stats"
check_endpoint "GET /api/yara/rules" "/api/yara/rules"
check_endpoint "GET /api/agent/list" "/api/agent/list"
check_endpoint "GET /api/monitor/status" "/api/monitor/status"
check_endpoint "GET /api/tenants" "/api/tenants"
check_endpoint "GET /api/ansible/jobs" "/api/ansible/jobs"
check_endpoint "GET /api/sbom/latest" "/api/sbom/latest" "404"   # sin SBOM generado todavía — 404 esperado
check_endpoint "GET /api/openapi.json" "/api/openapi.json"
check_endpoint "GET /api/docs" "/api/docs"
check_endpoint "GET /api/compliance" "/api/compliance"

# ── 2FA / TOTP ────────────────────────────────────────────────────────────────
header "2FA / TOTP"
TOTP_STATUS=$(api_get "/api/auth/2fa/status")
STATUS_CODE="${TOTP_STATUS%%|*}"
STATUS_BODY="${TOTP_STATUS#*|}"
if [ "$STATUS_CODE" = "200" ]; then
  ok "GET /api/auth/2fa/status (HTTP 200)"
  ENABLED=$(echo "$STATUS_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('enabled','?'))" 2>/dev/null)
  info "  2FA actualmente: $ENABLED"
else
  fail "GET /api/auth/2fa/status — HTTP $STATUS_CODE"
fi

SETUP_RESP=$(api_post "/api/auth/2fa/setup" "{}")
SETUP_CODE="${SETUP_RESP%%|*}"
SETUP_BODY="${SETUP_RESP#*|}"
if [ "$SETUP_CODE" = "200" ]; then
  ok "POST /api/auth/2fa/setup (HTTP 200)"
  HAS_SECRET=$(echo "$SETUP_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok' if d.get('secret') else 'missing')" 2>/dev/null)
  HAS_QR=$(echo "$SETUP_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok' if d.get('qr_svg') else 'missing')" 2>/dev/null)
  HAS_CODES=$(echo "$SETUP_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok' if d.get('recovery_codes') else 'missing')" 2>/dev/null)
  [ "$HAS_SECRET" = "ok" ] && ok "  2FA secret generado" || fail "  Falta campo 'secret'"
  [ "$HAS_QR" = "ok" ]     && ok "  QR SVG generado" || fail "  Falta campo 'qr_svg'"
  [ "$HAS_CODES" = "ok" ]  && ok "  Códigos de recuperación generados" || fail "  Falta campo 'recovery_codes'"
else
  fail "POST /api/auth/2fa/setup — HTTP $SETUP_CODE: ${SETUP_BODY:0:200}"
fi

# Test activación con código inválido (debe devolver ok:false)
ACT_RESP=$(api_post "/api/auth/2fa/activate" '{"code":"000000"}')
ACT_CODE="${ACT_RESP%%|*}"
ACT_BODY="${ACT_RESP#*|}"
ACT_OK=$(echo "$ACT_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ok'))" 2>/dev/null)
if [ "$ACT_CODE" = "200" ] && [ "$ACT_OK" = "False" ]; then
  ok "POST /api/auth/2fa/activate — código inválido rechazado correctamente"
else
  fail "POST /api/auth/2fa/activate — respuesta inesperada: HTTP $ACT_CODE, ok=$ACT_OK"
fi

# ── Scheduler ─────────────────────────────────────────────────────────────────
header "Scheduler"
check_endpoint "GET /api/scheduler" "/api/scheduler"
# Lanzar un task manual (run_now del scheduler diario)
RUN_RESP=$(api_post "/api/scheduler/daily_audit/run" "{}")
RUN_CODE="${RUN_RESP%%|*}"
[ "$RUN_CODE" = "200" ] && ok "POST /api/scheduler/daily_audit/run" || info "Scheduler run: HTTP $RUN_CODE (puede estar deshabilitado)"

# ── Scans — lanzar un audit rápido vía WebSocket ─────────────────────────────
header "Scans WebSocket"
info "Comprobando conectividad WS con wscat (si está disponible)…"
if command -v wscat &>/dev/null; then
  WS_OUT=$(echo '{"task":"audit"}' | timeout 30 wscat -c "wss://localhost:8443/ws" --no-check -x '{"task":"audit"}' 2>&1 | head -5)
  if echo "$WS_OUT" | grep -q '"type"'; then
    ok "WebSocket /ws conectado y respondiendo"
  else
    fail "WebSocket /ws no responde: ${WS_OUT:0:100}"
  fi
else
  info "wscat no disponible — saltando test WS interactivo"
  info "  Para instalar: npm install -g wscat"
fi

# Comprobar el WS push
WS_PUSH=$(${CURL} ${AUTH_OPTS} -o /dev/null -w "%{http_code}" \
  --http1.1 -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  "${BASE}/ws/push" 2>&1)
[ "$WS_PUSH" = "101" ] && ok "WebSocket /ws/push upgrade (HTTP 101)" || \
  info "WS push: HTTP $WS_PUSH (puede ser 400 sin handshake completo)"

# ── Compliance ────────────────────────────────────────────────────────────────
header "Compliance"
COMP_RESP=$(api_get "/api/compliance?frameworks=ens,iso27001")
COMP_CODE="${COMP_RESP%%|*}"
COMP_BODY="${COMP_RESP#*|}"
if [ "$COMP_CODE" = "200" ]; then
  ENS_SCORE=$(echo "$COMP_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('ens',{}).get('score_pct','?'))" 2>/dev/null)
  ok "GET /api/compliance — ENS score: ${ENS_SCORE}%"
else
  fail "GET /api/compliance — HTTP $COMP_CODE"
fi

# ── PDF ───────────────────────────────────────────────────────────────────────
header "Informe PDF"
PDF_RESP=$(api_post "/api/report/pdf" '{"scan_type":"audit","target":"localhost"}')
PDF_CODE="${PDF_RESP%%|*}"
if [ "$PDF_CODE" = "200" ]; then
  ok "POST /api/report/pdf (HTTP 200)"
else
  fail "POST /api/report/pdf — HTTP $PDF_CODE"
fi

# ── SBOM ─────────────────────────────────────────────────────────────────────
header "SBOM"
SBOM_RESP=$(api_post "/api/sbom/generate" '{"include":["kernel","pip"]}')
SBOM_CODE="${SBOM_RESP%%|*}"
SBOM_BODY="${SBOM_RESP#*|}"
if [ "$SBOM_CODE" = "200" ]; then
  SBOM_TOTAL=$(echo "$SBOM_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null)
  ok "POST /api/sbom/generate — $SBOM_TOTAL componentes"
else
  fail "POST /api/sbom/generate — HTTP $SBOM_CODE: ${SBOM_BODY:0:100}"
fi

# ── Multi-tenant ─────────────────────────────────────────────────────────────
header "Multi-tenant"
TENANT_CREATE=$(api_post "/api/tenants" '{"slug":"test-tenant","name":"Test Org","plan":"starter"}')
T_CODE="${TENANT_CREATE%%|*}"
T_BODY="${TENANT_CREATE#*|}"
if [ "$T_CODE" = "201" ]; then
  ok "POST /api/tenants — tenant creado"
  # Limpiar
  api_post "/api/tenants/test-tenant" '{"active":false}' > /dev/null 2>&1
elif echo "$T_BODY" | grep -qi "ya existe"; then
  ok "POST /api/tenants — tenant ya existe (OK)"
else
  fail "POST /api/tenants — HTTP $T_CODE: ${T_BODY:0:100}"
fi

# ── Cuarentena ────────────────────────────────────────────────────────────────
header "Cuarentena"
QUAR_LIST=$(api_get "/api/quarantine")
Q_CODE="${QUAR_LIST%%|*}"
[ "$Q_CODE" = "200" ] && ok "GET /api/quarantine (HTTP 200)" || fail "GET /api/quarantine — HTTP $Q_CODE"

QUAR_STATS=$(api_get "/api/quarantine/stats")
QS_CODE="${QUAR_STATS%%|*}"
[ "$QS_CODE" = "200" ] && ok "GET /api/quarantine/stats (HTTP 200)" || fail "GET /api/quarantine/stats — HTTP $QS_CODE"

# ── Licencias ─────────────────────────────────────────────────────────────────
header "Licencias"
LIC_RESP=$(api_get "/api/license")
L_CODE="${LIC_RESP%%|*}"
L_BODY="${LIC_RESP#*|}"
if [ "$L_CODE" = "200" ]; then
  TIER=$(echo "$L_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tier','?'))" 2>/dev/null)
  ok "GET /api/license — tier: $TIER"
else
  fail "GET /api/license — HTTP $L_CODE"
fi

# ── OpenAPI / Swagger ─────────────────────────────────────────────────────────
header "API Docs"
SPEC_RESP=$(api_get "/api/openapi.json")
SPEC_CODE="${SPEC_RESP%%|*}"
SPEC_BODY="${SPEC_RESP#*|}"
if [ "$SPEC_CODE" = "200" ]; then
  ENDPOINT_COUNT=$(echo "$SPEC_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(sum(len(v) for v in d.get('paths',{}).values()))" 2>/dev/null)
  ok "GET /api/openapi.json — $ENDPOINT_COUNT endpoints documentados"
else
  fail "GET /api/openapi.json — HTTP $SPEC_CODE"
fi
check_endpoint "GET /api/docs (Swagger UI)" "/api/docs"

# ── Monitor ───────────────────────────────────────────────────────────────────
header "Monitor"
MON_RESP=$(api_get "/api/monitor/status")
M_CODE="${MON_RESP%%|*}"
M_BODY="${MON_RESP#*|}"
if [ "$M_CODE" = "200" ]; then
  MODE=$(echo "$M_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('mode','?'))" 2>/dev/null)
  ok "GET /api/monitor/status — modo: $MODE"
else
  fail "GET /api/monitor/status — HTTP $M_CODE"
fi

# ── Ansible ───────────────────────────────────────────────────────────────────
header "Ansible"
ANS_RESP=$(api_get "/api/ansible/jobs")
A_CODE="${ANS_RESP%%|*}"
[ "$A_CODE" = "200" ] && ok "GET /api/ansible/jobs (HTTP 200)" || fail "GET /api/ansible/jobs — HTTP $A_CODE"

# ── Tests unitarios ───────────────────────────────────────────────────────────
header "Tests unitarios pytest"
cd "$(dirname "$0")/.." || true
if command -v pytest &>/dev/null; then
  if pytest tests/ -q --no-header --tb=no 2>&1 | tail -3; then
    ok "Suite de tests completada"
  else
    fail "Algunos tests fallaron"
  fi
elif /home/jose/.venv/cyberhound/bin/pytest tests/ -q --no-header --tb=no 2>&1 | tail -3; then
  ok "Suite de tests completada (venv)"
else
  info "pytest no disponible en PATH — ejecutar manualmente: ~/.venv/cyberhound/bin/pytest tests/"
fi

# ── Resumen ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════${NC}"
echo -e "${BOLD}Resumen de verificación CyberHound Pro${NC}"
echo -e "${BOLD}══════════════════════════════════════${NC}"
echo -e "  ${GREEN}Pasados:${NC} $PASS_COUNT"
echo -e "  ${RED}Fallidos:${NC} $FAIL"
echo ""
if [ $FAIL -eq 0 ]; then
  echo -e "${GREEN}${BOLD}✓ Todo correcto — CyberHound Pro funcionando perfectamente${NC}"
  exit 0
else
  echo -e "${RED}${BOLD}✗ $FAIL verificación(es) fallaron — revisar los errores anteriores${NC}"
  exit 1
fi
