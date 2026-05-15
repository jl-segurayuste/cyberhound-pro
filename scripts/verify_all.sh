#!/bin/bash
# CyberHound Pro — Verificación completa
# Uso: bash scripts/verify_all.sh
# Variables opcionales: CH_PASSWORD=xxx CH_USERNAME=admin

BASE="https://localhost:8443"
PASS="${CH_PASSWORD:-cyberhound}"
USER="${CH_USERNAME:-admin}"
COOKIES="/tmp/ch_cookies_$$.txt"
FAIL=0; OK_COUNT=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'

ok()  { echo -e "  ${GREEN}✓${NC} $*"; ((OK_COUNT++)) || true; }
fail(){ echo -e "  ${RED}✗${NC} $*"; ((FAIL++)) || true; }
info(){ echo -e "  ${BLUE}ℹ${NC} $*"; }
hdr() { echo -e "\n${BOLD}${BLUE}═══ $* ═══${NC}"; }
trap "rm -f $COOKIES" EXIT

C="curl -sk --max-time 15 -b $COOKIES -c $COOKIES"

# ── Login ─────────────────────────────────────────────────────────────────────
hdr "1. Autenticación"

# Obtener página de login
PAGE=$($C "${BASE}/login" 2>&1)
if [ -z "$PAGE" ]; then
  fail "No se puede conectar a ${BASE} — ¿está el servidor corriendo?"
  echo -e "\n  ${YELLOW}Iniciar servidor:${NC} sudo cyberhound web --port 8443 &"
  exit 1
fi
ok "Servidor accesible en ${BASE}"

# Extraer token CSRF (campo _csrf)
CSRF=$(echo "$PAGE" | python3 -c "
import sys, re
html = sys.stdin.read()
for pat in [
    r'name=[\"_csrf\"]+\s+value=\"([^\"]+)\"',
    r'value=\"([^\"]+)\"\s+name=\"_csrf\"',
    r'_csrf.*?value=\"([^\"]+)\"',
    r'value=\"([a-f0-9]{32,})\"',
]:
    m = re.search(pat, html, re.IGNORECASE)
    if m:
        print(m.group(1))
        break
" 2>/dev/null)

[ -z "$CSRF" ] && CSRF="noop"
info "Token CSRF: ${CSRF:0:16}…"

# Login POST
HTTP=$($C -X POST "${BASE}/login" \
  -d "username=${USER}&password=${PASS}&_csrf=${CSRF}" \
  -o /dev/null -w "%{http_code}" 2>&1)

if [ "$HTTP" = "200" ] || [ "$HTTP" = "302" ]; then
  if grep -q "ch_token" "$COOKIES" 2>/dev/null; then
    ok "Login exitoso (HTTP ${HTTP}) — cookie JWT obtenida"
  else
    fail "HTTP ${HTTP} pero sin cookie JWT. Verifica: CH_PASSWORD=tupass bash $0"
  fi
else
  fail "Login fallido — HTTP ${HTTP}. Verifica contraseña: CH_PASSWORD=tupass bash $0"
fi

# ── Helper ────────────────────────────────────────────────────────────────────
GET() {
  local r; r=$($C -w "\n%{http_code}" "${BASE}$1" 2>&1)
  echo "${r##*$'\n'}|${r%$'\n'*}"
}
POST() {
  local r; r=$($C -X POST -H "Content-Type: application/json" \
    -d "${2:-{}}" -w "\n%{http_code}" "${BASE}$1" 2>&1)
  echo "${r##*$'\n'}|${r%$'\n'*}"
}
JQ() { echo "$1" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    for k in '$2'.split('.'): d=d.get(k,'?') if isinstance(d,dict) else '?'
    print(d)
except: print('?')
" 2>/dev/null; }
CHK() {
  local desc="$1" path="$2" exp="${3:-200}"
  local r; r=$(GET "$path")
  local code="${r%%|*}"
  [ "$code" = "$exp" ] && ok "$desc" || fail "$desc — HTTP $code (esperado $exp)"
}

# ── Endpoints básicos ─────────────────────────────────────────────────────────
hdr "2. Endpoints básicos"
CHK "GET /health"                  "/health"
CHK "GET /api/dashboard"           "/api/dashboard"
CHK "GET /api/score/trend"         "/api/score/trend"
CHK "GET /api/history"             "/api/history"
CHK "GET /api/assets"              "/api/assets"
CHK "GET /api/suppressions"        "/api/suppressions"
CHK "GET /api/users"               "/api/users"
CHK "GET /api/scheduler"           "/api/scheduler"
CHK "GET /api/license"             "/api/license"
CHK "GET /api/quarantine"          "/api/quarantine"
CHK "GET /api/quarantine/stats"    "/api/quarantine/stats"
CHK "GET /api/yara/rules"          "/api/yara/rules"
CHK "GET /api/agent/list"          "/api/agent/list"
CHK "GET /api/monitor/status"      "/api/monitor/status"
CHK "GET /api/tenants"             "/api/tenants"
CHK "GET /api/ansible/jobs"        "/api/ansible/jobs"
CHK "GET /api/openapi.json"        "/api/openapi.json"
CHK "GET /api/docs"                "/api/docs"
CHK "GET /api/compliance"          "/api/compliance"
CHK "GET /api/config/keys"         "/api/config/keys"
CHK "GET /api/config/notifications""/api/config/notifications"
CHK "GET /api/config/siem"         "/api/config/siem"
CHK "GET /api/sbom/latest (404 OK)""/api/sbom/latest" "404"

# ── 2FA ──────────────────────────────────────────────────────────────────────
hdr "3. 2FA / TOTP"

R=$(GET "/api/auth/2fa/status"); CODE="${R%%|*}"; BODY="${R#*|}"
[ "$CODE" = "200" ] && ok "GET /api/auth/2fa/status — enabled: $(JQ "$BODY" "enabled")" \
                      || fail "GET /api/auth/2fa/status — HTTP $CODE"

R=$(POST "/api/auth/2fa/setup" "{}"); CODE="${R%%|*}"; BODY="${R#*|}"
if [ "$CODE" = "200" ]; then
  ok "POST /api/auth/2fa/setup"
  SECRET=$(JQ "$BODY" "secret")
  HAS_QR=$(echo "$BODY" | python3 -c "import sys,json; print('si' if json.load(sys.stdin).get('qr_svg') else 'no')" 2>/dev/null)
  HAS_RC=$(echo "$BODY" | python3 -c "import sys,json; print('si' if json.load(sys.stdin).get('recovery_codes') else 'no')" 2>/dev/null)
  [ "$HAS_QR" = "si" ] && ok "  QR SVG generado" || fail "  Falta qr_svg"
  [ "$HAS_RC" = "si" ] && ok "  Códigos de recuperación presentes" || fail "  Faltan recovery_codes"
  ok "  Secret: ${SECRET:0:12}…"
else
  fail "POST /api/auth/2fa/setup — HTTP $CODE: ${BODY:0:200}"
fi

R=$(POST "/api/auth/2fa/activate" '{"code":"000000"}'); CODE="${R%%|*}"; BODY="${R#*|}"
ACT_OK=$(JQ "$BODY" "ok")
[ "$CODE" = "200" ] && [ "$ACT_OK" = "False" ] \
  && ok "POST /api/auth/2fa/activate — código inválido rechazado" \
  || fail "POST /api/auth/2fa/activate — HTTP $CODE, ok=$ACT_OK"

# ── Compliance ────────────────────────────────────────────────────────────────
hdr "4. Compliance"
R=$(GET "/api/compliance?frameworks=ens,iso27001,cis"); CODE="${R%%|*}"; BODY="${R#*|}"
if [ "$CODE" = "200" ]; then
  ok "GET /api/compliance — ENS: $(JQ "$BODY" "ens.score_pct")%, ISO: $(JQ "$BODY" "iso27001.score_pct")%, CIS: $(JQ "$BODY" "cis.score_pct")%"
else
  fail "GET /api/compliance — HTTP $CODE"
fi

R=$(POST "/api/compliance" '{"frameworks":["ens"]}'); CODE="${R%%|*}"
[ "$CODE" = "200" ] && ok "POST /api/compliance" || fail "POST /api/compliance — HTTP $CODE"

# ── PDF ───────────────────────────────────────────────────────────────────────
hdr "5. Informe PDF"
R=$(POST "/api/report/pdf" '{"scan_type":"audit","target":"localhost"}')
CODE="${R%%|*}"; BODY="${R#*|}"
[ "$CODE" = "200" ] && ok "POST /api/report/pdf" || fail "POST /api/report/pdf — HTTP $CODE: ${BODY:0:80}"

# ── SBOM ─────────────────────────────────────────────────────────────────────
hdr "6. SBOM"
R=$(POST "/api/sbom/generate" '{"include":["kernel"]}'); CODE="${R%%|*}"; BODY="${R#*|}"
if [ "$CODE" = "200" ]; then
  ok "POST /api/sbom/generate — $(JQ "$BODY" "total") componentes"
else
  fail "POST /api/sbom/generate — HTTP $CODE: ${BODY:0:80}"
fi

# ── Multi-tenant ─────────────────────────────────────────────────────────────
hdr "7. Multi-tenant"
R=$(POST "/api/tenants" '{"slug":"verify-tmp","name":"Test","plan":"starter"}')
CODE="${R%%|*}"; BODY="${R#*|}"
if [ "$CODE" = "201" ]; then
  ok "POST /api/tenants — tenant creado"
  POST "/api/tenants/verify-tmp" '{"active":false}' > /dev/null 2>&1
elif echo "$BODY" | grep -qi "existe\|already"; then
  ok "POST /api/tenants — tenant ya existe (OK)"
else
  fail "POST /api/tenants — HTTP $CODE: ${BODY:0:80}"
fi
CHK "GET /api/tenants" "/api/tenants"

# ── OpenAPI ───────────────────────────────────────────────────────────────────
hdr "8. OpenAPI / Swagger"
R=$(GET "/api/openapi.json"); CODE="${R%%|*}"; BODY="${R#*|}"
if [ "$CODE" = "200" ]; then
  NEPS=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(sum(len(v) for v in d.get('paths',{}).values()))" 2>/dev/null)
  ok "GET /api/openapi.json — ${NEPS} endpoints documentados"
else
  fail "GET /api/openapi.json — HTTP $CODE"
fi
CHK "GET /api/docs (Swagger UI)" "/api/docs"

# ── Ansible ───────────────────────────────────────────────────────────────────
hdr "9. Ansible"
CHK "GET /api/ansible/jobs" "/api/ansible/jobs"
R=$(POST "/api/ansible/run" '{"mode":"local","target":"localhost"}')
CODE="${R%%|*}"; BODY="${R#*|}"
[ "$CODE" = "200" ] \
  && ok "POST /api/ansible/run" \
  || info "POST /api/ansible/run — HTTP $CODE (sin scan disponible es normal)"

# ── Monitor ───────────────────────────────────────────────────────────────────
hdr "10. Monitor"
R=$(GET "/api/monitor/status"); CODE="${R%%|*}"; BODY="${R#*|}"
if [ "$CODE" = "200" ]; then
  MODE=$(JQ "$BODY" "mode"); ACTIVE=$(JQ "$BODY" "active")
  ok "GET /api/monitor/status — modo: $MODE, activo: $ACTIVE"
  [ "$ACTIVE" = "False" ] && info "  Para activar: sudo apt install auditd && sudo systemctl enable --now auditd"
else
  fail "GET /api/monitor/status — HTTP $CODE"
fi

# ── Agentes ───────────────────────────────────────────────────────────────────
hdr "11. Agentes"
CHK "GET /api/agent/list" "/api/agent/list"

# ── Tests pytest ──────────────────────────────────────────────────────────────
hdr "12. Tests unitarios (pytest)"
PYTEST=""
for p in \
  "/home/jose/.venv/cyberhound/bin/pytest" \
  "$(which pytest 2>/dev/null)" \
  "/home/$(whoami)/.venv/cyberhound/bin/pytest"; do
  [ -x "$p" ] && PYTEST="$p" && break
done

if [ -n "$PYTEST" ]; then
  cd "$(dirname "$0")/.." 2>/dev/null
  $PYTEST tests/ -q --no-header --tb=line 2>&1 | tail -5
  [ ${PIPESTATUS[0]} -eq 0 ] && ok "Suite pytest — todos pasados" || fail "Algunos tests fallaron"
else
  info "pytest no en PATH — ejecutar manualmente:"
  info "  ~/.venv/cyberhound/bin/pytest tests/ -q"
fi

# ── Resumen ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════${NC}"
echo -e "${BOLD}  Resumen CyberHound Pro Verificación  ${NC}"
echo -e "${BOLD}═══════════════════════════════════════${NC}"
echo -e "  ${GREEN}✓ Pasados:${NC}  ${OK_COUNT}"
echo -e "  ${RED}✗ Fallidos:${NC} ${FAIL}"
echo ""
if [ $FAIL -eq 0 ]; then
  echo -e "${GREEN}${BOLD}  ✓ CyberHound Pro funcionando correctamente${NC}"
  exit 0
else
  echo -e "${RED}${BOLD}  ✗ ${FAIL} fallo(s) — ver errores anteriores${NC}"
  echo ""
  echo -e "  ${YELLOW}Resolución rápida:${NC}"
  echo "  • Contraseña: CH_PASSWORD=tupass bash scripts/verify_all.sh"
  echo "  • Logs: sudo journalctl -u cyberhound -n 30"
  echo "  • Estado: sudo systemctl status cyberhound"
  exit 1
fi
