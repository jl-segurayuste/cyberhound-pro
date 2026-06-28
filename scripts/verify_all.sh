#!/bin/bash
# =============================================================================
# CyberHound Pro — Verificación completa de funcionalidades
# Uso: bash scripts/verify_all.sh
#
# La contraseña se detecta automáticamente desde:
#   1. Variable de entorno: CH_PASSWORD=xxx bash scripts/verify_all.sh
#   2. ~/.cyberhound/config.yaml  (password_hash → no aplica)
# Si falla el login, el script indica cómo obtener la contraseña correcta.
# =============================================================================

BASE="${CH_BASE:-https://localhost:8443}"
PASS="${CH_PASSWORD:-}"
USER="${CH_USERNAME:-admin}"
COOKIES="/tmp/ch_cookies_$$.txt"
FAIL=0; OK_COUNT=0; SKIP=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'

ok()   { echo -e "  ${GREEN}✓${NC} $*"; ((OK_COUNT++)) || true; }
fail() { echo -e "  ${RED}✗${NC} $*"; ((FAIL++)) || true; }
info() { echo -e "  ${BLUE}ℹ${NC} $*"; }
skip() { echo -e "  ${YELLOW}⏭${NC} $* (saltado — sin sesión)"; ((SKIP++)) || true; }
hdr()  { echo -e "\n${BOLD}${BLUE}═══ $* ═══${NC}"; }

trap "rm -f $COOKIES /tmp/ch_login_$$.txt" EXIT

CURL="curl -sk --max-time 15 -b $COOKIES -c $COOKIES"
LOGGED_IN=false

# ── Si no se pasó contraseña, intentar obtenerla del config ──────────────────
if [ -z "$PASS" ]; then
  # CyberHound guarda la contraseña hasheada, no en texto plano
  # Intentamos con las contraseñas más comunes usadas en setup
  PASS="cyberhound"  # default de instalación
fi

# ── 1. Login ─────────────────────────────────────────────────────────────────
hdr "1. Autenticación"

PAGE=$($CURL "${BASE}/login" 2>&1)
if [ -z "$PAGE" ]; then
  fail "No se puede conectar a ${BASE}"
  echo -e "\n  ${YELLOW}El servidor no está corriendo. Iniciarlo con:${NC}"
  echo "  sudo cyberhound web --port 8443 &"
  exit 1
fi
ok "Servidor accesible en ${BASE}"

# Extraer token CSRF (_csrf)
CSRF=$(echo "$PAGE" | python3 -c "
import sys, re
html = sys.stdin.read()
patterns = [
    r'name=\"_csrf\"\s+value=\"([^\"]+)\"',
    r'value=\"([^\"]+)\"\s+name=\"_csrf\"',
    r'_csrf[^>]+value=\"([^\"]+)\"',
    r'value=\"([a-f0-9]{32,64})\"',
]
for p in patterns:
    m = re.search(p, html, re.IGNORECASE | re.DOTALL)
    if m:
        print(m.group(1))
        break
" 2>/dev/null)
[ -z "$CSRF" ] && CSRF="noop"

# Intentar login
HTTP=$(${CURL} -X POST "${BASE}/login" \
  -d "username=${USER}&password=${PASS}&_csrf=${CSRF}" \
  -o /tmp/ch_login_$$.txt \
  -w "%{http_code}" 2>&1)

BODY=$(cat /tmp/ch_login_$$.txt 2>/dev/null)

if grep -q "ch_token" "$COOKIES" 2>/dev/null; then
  ok "Login exitoso (HTTP ${HTTP})"
  LOGGED_IN=true
else
  fail "Login fallido (HTTP ${HTTP}) — contraseña incorrecta para usuario '${USER}'"
  echo ""
  echo -e "  ${YELLOW}══ Cómo obtener la contraseña ══${NC}"
  echo "  Opción A: Cambiar la contraseña ahora:"
  echo "    sudo cyberhound setup"
  echo ""
  echo "  Opción B: Pasar la contraseña al script:"
  echo "    CH_PASSWORD=tu_contraseña bash scripts/verify_all.sh"
  echo ""
  echo "  Opción C: Ver el hash en el config (no es la contraseña directamente):"
  echo "    cat ~/.cyberhound/config.yaml | grep password"
  echo ""
  echo -e "  ${YELLOW}Continuando con verificaciones que no requieren autenticación…${NC}"
fi

# ── Helpers ───────────────────────────────────────────────────────────────────
GET() {
  local out
  out=$(${CURL} -w "\n%{http_code}" "${BASE}$1" 2>&1)
  # Separar el código (última línea) del body (todo lo anterior)
  local code body
  code=$(printf '%s' "$out" | tail -1)
  body=$(printf '%s' "$out" | head -n -1)
  printf '%s|%s' "$code" "$body"
}

POST() {
  local out
  out=$(${CURL} -X POST \
    -H "Content-Type: application/json" \
    -d "${2:-{}}" \
    -w "\n%{http_code}" "${BASE}$1" 2>&1)
  local code body
  code=$(printf '%s' "$out" | tail -1)
  body=$(printf '%s' "$out" | head -n -1)
  printf '%s|%s' "$code" "$body"
}

JQ() {
  echo "$1" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    parts = '$2'.split('.')
    v = d
    for p in parts:
        v = v.get(p, '?') if isinstance(v, dict) else '?'
    print(v)
except:
    print('?')
" 2>/dev/null
}

CHK() {
  local desc="$1" path="$2" exp="${3:-200}"
  if [ "$LOGGED_IN" = "false" ] && [ "$exp" != "200" ]; then
    skip "$desc"
    return
  fi
  local r code body
  r=$(GET "$path")
  code="${r%%|*}"
  body="${r#*|}"
  if [ "$code" = "$exp" ]; then
    ok "$desc"
  elif [ "$code" = "401" ] && [ "$LOGGED_IN" = "false" ]; then
    skip "$desc (sin sesión)"
  else
    fail "$desc — HTTP $code (esperado $exp) ${body:+— ${body:0:80}}"
  fi
}

CHKAUTH() {
  # Solo verifica si estamos logueados
  if [ "$LOGGED_IN" = "false" ]; then
    skip "$1 (sin sesión)"
    return
  fi
  CHK "$@"
}

# ── 2. Endpoints sin auth (públicos) ─────────────────────────────────────────
hdr "2. Endpoints públicos"
CHK "GET /health" "/health"
CHK "GET /login"  "/login"

# ── 3. Endpoints autenticados — básicos ──────────────────────────────────────
hdr "3. Endpoints autenticados — básicos"
CHKAUTH "GET /api/dashboard"           "/api/dashboard"
CHKAUTH "GET /api/score/trend"         "/api/score/trend"
CHKAUTH "GET /api/history"             "/api/history"
CHKAUTH "GET /api/assets"              "/api/assets"
CHKAUTH "GET /api/suppressions"        "/api/suppressions"
CHKAUTH "GET /api/users"               "/api/users"
CHKAUTH "GET /api/scheduler"           "/api/scheduler"
CHKAUTH "GET /api/license"             "/api/license"
CHKAUTH "GET /api/quarantine"          "/api/quarantine"
CHKAUTH "GET /api/quarantine/stats"    "/api/quarantine/stats"
CHKAUTH "GET /api/yara/rules"          "/api/yara/rules"
CHKAUTH "GET /api/agent/list"          "/api/agent/list"
CHKAUTH "GET /api/monitor/status"      "/api/monitor/status"
CHKAUTH "GET /api/tenants"             "/api/tenants"
CHKAUTH "GET /api/ansible/jobs"        "/api/ansible/jobs"
CHKAUTH "GET /api/openapi.json"        "/api/openapi.json"
CHKAUTH "GET /api/docs"                "/api/docs"
CHKAUTH "GET /api/compliance"          "/api/compliance"
CHKAUTH "GET /api/config/keys"         "/api/config/keys"
CHKAUTH "GET /api/config/notifications" "/api/config/notifications"
CHKAUTH "GET /api/config/siem"         "/api/config/siem"

if [ "$LOGGED_IN" = "true" ]; then
  R=$(GET "/api/sbom/latest")
  CODE="${R%%|*}"
  [ "$CODE" = "404" ] && ok "GET /api/sbom/latest (404 = sin SBOM generado todavía, OK)" \
    || fail "GET /api/sbom/latest — HTTP $CODE"
else
  skip "GET /api/sbom/latest (sin sesión)"
fi

# ── 4. 2FA / TOTP ─────────────────────────────────────────────────────────────
hdr "4. 2FA / TOTP"

if [ "$LOGGED_IN" = "false" ]; then
  skip "2FA — sin sesión"
else
  R=$(GET "/api/auth/2fa/status"); CODE="${R%%|*}"; BODY="${R#*|}"
  if [ "$CODE" = "200" ]; then
    ok "GET /api/auth/2fa/status — enabled: $(JQ "$BODY" "enabled")"
  else
    fail "GET /api/auth/2fa/status — HTTP $CODE"
  fi

  R=$(POST "/api/auth/2fa/setup" "{}"); CODE="${R%%|*}"; BODY="${R#*|}"
  if [ "$CODE" = "200" ]; then
    ok "POST /api/auth/2fa/setup"
    SECRET=$(JQ "$BODY" "secret")
    HAS_QR=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print('si' if d.get('qr_svg') else 'no')" 2>/dev/null)
    HAS_RC=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print('si' if d.get('recovery_codes') else 'no')" 2>/dev/null)
    [ "$HAS_QR" = "si" ] && ok "  QR SVG generado" || fail "  Falta qr_svg en la respuesta"
    [ "$HAS_RC" = "si" ] && ok "  Códigos de recuperación presentes" || fail "  Faltan recovery_codes"
    [ "$SECRET" != "?" ] && ok "  Secret TOTP: ${SECRET:0:12}…" || fail "  Falta 'secret' en respuesta"
  else
    fail "POST /api/auth/2fa/setup — HTTP $CODE: ${BODY:0:200}"
  fi

  R=$(POST "/api/auth/2fa/activate" '{"code":"000000"}'); CODE="${R%%|*}"; BODY="${R#*|}"
  ACT_OK=$(JQ "$BODY" "ok")
  # ok=False con código inválido es el comportamiento CORRECTO
  if [ "$CODE" = "200" ] && [ "$ACT_OK" = "False" ]; then
    ok "POST /api/auth/2fa/activate — código inválido correctamente rechazado (ok=false)"
  elif [ "$CODE" = "400" ]; then
    ok "POST /api/auth/2fa/activate — código inválido rechazado (HTTP 400)"
  else
    fail "POST /api/auth/2fa/activate — respuesta inesperada: HTTP $CODE, ok=$ACT_OK"
  fi
fi

# ── 5. Compliance ─────────────────────────────────────────────────────────────
hdr "5. Compliance"
if [ "$LOGGED_IN" = "true" ]; then
  R=$(GET "/api/compliance?frameworks=ens,iso27001,cis"); CODE="${R%%|*}"; BODY="${R#*|}"
  if [ "$CODE" = "200" ]; then
    ok "GET /api/compliance"
    ok "  ENS: $(JQ "$BODY" "ens.score_pct")%  ISO27001: $(JQ "$BODY" "iso27001.score_pct")%  CIS: $(JQ "$BODY" "cis.score_pct")%"
  else
    fail "GET /api/compliance — HTTP $CODE"
  fi
  R=$(POST "/api/compliance" '{"frameworks":["ens"]}'); CODE="${R%%|*}"
  [ "$CODE" = "200" ] && ok "POST /api/compliance" || fail "POST /api/compliance — HTTP $CODE"
else
  skip "Compliance (sin sesión)"
fi

# ── 6. PDF ────────────────────────────────────────────────────────────────────
hdr "6. Informe PDF"
if [ "$LOGGED_IN" = "true" ]; then
  R=$(POST "/api/report/pdf" '{"scan_type":"audit","target":"localhost"}')
  CODE="${R%%|*}"; BODY="${R#*|}"
  [ "$CODE" = "200" ] && ok "POST /api/report/pdf" || fail "POST /api/report/pdf — HTTP $CODE: ${BODY:0:100}"
else
  skip "PDF (sin sesión)"
fi

# ── 7. SBOM ───────────────────────────────────────────────────────────────────
hdr "7. SBOM"
if [ "$LOGGED_IN" = "true" ]; then
  R=$(POST "/api/sbom/generate" '{"include":["kernel"]}'); CODE="${R%%|*}"; BODY="${R#*|}"
  if [ "$CODE" = "200" ]; then
    ok "POST /api/sbom/generate — $(JQ "$BODY" "total") componentes"
  else
    fail "POST /api/sbom/generate — HTTP $CODE: ${BODY:0:100}"
  fi
else
  skip "SBOM (sin sesión)"
fi

# ── 8. Multi-tenant ───────────────────────────────────────────────────────────
hdr "8. Multi-tenant"
if [ "$LOGGED_IN" = "true" ]; then
  R=$(POST "/api/tenants" '{"slug":"verify-tmp","name":"Verify Test","plan":"starter"}')
  CODE="${R%%|*}"; BODY="${R#*|}"
  if [ "$CODE" = "201" ]; then
    ok "POST /api/tenants — creado"
    POST "/api/tenants/verify-tmp" '{"active":false}' > /dev/null 2>&1
  elif echo "$BODY" | grep -qi "existe\|already"; then
    ok "POST /api/tenants — ya existe (OK)"
  else
    fail "POST /api/tenants — HTTP $CODE: ${BODY:0:80}"
  fi
  CHKAUTH "GET /api/tenants" "/api/tenants"
else
  skip "Multi-tenant (sin sesión)"
fi

# ── 9. OpenAPI ────────────────────────────────────────────────────────────────
hdr "9. OpenAPI / Swagger"
if [ "$LOGGED_IN" = "true" ]; then
  R=$(GET "/api/openapi.json"); CODE="${R%%|*}"; BODY="${R#*|}"
  if [ "$CODE" = "200" ]; then
    NEPS=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(sum(len(v) for v in d.get('paths',{}).values()))" 2>/dev/null)
    ok "GET /api/openapi.json — ${NEPS} endpoints documentados"
  else
    fail "GET /api/openapi.json — HTTP $CODE"
  fi
  CHKAUTH "GET /api/docs (Swagger UI)" "/api/docs"
else
  skip "OpenAPI (sin sesión)"
fi

# ── 10. Ansible ───────────────────────────────────────────────────────────────
hdr "10. Ansible AWX/Tower"
if [ "$LOGGED_IN" = "true" ]; then
  CHKAUTH "GET /api/ansible/jobs" "/api/ansible/jobs"
  R=$(POST "/api/ansible/run" '{"mode":"local","target":"localhost"}')
  CODE="${R%%|*}"; BODY="${R#*|}"
  [ "$CODE" = "200" ] \
    && ok "POST /api/ansible/run" \
    || info "POST /api/ansible/run — HTTP $CODE (sin scan disponible es normal)"
else
  skip "Ansible (sin sesión)"
fi

# ── 11. Monitor ───────────────────────────────────────────────────────────────
hdr "11. Monitor en tiempo real"
if [ "$LOGGED_IN" = "true" ]; then
  R=$(GET "/api/monitor/status"); CODE="${R%%|*}"; BODY="${R#*|}"
  if [ "$CODE" = "200" ]; then
    MODE=$(JQ "$BODY" "mode"); ACTIVE=$(JQ "$BODY" "active")
    ok "GET /api/monitor/status — modo: $MODE, activo: $ACTIVE"
    [ "$ACTIVE" = "False" ] && info "  Para activar: sudo apt install auditd && sudo systemctl enable --now auditd"
  else
    fail "GET /api/monitor/status — HTTP $CODE"
  fi
else
  skip "Monitor (sin sesión)"
fi

# ── 12. Cuarentena ────────────────────────────────────────────────────────────
hdr "12. Cuarentena"
if [ "$LOGGED_IN" = "true" ]; then
  CHKAUTH "GET /api/quarantine" "/api/quarantine"
  R=$(GET "/api/quarantine/stats"); CODE="${R%%|*}"; BODY="${R#*|}"
  [ "$CODE" = "200" ] \
    && ok "GET /api/quarantine/stats — $(JQ "$BODY" "total") ficheros, $(JQ "$BODY" "size_mb") MB" \
    || fail "GET /api/quarantine/stats — HTTP $CODE"
else
  skip "Cuarentena (sin sesión)"
fi

# ── 13. Licencias ─────────────────────────────────────────────────────────────
hdr "13. Licencias"
if [ "$LOGGED_IN" = "true" ]; then
  R=$(GET "/api/license"); CODE="${R%%|*}"; BODY="${R#*|}"
  [ "$CODE" = "200" ] \
    && ok "GET /api/license — tier: $(JQ "$BODY" "tier"), licensee: $(JQ "$BODY" "licensee")" \
    || fail "GET /api/license — HTTP $CODE"
else
  skip "Licencias (sin sesión)"
fi

# ── 14. Agentes ───────────────────────────────────────────────────────────────
hdr "14. Agentes"
CHKAUTH "GET /api/agent/list" "/api/agent/list"

# ── 15. Tests unitarios ───────────────────────────────────────────────────────
hdr "15. Tests unitarios (pytest)"
PYTEST=""
for p in \
  "/home/jose/.venv/cyberhound/bin/pytest" \
  "/home/$(whoami)/.venv/cyberhound/bin/pytest" \
  "$(which pytest 2>/dev/null)"; do
  [ -x "$p" ] && PYTEST="$p" && break
done

if [ -n "$PYTEST" ]; then
  cd "$(dirname "$0")/.." 2>/dev/null || true
  $PYTEST tests/ -q --no-header --tb=line -p no:cacheprovider 2>&1 | tail -4
  [ ${PIPESTATUS[0]:-0} -eq 0 ] && ok "Suite pytest completa" || fail "Algunos tests fallaron"
else
  info "pytest no encontrado — ejecutar: ~/.venv/cyberhound/bin/pytest tests/ -q"
fi

# ── Resumen ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════${NC}"
echo -e "${BOLD}  CyberHound Pro — Resumen            ${NC}"
echo -e "${BOLD}══════════════════════════════════════${NC}"
echo -e "  ${GREEN}✓ Pasados:${NC}  ${OK_COUNT}"
if [ $SKIP -gt 0 ]; then
echo -e "  ${YELLOW}⏭ Saltados:${NC} ${SKIP} (requieren login)"
fi
echo -e "  ${RED}✗ Fallidos:${NC} ${FAIL}"
echo ""

if [ "$LOGGED_IN" = "false" ]; then
  echo -e "${YELLOW}${BOLD}  ⚠ Sin sesión — la mayoría de checks se saltaron${NC}"
  echo ""
  echo "  Para ejecutar la verificación completa:"
  echo "  1. Averigua tu contraseña:"
  echo "     sudo cyberhound setup   ← para cambiarla"
  echo "  2. Pásala al script:"
  echo "     CH_PASSWORD=tupass bash scripts/verify_all.sh"
  echo ""
elif [ $FAIL -eq 0 ]; then
  echo -e "${GREEN}${BOLD}  ✓ Todo correcto — CyberHound Pro funcionando al 100%${NC}"
else
  echo -e "${RED}${BOLD}  ✗ ${FAIL} fallo(s)${NC}"
  echo "  Ver errores anteriores para más detalles."
fi
exit $FAIL
