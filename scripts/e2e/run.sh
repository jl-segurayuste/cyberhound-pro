#!/usr/bin/env bash
# Batería E2E de CyberHound Pro: levanta instancias de demo (datos ficticios) y las recorre con un
# navegador real. Cubre cada panel en 3 tamaños de pantalla, cada botón, los roles, el multi-tenant y
# la API/escaneos reales contra objetivos controlados. Ver scripts/e2e/README.md.
#
#   CH_PYTHON=.venv/bin/python E2E_PYTHON=/ruta/venv-playwright/bin/python scripts/e2e/run.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
CH_PYTHON="${CH_PYTHON:-python3}"       # con cyberhound instalado (pip install -e .)
E2E_PYTHON="${E2E_PYTHON:-python3}"     # con playwright (pip install playwright && playwright install chromium)
abs() { case "$1" in /*) echo "$1" ;; */*) echo "$PWD/$1" ;; *) command -v "$1" ;; esac; }
CH_PYTHON="$(abs "$CH_PYTHON")"; E2E_PYTHON="$(abs "$E2E_PYTHON")"   # el script cambia de directorio
PORT="${CH_E2E_PORT:-18443}"; MT_PORT=$((PORT + 1)); WEB_PORT="${CH_E2E_WEB_PORT:-18080}"
SSH_PORT="${CH_E2E_SSH_PORT:-18022}"
export CH_E2E_SSH_PASSWORD="ssh-$("$CH_PYTHON" -c 'import secrets; print(secrets.token_hex(6))')"
export CH_E2E_PASSWORD="e2e-$("$CH_PYTHON" -c 'import secrets; print(secrets.token_hex(6))')"
WORK="$(mktemp -d)"; PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT

instance() {   # instance <nombre> <puerto> <multi_tenant true|false>
    local d="$WORK/$1"; mkdir -p "$d"
    printf '%s\n' "$CH_E2E_PASSWORD" | CH_DATA_DIR="$d" "$CH_PYTHON" -m cyberhound setup --config "$d/config.yaml" \
        --password-stdin --username admin --host 127.0.0.1 --port "$2" >/dev/null
    "$CH_PYTHON" - "$d" "$3" <<'PY'
import sys, yaml
d, mt = sys.argv[1], sys.argv[2] == "true"
c = yaml.safe_load(open(f"{d}/config.yaml"))
c["server"]["log_dir"] = d
c["db_path"] = f"{d}/cyberhound.db"
c["multi_tenant"] = {"enabled": mt}
yaml.safe_dump(c, open(f"{d}/config.yaml", "w"))
PY
    (cd "$REPO" && CH_DATA_DIR="$d" "$CH_PYTHON" "$HERE/seed.py" "$d/cyberhound.db" >/dev/null)
    (cd "$d" && CH_DATA_DIR="$d" CH_TLS_DIR="$d/tls" exec "$CH_PYTHON" -m cyberhound web --config "$d/config.yaml" \
        > "$d/web.log" 2>&1) &
    PIDS+=($!)
    for _ in $(seq 1 40); do curl -sk -o /dev/null "https://127.0.0.1:$2/health" && return 0; sleep 0.5; done
    echo "✗ la instancia $1 no arranca:"; tail -20 "$d/web.log"; exit 2
}

echo "── Preparando instancias de demo en $WORK"
"$CH_PYTHON" "$HERE/targets.py" "$WORK/targets"
(exec "$CH_PYTHON" -m http.server "$WEB_PORT" --bind 127.0.0.1 -d "$WORK/targets/web" >/dev/null 2>&1) &
PIDS+=($!)
# servidor SSH de pruebas (solo 127.0.0.1): credenciales guardadas y auditoría SSH programada
(exec "$CH_PYTHON" "$HERE/sshd.py" "$SSH_PORT" "$WORK" >"$WORK/sshd.log" 2>&1) &
PIDS+=($!)
instance plataforma "$PORT" false
instance multitenant "$MT_PORT" true

RESULT=0
run() {   # run <nombre> <script> [args…]
    echo; echo "── $1"
    if CH_E2E_BASE="${BASE:-https://127.0.0.1:$PORT}" CH_E2E_WEB="http://127.0.0.1:$WEB_PORT" CH_E2E_SSH_PORT="$SSH_PORT" \
        "$E2E_PYTHON" -I "$HERE/$2" "${@:3}"; then echo "✓ $1"; else echo "✗ $1"; RESULT=1; fi
}
run "Interfaz: paneles, scroll y todos los controles" ui.py "$HERE/fakews.js" "$WORK"
run "Roles: lector y operador" roles.py "$HERE/fakews.js"
BASE="https://127.0.0.1:$MT_PORT" run "Multi-tenant" multitenant.py "$HERE/fakews.js"
run "Funcional: API, análisis reales, 2FA, cuarentena, rate limit" functional.py "$WORK/targets" "$WORK"

echo
[ $RESULT = 0 ] && echo "✓ Batería E2E completa sin fallos" || echo "✗ Hay fallos (detalle arriba)"
exit $RESULT
