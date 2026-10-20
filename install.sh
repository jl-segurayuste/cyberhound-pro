#!/bin/bash
# CyberHound Pro — Instalador (Debian/Ubuntu y RHEL/Rocky/Alma)
# Uso: sudo bash install.sh [--host 0.0.0.0] [--port 8443] [--user admin] [--postgres] [--no-service]
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$SRC_DIR/cyberhound/__init__.py")"
INSTALL_DIR="/opt/cyberhound"
VENV_DIR="/opt/cyberhound/venv"
CONFIG_DIR="/root/.cyberhound"          # = CH_DATA_DIR: config, BD, cuarentena, reglas YARA, certificado
LOG_DIR="/var/log/cyberhound"
SERVICE_FILE="/etc/systemd/system/cyberhound.service"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'
info()    { echo -e "${BLUE}ℹ${NC}  $*"; }
success() { echo -e "${GREEN}✓${NC}  $*"; }
warn()    { echo -e "${YELLOW}⚠${NC}  $*"; }
error()   { echo -e "${RED}✗${NC}  $*"; exit 1; }
header()  { echo -e "\n${BOLD}${BLUE}═══ $* ═══${NC}\n"; }

# ── Argumentos ────────────────────────────────────────────────────────────────
USE_POSTGRES=false
WITH_SERVICE=true
HOST="127.0.0.1"
PORT=8443
ADMIN_USER="admin"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --postgres)    USE_POSTGRES=true; shift ;;
        --no-service)  WITH_SERVICE=false; shift ;;
        --host)        HOST="$2"; shift 2 ;;
        --port)        PORT="$2"; shift 2 ;;
        --user)        ADMIN_USER="$2"; shift 2 ;;
        -h|--help)
            echo "Uso: sudo bash install.sh [opciones]"
            echo ""
            echo "  --host IP         Interfaz de escucha (defecto 127.0.0.1; 0.0.0.0 = toda la red)"
            echo "  --port PORT       Puerto HTTPS (defecto: 8443)"
            echo "  --user USER       Usuario admin (defecto: admin)"
            echo "  --postgres        PostgreSQL local en lugar de SQLite"
            echo "  --no-service      No crear el servicio systemd (contenedores, pruebas)"
            exit 0 ;;
        *) error "Opción desconocida: $1 (ver --help)" ;;
    esac
done

header "CyberHound Pro v${VERSION} — Instalación"
[[ $EUID -ne 0 ]] && error "Ejecutar como root: sudo bash install.sh"

if command -v apt-get &>/dev/null; then PKG_MGR="apt"
elif command -v dnf &>/dev/null; then PKG_MGR="dnf"
elif command -v yum &>/dev/null; then PKG_MGR="yum"
else error "Gestor de paquetes no soportado"; fi

info "Sistema: $(. /etc/os-release && echo "$PRETTY_NAME")"
info "Escucha: $HOST:$PORT | Usuario: $ADMIN_USER | BD: $([ "$USE_POSTGRES" = true ] && echo PostgreSQL || echo SQLite)"

# ── Dependencias del sistema ──────────────────────────────────────────────────
header "Instalando dependencias del sistema"
if [ "$PKG_MGR" = "apt" ]; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        python3 python3-pip python3-venv python3-dev build-essential libssl-dev libffi-dev \
        nmap curl ca-certificates auditd shellcheck >/dev/null
else
    $PKG_MGR install -y -q python3 python3-pip python3-devel gcc openssl-devel nmap curl audit >/dev/null
    $PKG_MGR install -y -q ShellCheck >/dev/null 2>&1 || warn "ShellCheck no disponible en los repositorios (opcional)"
fi
python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' || error "Hace falta Python 3.11 o superior"
success "Dependencias instaladas"

# ── PostgreSQL (opcional) ─────────────────────────────────────────────────────
DB_URL=""
if [ "$USE_POSTGRES" = true ]; then
    header "Configurando PostgreSQL"
    if ! command -v psql &>/dev/null; then
        if [ "$PKG_MGR" = "apt" ]; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postgresql >/dev/null
        else
            $PKG_MGR install -y -q postgresql-server >/dev/null
            postgresql-setup --initdb >/dev/null 2>&1 || true
        fi
        systemctl enable --now postgresql >/dev/null 2>&1 || true
    fi
    PG_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
    sudo -u postgres psql -qc "CREATE USER cyberhound WITH PASSWORD '$PG_PASS';" 2>/dev/null \
        || sudo -u postgres psql -qc "ALTER USER cyberhound WITH PASSWORD '$PG_PASS';"
    sudo -u postgres psql -qc "CREATE DATABASE cyberhound OWNER cyberhound;" 2>/dev/null || true
    DB_URL="postgresql://cyberhound:${PG_PASS}@127.0.0.1:5432/cyberhound"
    success "PostgreSQL configurado (la URL queda en $CONFIG_DIR/config.yaml)"
fi

# ── Código y entorno Python ───────────────────────────────────────────────────
header "Instalando CyberHound Pro"
mkdir -p "$INSTALL_DIR"
# Solo el código: nada de .git, entornos virtuales ni cachés
tar -C "$SRC_DIR" --exclude=.git --exclude=.venv --exclude=venv --exclude='__pycache__' \
    --exclude='*.egg-info' --exclude=build --exclude=dist -cf - . | tar -C "$INSTALL_DIR" -xf -
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install -q --upgrade pip
EXTRAS=""; [ "$USE_POSTGRES" = true ] && EXTRAS="[postgres]"
"$VENV_DIR/bin/pip" install -q "$INSTALL_DIR$EXTRAS" -c "$INSTALL_DIR/constraints.txt"
ln -sf "$VENV_DIR/bin/cyberhound" /usr/local/bin/cyberhound
success "Instalado en $INSTALL_DIR (comando: cyberhound)"

# ── Configuración inicial ─────────────────────────────────────────────────────
header "Configuración inicial"
mkdir -p "$CONFIG_DIR" "$LOG_DIR"
chmod 700 "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    ADMIN_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(16))')"
    # La contraseña va por stdin: no aparece en la lista de procesos
    printf '%s\n' "$ADMIN_PASS" | CH_DATA_DIR="$CONFIG_DIR" cyberhound setup --config "$CONFIG_DIR/config.yaml" \
        --password-stdin --username "$ADMIN_USER" --host "$HOST" --port "$PORT" --db-url "$DB_URL" >/dev/null
    echo ""
    echo -e "  ${BOLD}${GREEN}Credenciales de acceso:${NC}"
    echo -e "  Usuario:    ${BOLD}$ADMIN_USER${NC}"
    echo -e "  Contraseña: ${BOLD}$ADMIN_PASS${NC}"
    echo ""
    warn "Guárdalas: no se vuelven a mostrar (cámbiala con: cyberhound setup)"
else
    info "Ya existe $CONFIG_DIR/config.yaml: se conserva"
fi

# ── Servicio systemd ──────────────────────────────────────────────────────────
if [ "$WITH_SERVICE" = true ]; then
    header "Configurando servicio systemd"
    cat > "$SERVICE_FILE" << UNIT
[Unit]
Description=CyberHound Pro
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Environment=CH_DATA_DIR=$CONFIG_DIR
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/cyberhound web --config $CONFIG_DIR/config.yaml
Restart=on-failure
RestartSec=10
SyslogIdentifier=cyberhound
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now cyberhound >/dev/null 2>&1
    sleep 3
    if systemctl is-active --quiet cyberhound; then
        success "Servicio cyberhound en marcha"
    else
        warn "El servicio no arrancó: journalctl -u cyberhound -n 30"
    fi
fi

# ── Resumen ───────────────────────────────────────────────────────────────────
URL_HOST="$HOST"; [ "$HOST" = "0.0.0.0" ] && URL_HOST="$(hostname -I | awk '{print $1}')"
header "Instalación completada"
echo -e "  URL:       ${BOLD}https://${URL_HOST}:${PORT}${NC}   (certificado autofirmado: el navegador avisará)"
if [ "$WITH_SERVICE" = true ]; then
    echo -e "  Logs:      journalctl -u cyberhound -f"
    echo -e "  Reiniciar: systemctl restart cyberhound"
else
    echo -e "  Arrancar:  CH_DATA_DIR=$CONFIG_DIR cyberhound web --config $CONFIG_DIR/config.yaml"
fi
if [ "$HOST" = "127.0.0.1" ]; then
    echo -e "  ${YELLOW}Solo accesible desde este equipo: usa --host 0.0.0.0 o un proxy inverso para la red.${NC}"
fi
echo ""
