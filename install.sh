#!/bin/bash
# CyberHound Pro — Instalador
# Uso: sudo bash install.sh [--postgres] [--port 8443] [--user admin]
set -e

VERSION="6.1.0"
INSTALL_DIR="/opt/cyberhound"
VENV_DIR="/opt/cyberhound/venv"
CONFIG_DIR="/root/.cyberhound"
LOG_DIR="/var/log/cyberhound"
SERVICE_FILE="/etc/systemd/system/cyberhound.service"

# Colores
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'

info()    { echo -e "${BLUE}ℹ${NC}  $*"; }
success() { echo -e "${GREEN}✓${NC}  $*"; }
warn()    { echo -e "${YELLOW}⚠${NC}  $*"; }
error()   { echo -e "${RED}✗${NC}  $*"; exit 1; }
header()  { echo -e "\n${BOLD}${BLUE}═══ $* ═══${NC}\n"; }

# ── Argumentos ────────────────────────────────────────────────────────────────
USE_POSTGRES=false
PORT=8443
ADMIN_USER="admin"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --postgres)    USE_POSTGRES=true; shift ;;
        --port)        PORT="$2"; shift 2 ;;
        --user)        ADMIN_USER="$2"; shift 2 ;;
        -h|--help)
            echo "Uso: sudo bash install.sh [opciones]"
            echo ""
            echo "Opciones:"
            echo "  --postgres        Usar PostgreSQL en lugar de SQLite"
            echo "  --port PORT       Puerto HTTPS (defecto: 8443)"
            echo "  --user USER       Usuario admin (defecto: admin)"
            echo "  -h, --help        Mostrar esta ayuda"
            exit 0 ;;
        *) warn "Opción desconocida: $1"; shift ;;
    esac
done

# ── Verificaciones ────────────────────────────────────────────────────────────
header "CyberHound Pro v${VERSION} — Instalación"

[[ $EUID -ne 0 ]] && error "Ejecutar como root: sudo bash install.sh"

# Detectar distribución
if command -v apt-get &>/dev/null; then PKG_MGR="apt"; 
elif command -v dnf &>/dev/null; then PKG_MGR="dnf";
elif command -v yum &>/dev/null; then PKG_MGR="yum";
else error "Gestor de paquetes no soportado"; fi

info "Distribución: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
info "Puerto: $PORT | Usuario: $ADMIN_USER | BD: $([ $USE_POSTGRES = true ] && echo PostgreSQL || echo SQLite)"

# ── Dependencias del sistema ──────────────────────────────────────────────────
header "Instalando dependencias del sistema"

PACKAGES="python3 python3-pip python3-venv nmap git curl wget"

if [ "$PKG_MGR" = "apt" ]; then
    apt-get update -qq
    apt-get install -y --no-install-recommends $PACKAGES \
        libssl-dev libffi-dev python3-dev build-essential \
        auditd shellcheck 2>/dev/null || true
elif [ "$PKG_MGR" = "dnf" ] || [ "$PKG_MGR" = "yum" ]; then
    $PKG_MGR install -y $PACKAGES openssl-devel python3-devel gcc \
        audit ShellCheck 2>/dev/null || true
fi
success "Dependencias instaladas"

# ── PostgreSQL (opcional) ─────────────────────────────────────────────────────
if [ "$USE_POSTGRES" = true ]; then
    header "Configurando PostgreSQL"
    if ! command -v psql &>/dev/null; then
        [ "$PKG_MGR" = "apt" ] && apt-get install -y postgresql postgresql-contrib
        [ "$PKG_MGR" = "dnf" ] && dnf install -y postgresql-server postgresql-contrib
        systemctl enable --now postgresql 2>/dev/null || true
    fi

    # Crear usuario y base de datos
    PG_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
    sudo -u postgres psql -c "CREATE USER cyberhound WITH PASSWORD '$PG_PASS';" 2>/dev/null || true
    sudo -u postgres psql -c "CREATE DATABASE cyberhound OWNER cyberhound;" 2>/dev/null || true
    success "PostgreSQL configurado"
    PG_URL="postgresql://cyberhound:${PG_PASS}@localhost:5432/cyberhound"
    warn "Guarda la URL de BD: $PG_URL"
fi

# ── Instalación de CyberHound ─────────────────────────────────────────────────
header "Instalando CyberHound Pro"

# Copiar código
mkdir -p "$INSTALL_DIR"
cp -r . "$INSTALL_DIR/"
success "Código copiado en $INSTALL_DIR"

# Entorno virtual Python
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -e "$INSTALL_DIR" -q
[ "$USE_POSTGRES" = true ] && "$VENV_DIR/bin/pip" install asyncpg -q
success "Entorno Python configurado"

# Crear enlace simbólico
ln -sf "$VENV_DIR/bin/cyberhound" /usr/local/bin/cyberhound
success "Comando 'cyberhound' disponible"

# ── Configuración inicial ─────────────────────────────────────────────────────
header "Configuración inicial"

mkdir -p "$CONFIG_DIR" "$LOG_DIR"
chmod 700 "$CONFIG_DIR"

# Generar contraseña aleatoria
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    ADMIN_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")
    cyberhound setup --username "$ADMIN_USER" --password "$ADMIN_PASS" 2>/dev/null || {
        # Fallback: crear config mínima
        PASS_HASH=$(python3 -c "import hashlib; print(hashlib.sha256('${ADMIN_PASS}'.encode()).hexdigest())")
        JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
        cat > "$CONFIG_DIR/config.yaml" << YAML
auth:
  username: $ADMIN_USER
  password_hash: $PASS_HASH
  secret: $JWT_SECRET
  token_ttl_hours: 8
server:
  port: $PORT
$([ "$USE_POSTGRES" = true ] && echo "db_url: $PG_URL" || echo "")
YAML
        chmod 600 "$CONFIG_DIR/config.yaml"
    }
    echo ""
    echo -e "  ${BOLD}${GREEN}Credenciales de acceso:${NC}"
    echo -e "  Usuario: ${BOLD}$ADMIN_USER${NC}"
    echo -e "  Contraseña: ${BOLD}$ADMIN_PASS${NC}"
    echo ""
    warn "Guarda estas credenciales — no volverán a mostrarse"
fi

# ── Servicio systemd ─────────────────────────────────────────────────────────
header "Configurando servicio systemd"

cat > "$SERVICE_FILE" << UNIT
[Unit]
Description=CyberHound Pro Security Scanner
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/cyberhound web --port $PORT
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cyberhound

# Seguridad del servicio
NoNewPrivileges=false
PrivateTmp=true
ProtectHome=false
ReadWritePaths=$CONFIG_DIR $LOG_DIR /tmp

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable cyberhound
systemctl start cyberhound
sleep 2

if systemctl is-active --quiet cyberhound; then
    success "Servicio cyberhound iniciado"
else
    warn "El servicio no arrancó — comprueba: journalctl -u cyberhound -n 20"
fi

# ── Resumen ───────────────────────────────────────────────────────────────────
IP=$(hostname -I | awk '{print $1}')
header "✅ Instalación completada"
echo -e "  URL de acceso: ${BOLD}https://${IP}:${PORT}${NC}"
echo -e "  Logs: journalctl -u cyberhound -f"
echo -e "  Reiniciar: systemctl restart cyberhound"
echo -e "  Estado: systemctl status cyberhound"
echo ""
echo -e "  ${YELLOW}Nota: El certificado TLS es auto-firmado. Tu navegador mostrará una advertencia.${NC}"
echo -e "  ${YELLOW}Acepta la excepción de seguridad para acceder.${NC}"
echo ""
