#!/usr/bin/env bash
# CyberHound Pro — Instalador
set -euo pipefail

# El script está en la raíz del paquete (donde está pyproject.toml)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="${HOME}/.venv/cyberhound"
BIN_LINK="/usr/local/bin/cyberhound"

echo ""
echo "🐾 CyberHound Pro — Instalador"
echo "================================"

# ── Verificar Python 3.11+ ────────────────────────────────────────────────────
PYTHON=$(command -v python3.12 2>/dev/null || command -v python3.11 2>/dev/null || command -v python3 2>/dev/null || true)
if [ -z "$PYTHON" ]; then
    echo "❌ Python 3.11+ no encontrado."
    echo "   Ubuntu/Debian: sudo apt install python3.12 python3.12-venv"
    exit 1
fi

PY_VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]); then
    echo "❌ Se requiere Python 3.11+. Detectado: $PY_VER"
    exit 1
fi
echo "✓ Python $PY_VER detectado: $PYTHON"

# ── Verificar que pyproject.toml está en el directorio actual ─────────────────
if [ ! -f "$SCRIPT_DIR/pyproject.toml" ]; then
    echo "❌ pyproject.toml no encontrado en $SCRIPT_DIR"
    echo "   Asegúrate de ejecutar install.sh desde el directorio raíz del paquete."
    exit 1
fi

# ── Crear venv aislado ────────────────────────────────────────────────────────
echo ""
echo "Creando entorno virtual en $VENV_DIR…"
"$PYTHON" -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip setuptools wheel

# ── Instalar el paquete ───────────────────────────────────────────────────────
echo "Instalando CyberHound Pro y dependencias…"
"$VENV_DIR/bin/pip" install --quiet "$SCRIPT_DIR"

# Verificar que el módulo es importable
if ! "$VENV_DIR/bin/python" -c "import cyberhound" 2>/dev/null; then
    echo "⚠ El módulo no se encontró tras la instalación. Intentando instalación directa…"
    # Fallback: instalar dependencias y añadir el directorio al path
    "$VENV_DIR/bin/pip" install --quiet \
        aiohttp aiosqlite aiofiles pyyaml colorama fpdf2 jinja2 \
        beautifulsoup4 PyJWT cryptography tenacity python-dotenv asyncssh

    # Crear un .pth para que el directorio padre sea importable
    SITE_PKG=$("$VENV_DIR/bin/python" -c "import site; print(site.getsitepackages()[0])")
    echo "$(dirname "$SCRIPT_DIR")" > "$SITE_PKG/cyberhound_dev.pth"
    echo "✓ Instalado en modo desarrollo desde: $SCRIPT_DIR"
fi

# Verificar de nuevo
if ! "$VENV_DIR/bin/python" -c "import cyberhound" 2>/dev/null; then
    echo "❌ No se pudo importar el módulo cyberhound. Revisa la estructura del directorio."
    echo "   Estructura esperada:"
    echo "   cyberhound/          ← directorio raíz (donde está install.sh)"
    echo "   ├── pyproject.toml"
    echo "   ├── __main__.py"
    echo "   ├── core/"
    echo "   ├── scanners/"
    echo "   └── api/"
    exit 1
fi
echo "✓ Módulo cyberhound instalado correctamente"

# ── yara-python (opcional) ────────────────────────────────────────────────────
echo ""
echo "Intentando instalar yara-python (opcional)…"
if sudo apt-get install -y libyara-dev 2>/dev/null; then
    "$VENV_DIR/bin/pip" install --quiet yara-python \
        && echo "✓ yara-python instalado" \
        || echo "⚠ yara-python no disponible (módulo YARA deshabilitado)"
else
    echo "⚠ libyara-dev no disponible. Módulo YARA deshabilitado."
fi

# ── asyncssh ──────────────────────────────────────────────────────────────────
"$VENV_DIR/bin/python" -c "import asyncssh" 2>/dev/null \
    && echo "✓ asyncssh disponible" \
    || { "$VENV_DIR/bin/pip" install --quiet asyncssh && echo "✓ asyncssh instalado"; }

# ── Crear wrapper en /usr/local/bin ──────────────────────────────────────────
echo ""
WRAPPER=$(mktemp)
cat > "$WRAPPER" << WEOF
#!/usr/bin/env bash
exec sudo -E "${VENV_DIR}/bin/python" -m cyberhound "\$@"
WEOF
chmod +x "$WRAPPER"

if sudo mv "$WRAPPER" "$BIN_LINK" 2>/dev/null; then
    echo "✓ Comando disponible: cyberhound"
else
    mkdir -p "$HOME/.local/bin"
    mv "$WRAPPER" "$HOME/.local/bin/cyberhound"
    BIN_LINK="$HOME/.local/bin/cyberhound"
    echo "✓ Comando en $BIN_LINK"
    echo "  Añade ~/.local/bin a tu PATH si no está ya:"
    echo "  echo 'export PATH=\$HOME/.local/bin:\$PATH' >> ~/.bashrc && source ~/.bashrc"
fi

# ── Herramientas del sistema ──────────────────────────────────────────────────
echo ""
echo "── Herramientas del sistema (recomendadas) ──"
for tool in nmap arp-scan gitleaks shellcheck bandit; do
    command -v "$tool" &>/dev/null && echo "  ✓ $tool" || echo "  ✗ $tool (no instalado)"
done
echo ""
echo "Para instalar las que falten:"
echo "  sudo apt install nmap arp-scan shellcheck"
echo "  pip install bandit"
echo "  # gitleaks: https://github.com/gitleaks/gitleaks/releases"

# ── Configuración inicial ─────────────────────────────────────────────────────
echo ""
echo "── Configuración inicial ──"
CONFIG_FILE="$HOME/.cyberhound/config.yaml"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Ejecutando asistente de configuración…"
    sudo -E "$VENV_DIR/bin/python" -m cyberhound setup
else
    echo "✓ Configuración existente en $CONFIG_FILE"
    echo "  Para reconfigurar: cyberhound setup"
fi

echo ""
echo "✅ Instalación completa."
echo ""
echo "Para lanzar la interfaz web:"
echo "  cyberhound web --port 8443"
echo ""
echo "Abre http://localhost:8443 en el navegador."

echo ""
echo "🐾 CyberHound Pro — Instalador"
echo "================================"

# ── Verificar Python 3.11+ ────────────────────────────────────────────────────
PYTHON=$(command -v python3.12 || command -v python3.11 || command -v python3 || true)
if [ -z "$PYTHON" ]; then
    echo "❌ Python 3.11+ no encontrado."
    echo "   Ubuntu/Debian: sudo apt install python3.12 python3.12-venv"
    exit 1
fi

PY_VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]); then
    echo "❌ Se requiere Python 3.11+. Detectado: $PY_VER"
    echo "   Ubuntu: sudo apt install python3.12 python3.12-venv"
    exit 1
fi

echo "✓ Python $PY_VER detectado: $PYTHON"

# ── Crear venv aislado ────────────────────────────────────────────────────────
echo ""
echo "Creando entorno virtual en $VENV_DIR…"
"$PYTHON" -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip

# ── Instalar paquete desde pyproject.toml ─────────────────────────────────────
echo "Instalando CyberHound Pro y dependencias…"
"$VENV_DIR/bin/pip" install --quiet "$INSTALL_DIR"

# ── yara-python (opcional, requiere libyara-dev) ──────────────────────────────
echo ""
echo "Intentando instalar yara-python (opcional)…"
if apt-get install -y libyara-dev 2>/dev/null || true; then
    "$VENV_DIR/bin/pip" install --quiet yara-python && echo "✓ yara-python instalado" \
        || echo "⚠ yara-python no disponible (módulo YARA deshabilitado)"
else
    echo "⚠ libyara-dev no instalado. Módulo YARA deshabilitado."
    echo "  Para activarlo: sudo apt install libyara-dev && pip install yara-python"
fi

# ── asyncssh (para análisis SSH seguro) ───────────────────────────────────────
echo "Verificando asyncssh…"
"$VENV_DIR/bin/python" -c "import asyncssh" 2>/dev/null \
    && echo "✓ asyncssh disponible" \
    || echo "⚠ asyncssh no instalado. El análisis SSH no estará disponible."

# ── Crear wrapper en /usr/local/bin ───────────────────────────────────────────
echo ""
if [ -w "$(dirname "$BIN_LINK")" ] || sudo -n true 2>/dev/null; then
    echo "Creando enlace en $BIN_LINK…"
    WRAPPER=$(mktemp)
    cat > "$WRAPPER" << EOF
#!/usr/bin/env bash
# Lanza cyberhound con sudo preservando el venv
exec sudo -E "${VENV_DIR}/bin/python" -m cyberhound "\$@"
EOF
    chmod +x "$WRAPPER"
    sudo mv "$WRAPPER" "$BIN_LINK" 2>/dev/null \
        || { cp "$WRAPPER" "$HOME/.local/bin/cyberhound" 2>/dev/null && BIN_LINK="$HOME/.local/bin/cyberhound"; }
    echo "✓ Comando disponible: cyberhound"
else
    echo "⚠ Sin permisos para instalar en /usr/local/bin."
    echo "  Añade este alias a tu ~/.bashrc:"
    echo "  alias cyberhound='sudo -E ${VENV_DIR}/bin/python -m cyberhound'"
fi

# ── Herramientas del sistema recomendadas ─────────────────────────────────────
echo ""
echo "── Herramientas del sistema (recomendadas) ──"
TOOLS=(nmap arp-scan gitleaks shellcheck)
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo "  ✓ $tool"
    else
        echo "  ✗ $tool (no instalado)"
    fi
done
echo ""
echo "Para instalar las que falten:"
echo "  sudo apt install nmap arp-scan shellcheck"
echo "  # gitleaks: https://github.com/gitleaks/gitleaks/releases"

# ── Configuración inicial ──────────────────────────────────────────────────────
echo ""
echo "── Configuración inicial ──"
if [ ! -f "$HOME/.cyberhound/config.yaml" ]; then
    echo "Ejecutando asistente de configuración…"
    sudo -E "$VENV_DIR/bin/python" -m cyberhound setup
else
    echo "⚠ Ya existe configuración en $HOME/.cyberhound/config.yaml"
    echo "  Para reconfigurar: cyberhound setup"
fi

echo ""
echo "✅ Instalación completa."
echo ""
echo "Para lanzar la interfaz web:"
echo "  cyberhound web --port 8443"
echo ""
echo "Primera vez: abre http://localhost:8443 y accede con las credenciales que configuraste."
