#!/usr/bin/env bash
# CyberHound Pro — Docker entrypoint
set -euo pipefail

DATA_DIR="/data"
CONFIG_FILE="$DATA_DIR/config.yaml"
LOG_DIR="$DATA_DIR/logs"

mkdir -p "$DATA_DIR" "$LOG_DIR"
umask 077

# Configuración inicial (solo la primera vez). Los valores viajan por el entorno,
# nunca interpolados en código: una contraseña con comillas no rompe nada.
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Primera ejecución: generando $CONFIG_FILE"
    if [ -z "${CH_PASSWORD:-}" ]; then
        CH_PASSWORD="$(python -c 'import secrets; print(secrets.token_urlsafe(15))')"
        echo "  CH_PASSWORD no definida: contraseña inicial generada → $CH_PASSWORD"
        echo "  (cámbiala con: docker exec -it <contenedor> cyberhound setup --config $CONFIG_FILE)"
    fi
    export CH_PASSWORD CH_USERNAME="${CH_USERNAME:-admin}" CONFIG_FILE LOG_DIR DATA_DIR
    python - <<'PYEOF'
import os
import yaml
from cyberhound.core.passwords import hash_password

cfg = {
    "auth": {"mode": "jwt", "username": os.environ["CH_USERNAME"],
             "password_hash": hash_password(os.environ["CH_PASSWORD"]),
             "token_ttl_hours": 8, "localhost_only": False},
    "server": {"host": "127.0.0.1", "port": 8443, "log_dir": os.environ["LOG_DIR"]},
    "scan": {"ssh_default_user": "root", "ssh_default_port": 22, "ssh_concurrency": 5,
             "max_ww_files": 200, "hash_scan_max": 50},
    "db_path": os.path.join(os.environ["DATA_DIR"], "cyberhound.db"),
}
with open(os.environ["CONFIG_FILE"], "w") as f:
    yaml.safe_dump(cfg, f, sort_keys=False)
PYEOF
    echo "  Usuario: ${CH_USERNAME:-admin}"
fi

# Clave SSH pasada como variable de entorno (contenido de la clave privada)
if [ -n "${CH_SSH_KEY:-}" ]; then
    mkdir -p /root/.ssh
    printf '%s\n' "$CH_SSH_KEY" > /root/.ssh/id_ed25519
    chmod 600 /root/.ssh/id_ed25519
fi
# Las API keys (SHODAN_API_KEY, VT_API_KEY…) y CH_DB_URL las lee la propia aplicación del entorno.

SUBCMD="${1:-web}"
shift || true
EXTRA=()
if [ "$SUBCMD" = "web" ]; then
    # CH_HOST / CH_PORT mandan sobre config.yaml (p. ej. 0.0.0.0 detrás de un proxy en red bridge)
    [ -n "${CH_HOST:-}" ] && EXTRA+=(--host "$CH_HOST")
    [ -n "${CH_PORT:-}" ] && EXTRA+=(--port "$CH_PORT")
fi
echo "CyberHound Pro $(python -c 'import cyberhound; print(cyberhound.__version__)') — https://${CH_HOST:-127.0.0.1}:${CH_PORT:-8443}"
exec python -m cyberhound "$SUBCMD" --config "$CONFIG_FILE" "${EXTRA[@]}" "$@"
