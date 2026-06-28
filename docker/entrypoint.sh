#!/usr/bin/env bash
# CyberHound Pro — Docker entrypoint
set -euo pipefail

DATA_DIR="/data"
CONFIG_FILE="$DATA_DIR/config.yaml"
LOG_DIR="$DATA_DIR/logs"

mkdir -p "$DATA_DIR" "$LOG_DIR"

# Generar configuración inicial si no existe
if [ ! -f "$CONFIG_FILE" ]; then
    echo "🐾 Primera ejecución — generando configuración inicial..."

    # Contraseña desde variable de entorno o valor por defecto
    CH_PASSWORD="${CH_PASSWORD:-cyberhound}"
    CH_USERNAME="${CH_USERNAME:-admin}"
    CH_PORT="${CH_PORT:-8443}"

    PASS_HASH=$(python -c "import hashlib; print(hashlib.sha256('${CH_PASSWORD}'.encode()).hexdigest())")

    cat > "$CONFIG_FILE" << EOF
auth:
  mode: jwt
  username: ${CH_USERNAME}
  password_hash: ${PASS_HASH}
  token_ttl_hours: 8
  localhost_only: false
server:
  host: "0.0.0.0"
  port: ${CH_PORT}
  log_dir: ${LOG_DIR}
scan:
  ssh_default_user: root
  ssh_default_port: 22
  ssh_concurrency: 5
  max_ww_files: 200
  hash_scan_max: 50
api_keys: {}
EOF

    echo "✓ Config generado: $CONFIG_FILE"
    echo "  Usuario: $CH_USERNAME"
    echo "  Contraseña: $CH_PASSWORD  ← CÁMBIALA en producción"
    echo "  Puerto: $CH_PORT"
fi

# Montar clave SSH si se pasó como variable de entorno
if [ -n "${CH_SSH_KEY:-}" ]; then
    mkdir -p /root/.ssh
    echo "$CH_SSH_KEY" > /root/.ssh/id_ed25519
    chmod 600 /root/.ssh/id_ed25519
    echo "✓ Clave SSH montada"
fi

# Añadir API keys desde variables de entorno si se proporcionan
if [ -n "${SHODAN_API_KEY:-}" ] || [ -n "${VT_API_KEY:-}" ]; then
    python - << PYEOF
import yaml, os
path = "$CONFIG_FILE"
with open(path) as f:
    cfg = yaml.safe_load(f) or {}
keys = cfg.setdefault('api_keys', {})
for env, key in [('SHODAN_API_KEY','shodan'), ('VT_API_KEY','virustotal'),
                 ('ABUSEIPDB_KEY','abuseipdb'), ('GREYNOISE_KEY','greynoise'),
                 ('OTX_KEY','otx'), ('HIBP_API_KEY','hibp')]:
    val = os.environ.get(env)
    if val:
        keys[key] = val
with open(path, 'w') as f:
    yaml.dump(cfg, f)
print("✓ API keys configuradas desde variables de entorno")
PYEOF
fi

echo ""
echo "🐾 CyberHound Pro v6.0.0"
echo "   Interfaz web: http://0.0.0.0:${CH_PORT:-8443}"
echo ""

# Ejecutar CyberHound — el subcomando debe ir ANTES de --config
SUBCMD="${1:-web}"
shift || true
exec python -m cyberhound "$SUBCMD" --config "$CONFIG_FILE" "$@"
