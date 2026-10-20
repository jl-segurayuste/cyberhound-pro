#!/bin/sh
# Copia diaria de PostgreSQL (la lanza el servicio backup de docker-compose.production.yml)
set -eu
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="/backups/cyberhound_${TIMESTAMP}.sql.gz"
umask 077
pg_dump -h postgres -U cyberhound cyberhound | gzip > "$BACKUP_FILE"
echo "[$(date)] Copia creada: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"
# Se conservan las 30 más recientes
ls -t /backups/*.sql.gz 2>/dev/null | tail -n +31 | xargs -r rm -f
