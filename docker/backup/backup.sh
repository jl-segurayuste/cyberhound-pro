#!/bin/sh
# Backup automático de PostgreSQL
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="/backups/cyberhound_${TIMESTAMP}.sql.gz"
pg_dump -h postgres -U cyberhound cyberhound | gzip > "$BACKUP_FILE"
echo "[$(date)] Backup creado: $BACKUP_FILE ($(du -h $BACKUP_FILE | cut -f1))"
# Mantener solo los últimos 30 backups
ls -t /backups/*.sql.gz 2>/dev/null | tail -n +31 | xargs rm -f
echo "[$(date)] Backups antiguos eliminados"
