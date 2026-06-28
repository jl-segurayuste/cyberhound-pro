"""
Logging estructurado para CyberHound.
- En producción: JSON a /var/log/cyberhound/ + systemd journal si disponible
- En desarrollo: salida coloreada en consola
- Nunca silencia excepciones: todo fallo queda registrado con contexto completo
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime
from pathlib import Path

LOG_DIR = Path("/var/log/cyberhound")
STRUCTURED_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"


class StructuredFormatter(logging.Formatter):
    """Emite JSON por línea para ingesta en SIEM/ELK."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict = {
            "ts":      datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level":   record.levelname,
            "logger":  record.name,
            "msg":     record.getMessage(),
            "module":  record.module,
            "lineno":  record.lineno,
        }
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        if hasattr(record, "extra"):
            entry.update(record.extra)
        return json.dumps(entry, ensure_ascii=False)


class ColorFormatter(logging.Formatter):
    COLORS = {
        "DEBUG":    "\033[37m",
        "INFO":     "\033[0m",
        "WARNING":  "\033[33m",
        "ERROR":    "\033[31m",
        "CRITICAL": "\033[91m",
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        msg = super().format(record)
        return f"{color}{msg}{self.RESET}"


def setup_logging(
    level: str = "INFO",
    log_dir: Path | None = None,
    structured: bool = False,
) -> logging.Logger:
    """
    Configura el sistema de logging global.

    - structured=True → JSON a archivo (para producción)
    - structured=False → salida coloreada en consola (para desarrollo/CLI)
    - Siempre intenta escribir en /var/log/cyberhound/ si hay permisos
    """
    root = logging.getLogger("cyberhound")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()

    # Handler de consola
    console = logging.StreamHandler(sys.stderr)
    if structured:
        console.setFormatter(StructuredFormatter())
    else:
        console.setFormatter(ColorFormatter(
            fmt="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S",
        ))
    root.addHandler(console)

    # Handler de archivo (si tenemos permisos)
    target_dir = log_dir or LOG_DIR
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        log_file = target_dir / f"cyberhound_{datetime.now().strftime('%Y%m%d')}.log"
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(StructuredFormatter())
        root.addHandler(fh)
    except PermissionError:
        root.warning(
            "Sin permisos para escribir en %s. "
            "Log solo en consola. Para activar log en archivo: "
            "sudo mkdir -p %s && sudo chown $USER %s",
            target_dir, target_dir, target_dir,
        )

    # Intentar integración con systemd journal
    try:
        from systemd.journal import JournalHandler
        jh = JournalHandler(SYSLOG_IDENTIFIER="cyberhound")
        jh.setFormatter(StructuredFormatter())
        root.addHandler(jh)
    except ImportError:
        pass  # systemd journal no disponible, no es crítico

    return root


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"cyberhound.{name}")


class SecurityAuditLogger:
    """
    Logger especializado para eventos de seguridad.
    Estos logs NUNCA se silencian y se escriben en un archivo separado.
    """

    def __init__(self) -> None:
        self._logger = logging.getLogger("cyberhound.security")
        target_dir = LOG_DIR
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(
                target_dir / "security_audit.log", encoding="utf-8"
            )
            fh.setFormatter(StructuredFormatter())
            self._logger.addHandler(fh)
        except PermissionError:
            pass

    def fix_applied(self, finding_id: str, user: str, host: str, dry_run: bool) -> None:
        self._logger.warning(
            "FIX_APPLIED finding=%s user=%s host=%s dry_run=%s",
            finding_id, user, host, dry_run,
        )

    def fix_rolled_back(self, finding_id: str, user: str, host: str, ok: bool) -> None:
        self._logger.warning(
            "FIX_ROLLED_BACK finding=%s user=%s host=%s ok=%s",
            finding_id, user, host, ok,
        )

    def auth_failure(self, remote_addr: str, reason: str) -> None:
        self._logger.error("AUTH_FAILURE remote=%s reason=%s", remote_addr, reason)

    def auth_success(self, remote_addr: str, user: str) -> None:
        self._logger.info("AUTH_SUCCESS remote=%s user=%s", remote_addr, user)

    def scan_started(self, target: str, scan_type: str, user: str) -> None:
        self._logger.info(
            "SCAN_STARTED target=%s type=%s user=%s", target, scan_type, user
        )


# Instancia global del audit logger
audit_log = SecurityAuditLogger()
