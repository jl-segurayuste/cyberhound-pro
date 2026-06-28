"""
Sistema de cuarentena para CyberHound Pro.

Cuando YARA, hash scan o detección de webshells identifica un fichero
sospechoso, el usuario puede enviarlo a cuarentena con un clic desde la UI.

La cuarentena:
  - Mueve el fichero a un directorio seguro (~/.cyberhound/quarantine/)
  - Lo cifra con XOR + clave aleatoria (previene ejecución accidental)
  - Guarda metadatos: ruta original, hash, fecha, finding_id
  - Permite restaurar el fichero a su ubicación original si era FP
  - No elimina permanentemente — eso siempre es decisión del usuario

IMPORTANTE: Las operaciones de cuarentena requieren privilegios suficientes
para mover el fichero original. El servidor debe ejecutarse como root o
tener los permisos necesarios.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cyberhound.core.logging import get_logger

logger = get_logger("quarantine")

QUARANTINE_DIR = Path.home() / ".cyberhound" / "quarantine"
QUARANTINE_META = QUARANTINE_DIR / "index.json"
QUARANTINE_KEY  = b"CyberHoundQuarantine2024"  # XOR key fija (no criptografía real, solo previene ejecución)


# ── Utilidades ────────────────────────────────────────────────────────────────

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR simple para prevenir ejecución accidental. No es cifrado real."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_meta() -> dict:
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    if QUARANTINE_META.exists():
        try:
            return json.loads(QUARANTINE_META.read_text())
        except Exception:
            pass
    return {"items": []}


def _save_meta(meta: dict) -> None:
    QUARANTINE_META.write_text(json.dumps(meta, indent=2))
    QUARANTINE_META.chmod(0o600)


# ── Operaciones ───────────────────────────────────────────────────────────────

def quarantine_file(
    filepath: str,
    finding_id: str,
    finding_title: str,
    quarantined_by: str = "system",
) -> tuple[bool, str]:
    """
    Mueve un fichero a cuarentena.

    Returns (ok, message)
    """
    src = Path(filepath)
    if not src.exists():
        return False, f"Fichero no encontrado: {filepath}"
    if not src.is_file():
        return False, f"No es un fichero regular: {filepath}"

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    # Nombre único en cuarentena
    ts        = datetime.now(timezone.utc)
    safe_name = f"{ts.strftime('%Y%m%d_%H%M%S')}_{src.name}.quar"
    dst       = QUARANTINE_DIR / safe_name

    try:
        # Calcular hash antes de mover
        file_hash = _file_sha256(src)
        file_size = src.stat().st_size

        # Leer, cifrar con XOR y guardar en cuarentena
        raw = src.read_bytes()
        dst.write_bytes(_xor_bytes(raw, QUARANTINE_KEY))
        dst.chmod(0o600)

        # Eliminar el original
        src.unlink()

        # Registrar en el índice
        meta = _load_meta()
        meta["items"].append({
            "id":              len(meta["items"]) + 1,
            "original_path":   str(src.absolute()),
            "quarantine_name": safe_name,
            "finding_id":      finding_id,
            "finding_title":   finding_title,
            "sha256":          file_hash,
            "size_bytes":      file_size,
            "quarantined_at":  ts.isoformat(),
            "quarantined_by":  quarantined_by,
            "restored":        False,
            "deleted":         False,
        })
        _save_meta(meta)

        logger.info(
            "Fichero enviado a cuarentena: %s → %s (sha256: %s)",
            filepath, safe_name, file_hash[:16],
        )
        return True, f"Fichero enviado a cuarentena: {safe_name}"

    except PermissionError as e:
        return False, f"Sin permisos para mover {filepath}: {e}"
    except Exception as e:
        logger.error("Error en cuarentena de %s: %s", filepath, e)
        return False, f"Error: {e}"


def restore_file(quarantine_name: str, restore_path: Optional[str] = None) -> tuple[bool, str]:
    """
    Restaura un fichero desde cuarentena a su ubicación original.

    Si restore_path es None, restaura a la ubicación original.
    Returns (ok, message)
    """
    meta = _load_meta()
    item = next((i for i in meta["items"] if i["quarantine_name"] == quarantine_name), None)
    if not item:
        return False, f"Entrada no encontrada en cuarentena: {quarantine_name}"
    if item.get("deleted"):
        return False, "El fichero fue eliminado permanentemente"

    src = QUARANTINE_DIR / quarantine_name
    if not src.exists():
        return False, f"Fichero de cuarentena no encontrado: {src}"

    dst = Path(restore_path or item["original_path"])
    try:
        # Descifrar y restaurar
        encrypted = src.read_bytes()
        original  = _xor_bytes(encrypted, QUARANTINE_KEY)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(original)

        # Verificar integridad
        restored_hash = _file_sha256(dst)
        if restored_hash != item["sha256"]:
            dst.unlink()
            return False, f"Error de integridad: hash no coincide ({restored_hash[:16]} vs {item['sha256'][:16]})"

        # Actualizar metadatos
        item["restored"] = True
        item["restored_at"] = datetime.now(timezone.utc).isoformat()
        item["restored_to"]  = str(dst)
        _save_meta(meta)

        logger.info("Fichero restaurado desde cuarentena: %s → %s", quarantine_name, dst)
        return True, f"Fichero restaurado en {dst}"

    except PermissionError as e:
        return False, f"Sin permisos para restaurar en {dst}: {e}"
    except Exception as e:
        logger.error("Error restaurando %s: %s", quarantine_name, e)
        return False, f"Error: {e}"


def delete_quarantined(quarantine_name: str) -> tuple[bool, str]:
    """Elimina permanentemente un fichero de cuarentena."""
    meta = _load_meta()
    item = next((i for i in meta["items"] if i["quarantine_name"] == quarantine_name), None)
    if not item:
        return False, "Entrada no encontrada"

    src = QUARANTINE_DIR / quarantine_name
    try:
        if src.exists():
            src.unlink()
        item["deleted"] = True
        item["deleted_at"] = datetime.now(timezone.utc).isoformat()
        _save_meta(meta)
        logger.info("Fichero eliminado de cuarentena: %s", quarantine_name)
        return True, "Fichero eliminado permanentemente"
    except Exception as e:
        return False, f"Error: {e}"


def list_quarantine() -> list[dict]:
    """Lista todos los ficheros en cuarentena."""
    meta = _load_meta()
    return [
        {
            **item,
            "quarantine_path": str(QUARANTINE_DIR / item["quarantine_name"]),
            "still_exists": (QUARANTINE_DIR / item["quarantine_name"]).exists(),
        }
        for item in meta.get("items", [])
        if not item.get("deleted")
    ]


def quarantine_stats() -> dict:
    """Estadísticas del directorio de cuarentena."""
    items = list_quarantine()
    total_size = sum(
        (QUARANTINE_DIR / i["quarantine_name"]).stat().st_size
        for i in items
        if (QUARANTINE_DIR / i["quarantine_name"]).exists()
    )
    return {
        "total":      len(items),
        "restored":   sum(1 for i in items if i.get("restored")),
        "pending":    sum(1 for i in items if not i.get("restored")),
        "size_bytes": total_size,
        "size_mb":    round(total_size / 1_048_576, 2),
    }
