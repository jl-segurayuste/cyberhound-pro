"""
Rollback de remediaciones de hardening.

Cuando `HardeningFixer` aplica un fix, va registrando **acciones de reversión**
(snapshot del fichero antes de tocarlo, modo de permisos previo, estado del
servicio, comando inverso…). Esas acciones se persisten en un *journal* (JSONL).
El rollback las re-aplica en orden inverso para devolver el sistema al estado
anterior al fix.

Principios:
- **Fail-safe de captura**: si no se puede tomar un snapshot, se registra una nota
  y se sigue; nunca bloquea el fix.
- **Lo no reversible se marca como tal** (p. ej. instalar un paquete NO se desinstala
  a ciegas): el rollback lo informa en vez de hacer algo peligroso.
- El journal es la única fuente de verdad para deshacer; sin entrada, no hay rollback.
"""
from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from cyberhound.core.executor import run_command
from cyberhound.core.logging import get_logger

logger = get_logger("rollback")


# ──────────────────────────────────────────────────────────────────────────────
# Acciones de reversión
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Action:
    """Una acción reversible registrada al aplicar un fix.

    `kind` determina qué campos son relevantes:
      - file:     path, existed, content_b64, mode   (restaura el fichero o lo borra)
      - chmod:    path, mode                          (restaura el modo de permisos)
      - service:  service, was_active, was_enabled    (restaura estado del servicio)
      - command:  cmd                                 (ejecuta el comando inverso)
      - irreversible: note                            (no se puede deshacer; se informa)
    """
    kind: str
    note: str = ""
    path: str | None = None
    existed: bool | None = None
    content_b64: str | None = None
    mode: int | None = None
    service: str | None = None
    was_active: bool | None = None
    was_enabled: bool | None = None
    cmd: list[str] | None = None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None and v != ""}

    @classmethod
    def from_dict(cls, d: dict) -> Action:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ── Constructores de snapshot (best-effort, nunca lanzan) ───────────────────────

def snapshot_file(path: str) -> Action:
    """Captura el contenido + modo actuales de un fichero (o que no existe)."""
    p = Path(path)
    try:
        if p.exists():
            data = p.read_bytes()
            return Action(
                kind="file", path=str(p), existed=True,
                content_b64=base64.b64encode(data).decode("ascii"),
                mode=os.stat(p).st_mode & 0o7777,
            )
        return Action(kind="file", path=str(p), existed=False)
    except OSError as e:  # noqa: BLE001
        logger.warning("No se pudo snapshotear %s para rollback: %s", path, e)
        return Action(kind="irreversible", note=f"snapshot de {path} falló: {e}")


def snapshot_chmod(path: str) -> Action:
    """Captura el modo de permisos actual (para fixes que solo hacen chmod)."""
    try:
        return Action(kind="chmod", path=str(path), mode=os.stat(path).st_mode & 0o7777)
    except OSError as e:  # noqa: BLE001
        logger.warning("No se pudo leer el modo de %s: %s", path, e)
        return Action(kind="irreversible", note=f"modo de {path} no capturado: {e}")


async def snapshot_service(service: str) -> Action:
    """Captura si el servicio está activo/habilitado, para restaurarlo luego."""
    try:
        a = await run_command(["systemctl", "is-active", service], timeout=15, check=False)
        e = await run_command(["systemctl", "is-enabled", service], timeout=15, check=False)
        return Action(
            kind="service", service=service,
            was_active=(a.stdout.strip() == "active"),
            was_enabled=(e.stdout.strip() == "enabled"),
        )
    except Exception as ex:  # noqa: BLE001
        logger.warning("No se pudo capturar el estado de %s: %s", service, ex)
        return Action(kind="irreversible", note=f"estado de {service} no capturado: {ex}")


def command_undo(cmd: list[str], note: str = "") -> Action:
    return Action(kind="command", cmd=list(cmd), note=note)


def irreversible(note: str) -> Action:
    return Action(kind="irreversible", note=note)


# ──────────────────────────────────────────────────────────────────────────────
# Entrada del journal
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class RollbackEntry:
    finding_id: str
    host: str
    user: str
    ts: float
    fix_message: str
    actions: list[Action] = field(default_factory=list)
    rolled_back_ts: float | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["actions"] = [a.to_dict() for a in self.actions]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> RollbackEntry:
        actions = [Action.from_dict(a) for a in d.get("actions", [])]
        return cls(
            finding_id=d["finding_id"], host=d.get("host", "localhost"),
            user=d.get("user", "unknown"), ts=d.get("ts", 0.0),
            fix_message=d.get("fix_message", ""), actions=actions,
            rolled_back_ts=d.get("rolled_back_ts"),
        )

    @property
    def reversible(self) -> bool:
        return any(a.kind != "irreversible" for a in self.actions)


# ──────────────────────────────────────────────────────────────────────────────
# Journal persistente (JSONL)
# ──────────────────────────────────────────────────────────────────────────────

class RollbackJournal:
    """Almacén append-only de entradas de rollback en un fichero JSONL."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def append(self, entry: RollbackEntry) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
        except OSError as e:  # noqa: BLE001
            logger.error("No se pudo escribir el journal de rollback (%s): %s", self.path, e)

    def _load_all(self) -> list[RollbackEntry]:
        if not self.path.exists():
            return []
        entries: list[RollbackEntry] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(RollbackEntry.from_dict(json.loads(line)))
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning("Línea de journal inválida ignorada: %s", e)
        return entries

    def latest_active(self, finding_id: str, host: str = "localhost") -> RollbackEntry | None:
        """La entrada más reciente para (finding, host) que aún NO se ha revertido."""
        match = [
            e for e in self._load_all()
            if e.finding_id == finding_id and e.host == host and e.rolled_back_ts is None
        ]
        return max(match, key=lambda e: e.ts) if match else None

    def list_active(self) -> list[RollbackEntry]:
        return [e for e in self._load_all() if e.rolled_back_ts is None]

    def mark_rolled_back(self, entry: RollbackEntry, when: float | None = None) -> None:
        """Reescribe el journal marcando la entrada (finding+host+ts) como revertida."""
        when = when or time.time()
        all_entries = self._load_all()
        for e in all_entries:
            if (e.finding_id == entry.finding_id and e.host == entry.host
                    and e.ts == entry.ts and e.rolled_back_ts is None):
                e.rolled_back_ts = when
        try:
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                for e in all_entries:
                    f.write(json.dumps(e.to_dict(), ensure_ascii=False) + "\n")
            tmp.replace(self.path)
        except OSError as e:  # noqa: BLE001
            logger.error("No se pudo actualizar el journal de rollback: %s", e)


# ──────────────────────────────────────────────────────────────────────────────
# Ejecución del rollback
# ──────────────────────────────────────────────────────────────────────────────

async def _undo_action(a: Action, runner=run_command) -> tuple[bool, str]:
    if a.kind == "file":
        p = Path(a.path)
        try:
            if a.existed:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(base64.b64decode(a.content_b64 or ""))
                if a.mode is not None:
                    os.chmod(p, a.mode)
                return True, f"restaurado {a.path}"
            if p.exists():
                p.unlink()
                return True, f"eliminado {a.path} (no existía antes)"
            return True, f"{a.path} ya no existe"
        except OSError as e:  # noqa: BLE001
            return False, f"fallo restaurando {a.path}: {e}"

    if a.kind == "chmod":
        try:
            if Path(a.path).exists() and a.mode is not None:
                os.chmod(a.path, a.mode)
                return True, f"permisos de {a.path} → {oct(a.mode)}"
            return True, f"{a.path} no existe; nada que restaurar"
        except OSError as e:  # noqa: BLE001
            return False, f"fallo en chmod de {a.path}: {e}"

    if a.kind == "service":
        msgs = []
        ok = True
        # Estado de habilitación
        verb = "enable" if a.was_enabled else "disable"
        r = await runner(["systemctl", verb, a.service], timeout=20, check=False)
        ok = ok and r.returncode == 0
        msgs.append(f"{a.service} {verb}")
        # Estado de actividad
        verb2 = "start" if a.was_active else "stop"
        r2 = await runner(["systemctl", verb2, a.service], timeout=20, check=False)
        ok = ok and r2.returncode == 0
        msgs.append(f"{a.service} {verb2}")
        return ok, "; ".join(msgs)

    if a.kind == "command":
        r = await runner(a.cmd, timeout=60, check=False)
        ok = r.returncode == 0
        return ok, f"{' '.join(a.cmd)} → rc={r.returncode}"

    if a.kind == "irreversible":
        return True, f"[no reversible] {a.note}"

    return False, f"acción desconocida: {a.kind}"


async def perform_rollback(entry: RollbackEntry, runner=run_command) -> tuple[bool, list[str]]:
    """Revierte una entrada aplicando sus acciones en orden inverso.

    Devuelve (ok_global, mensajes). `ok_global` es True si ninguna acción reversible
    falló (las marcadas como no reversibles no cuentan como fallo).
    """
    messages: list[str] = []
    ok_global = True
    for a in reversed(entry.actions):
        ok, msg = await _undo_action(a, runner=runner)
        messages.append(("✓ " if ok else "✗ ") + msg)
        if not ok and a.kind != "irreversible":
            ok_global = False
    return ok_global, messages


async def rollback_finding(
    journal: RollbackJournal, finding_id: str, host: str = "localhost", runner=run_command,
) -> tuple[bool, str]:
    """Busca el último fix activo de (finding, host) y lo revierte; marca el journal."""
    entry = journal.latest_active(finding_id, host)
    if entry is None:
        return False, f"No hay un fix reversible registrado para {finding_id} en {host}."
    ok, messages = await perform_rollback(entry, runner=runner)
    if ok:
        journal.mark_rolled_back(entry)
    return ok, " | ".join(messages) if messages else "Sin acciones que revertir."
