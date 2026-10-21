"""
Análisis programados de cada organización (y de la plataforma): tabla y validación.

El scheduler de la plataforma (cyberhound/core/scheduler.py) audita el propio servidor y
solo lo ve el superadmin. Estos son análisis de red/web/TLS/DNS que cualquier organización
programa sobre su ámbito: se guardan en su BD y los lanza el servidor en su contexto, con el
mismo código que un análisis manual por WebSocket.
"""
from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime

from cyberhound.core.security import InputValidator, ValidationError

SCHEDULES_TABLE = """
CREATE TABLE IF NOT EXISTS schedules (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    task         TEXT NOT NULL,
    targets      TEXT NOT NULL,
    hour         INTEGER NOT NULL,
    minute       INTEGER NOT NULL,
    days         TEXT NOT NULL,
    enabled      INTEGER DEFAULT 1,
    created_by   TEXT DEFAULT '',
    created_at   TEXT NOT NULL,
    last_run     TEXT,
    last_status  TEXT DEFAULT '',
    last_scan_id INTEGER,
    ssh_credential TEXT
);
"""

# Tarea → campo del mensaje WS con los objetivos. Las de SSH entran con una credencial guardada
# (core/ssh_credentials.py): obligatoria en "ssh" y opcional en "network" (con ella, además de
# descubrir y ver puertos, audita por SSH los equipos encontrados).
TASKS = {
    "network": "networks", "ssh": "hosts", "web_headers": "urls", "web_exposure": "urls", "api_security": "urls",
    "nuclei": "urls", "tls": "targets", "dns": "domains", "subdomain_enum": "domains",
}
SSH_TASKS = ("ssh", "network")
MAX_PER_TENANT = 50


def ws_message(task: str, targets: list[str], ssh_credential: str | None = None) -> dict:
    """Mensaje WS saneado equivalente al análisis manual (ValidationError si no vale)."""
    field = TASKS[task]
    value = ",".join(targets) if field == "networks" else " ".join(targets) if field == "hosts" else targets
    raw: dict = {"task": task, field: value}
    if task in SSH_TASKS:
        if ssh_credential:
            raw["ssh_credential"] = ssh_credential
        raw["ssh_audit"] = bool(ssh_credential)   # sin credencial, red = solo descubrimiento y puertos
    return InputValidator.ws_message(raw)


def validate(body: dict, partial: bool = False) -> dict:
    """Campos normalizados de una programación; ValueError con el motivo."""
    out: dict = {}
    if not partial or "name" in body:
        name = str(body.get("name", "")).strip()
        if not name:
            raise ValueError("Ponle un nombre")
        out["name"] = name[:80]
    if not partial or "task" in body:
        task = str(body.get("task", ""))
        if task not in TASKS:
            raise ValueError(f"Tipo de análisis no programable: {task or '(vacío)'}")
        out["task"] = task
    if not partial or "targets" in body:
        targets = body.get("targets", [])
        if isinstance(targets, str):
            targets = [t.strip() for t in targets.replace("\n", ",").split(",")]
        if not isinstance(targets, list) or not [t for t in targets if str(t).strip()]:
            raise ValueError("Indica al menos un objetivo")
        out["targets"] = [str(t).strip() for t in targets if str(t).strip()][:50]
    for k, lo, hi in (("hour", 0, 23), ("minute", 0, 59)):
        if not partial or k in body:
            v = body.get(k, 3 if k == "hour" else 0)
            if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
                raise ValueError(f"{k} debe estar entre {lo} y {hi}")
            out[k] = v
    if not partial or "days" in body:
        days = body.get("days", list(range(7)))
        if (not isinstance(days, list) or not days
                or not all(isinstance(d, int) and not isinstance(d, bool) and 0 <= d <= 6 for d in days)):
            raise ValueError("days: lista de 0 (lunes) a 6 (domingo)")
        out["days"] = sorted(set(days))
    if "enabled" in body:
        if not isinstance(body["enabled"], bool):
            raise ValueError("enabled debe ser true/false")
        out["enabled"] = body["enabled"]
    if not partial or "ssh_credential" in body:
        cred = body.get("ssh_credential") or None
        if cred is not None and not (isinstance(cred, str) and InputValidator.is_credential_id(cred)):
            raise ValueError("ssh_credential no válida")
        out["ssh_credential"] = cred
    return out


def check_credential(task: str, ssh_credential: str | None) -> None:
    if task == "ssh" and not ssh_credential:
        raise ValueError("La auditoría SSH programada necesita una credencial SSH guardada")
    if ssh_credential and task not in SSH_TASKS:
        raise ValueError("Solo los análisis de red y SSH usan credencial SSH")


def check_targets(task: str, targets: list[str], ssh_credential: str | None = None) -> None:
    try:
        ws_message(task, targets, ssh_credential)
    except ValidationError as e:
        raise ValueError(f"Objetivos no válidos: {e.reason}") from None


def is_due(sched: dict, now: datetime) -> bool:
    if not sched.get("enabled"):
        return False
    if now.weekday() not in sched["days"] or (now.hour, now.minute) != (sched["hour"], sched["minute"]):
        return False
    last = sched.get("last_run") or ""      # hora local, como hour/minute
    return not last.startswith(now.strftime("%Y-%m-%dT%H:%M"))


def _decode(row: dict) -> dict:
    d = dict(row)
    d["targets"] = json.loads(d["targets"])
    d["days"] = [int(x) for x in d["days"].split(",") if x != ""]
    d["enabled"] = bool(d["enabled"])
    return d


class SchedulesMixin:
    async def _run(self, sql: str, *args) -> int: ...
    async def _rows(self, sql: str, *args) -> list[dict]: ...
    async def _val(self, sql: str, *args): ...

    async def list_schedules(self) -> list[dict]:
        return [_decode(r) for r in await self._rows("SELECT * FROM schedules ORDER BY created_at")]

    async def get_schedule(self, sched_id: str) -> dict | None:
        rows = await self._rows("SELECT * FROM schedules WHERE id=?", sched_id)
        return _decode(rows[0]) if rows else None

    async def count_schedules(self) -> int:
        return int(await self._val("SELECT COUNT(*) FROM schedules") or 0)

    async def create_schedule(self, data: dict, created_by: str = "") -> str:
        sid = secrets.token_hex(4)
        await self._run("INSERT INTO schedules (id,name,task,targets,hour,minute,days,enabled,created_by,created_at,"
                        "ssh_credential) VALUES (?,?,?,?,?,?,?,?,?,?,?)", sid, data["name"], data["task"],
                        json.dumps(data["targets"]), data["hour"], data["minute"], ",".join(map(str, data["days"])),
                        1 if data.get("enabled", True) else 0, created_by, datetime.now(UTC).isoformat(),
                        data.get("ssh_credential"))
        return sid

    async def update_schedule(self, sched_id: str, data: dict) -> bool:
        sets, args = [], []
        for k, v in data.items():
            if k == "targets":
                v = json.dumps(v)
            elif k == "days":
                v = ",".join(map(str, v))
            elif k == "enabled":
                v = 1 if v else 0
            sets.append(f"{k}=?")
            args.append(v)
        if not sets:
            return await self.get_schedule(sched_id) is not None
        return await self._run(f"UPDATE schedules SET {', '.join(sets)} WHERE id=?", *args, sched_id) > 0

    async def delete_schedule(self, sched_id: str) -> bool:
        return await self._run("DELETE FROM schedules WHERE id=?", sched_id) > 0

    async def mark_schedule_run(self, sched_id: str, when: str, status: str, scan_id: int | None) -> None:
        await self._run("UPDATE schedules SET last_run=?, last_status=?, last_scan_id=? WHERE id=?",
                        when, status[:200], scan_id, sched_id)
