"""
Claves de host SSH conocidas de cada organización (TOFU, como known_hosts de OpenSSH).

Antes las conexiones SSH no verificaban la clave del host (known_hosts=None): quien suplantara un
equipo en la red recibía la contraseña guardada o el script con sudo. Ahora la primera conexión a
host:puerto guarda su clave y las siguientes tienen que presentar la misma; si cambia, la conexión
se corta y un administrador decide si olvidarla (Configuración › Credenciales SSH).
"""
from __future__ import annotations

from datetime import UTC, datetime

SSH_HOST_KEYS_TABLE = """
CREATE TABLE IF NOT EXISTS ssh_host_keys (
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL,
    key         TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT,
    PRIMARY KEY (host, port)
);
"""


def known_hosts_line(host: str, port: int, key: str) -> str:
    return f"{host if port == 22 else f'[{host}]:{port}'} {key}\n"


class SSHHostKeysMixin:
    async def _run(self, sql: str, *args) -> int: ...
    async def _rows(self, sql: str, *args) -> list[dict]: ...

    async def list_ssh_host_keys(self) -> list[dict]:
        return await self._rows("SELECT * FROM ssh_host_keys ORDER BY host, port")

    async def get_ssh_host_key(self, host: str, port: int) -> dict | None:
        rows = await self._rows("SELECT * FROM ssh_host_keys WHERE host=? AND port=?", host, port)
        return rows[0] if rows else None

    async def add_ssh_host_key(self, host: str, port: int, key: str, fingerprint: str) -> None:
        now = datetime.now(UTC).isoformat()
        await self._run("INSERT INTO ssh_host_keys (host,port,key,fingerprint,first_seen,last_seen) VALUES (?,?,?,?,?,?) "
                        "ON CONFLICT (host, port) DO NOTHING", host, port, key, fingerprint, now, now)

    async def touch_ssh_host_key(self, host: str, port: int) -> None:
        await self._run("UPDATE ssh_host_keys SET last_seen=? WHERE host=? AND port=?",
                        datetime.now(UTC).isoformat(), host, port)

    async def delete_ssh_host_key(self, host: str, port: int) -> bool:
        return await self._run("DELETE FROM ssh_host_keys WHERE host=? AND port=?", host, port) > 0


class HostKeyStore:
    """Lo que necesita RemoteAuditor: la clave conocida de un host y guardar la primera."""

    def __init__(self, db) -> None:
        self.db = db

    async def known(self, host: str, port: int) -> str | None:
        row = await self.db.get_ssh_host_key(host, port)
        return row["key"] if row else None

    async def learn(self, host: str, port: int, key: str, fingerprint: str) -> None:
        await self.db.add_ssh_host_key(host, port, key, fingerprint)

    async def seen(self, host: str, port: int) -> None:
        await self.db.touch_ssh_host_key(host, port)
