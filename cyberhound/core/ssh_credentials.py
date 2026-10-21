"""
Credenciales SSH guardadas de cada organización (y de la plataforma).

Sirven para los análisis SSH programados, que no tienen a nadie delante para escribir la
contraseña, y para que una organización use una clave propia en lugar de las del servidor.
El secreto (clave privada o contraseña) se guarda cifrado con una clave derivada de
auth.secret y del slug de la organización: copiado a la BD de otra no se puede descifrar.
La API nunca lo devuelve; de una clave solo se muestran la pública y su huella.
"""
from __future__ import annotations

import secrets
from datetime import UTC, datetime

from cyberhound.core.security import InputValidator, ValidationError
from cyberhound.core.totp import _fernet

SSH_CREDENTIALS_TABLE = """
CREATE TABLE IF NOT EXISTS ssh_credentials (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    username    TEXT NOT NULL,
    port        INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    secret      TEXT NOT NULL,
    public_key  TEXT DEFAULT '',
    fingerprint TEXT DEFAULT '',
    created_by  TEXT DEFAULT '',
    created_at  TEXT NOT NULL,
    last_used   TEXT
);
"""

KINDS = ("generate", "key", "password")
MAX_PER_TENANT = 50
_SEALED = "enc:v1:"
_PUBLIC = ("id", "name", "username", "port", "kind", "public_key", "fingerprint", "created_by", "created_at",
           "last_used")


def _info(slug: str) -> bytes:
    return b"cyberhound-ssh-v1:" + slug.encode()


def seal(value: str, key: str, slug: str) -> str:
    return _SEALED + _fernet(key, _info(slug)).encrypt(value.encode()).decode()


def unseal(value: str, key: str, slug: str) -> str | None:
    """Secreto en claro, o None si no se puede descifrar (auth.secret cambiado u otra organización)."""
    from cryptography.fernet import InvalidToken
    if not value.startswith(_SEALED):
        return None
    try:
        return _fernet(key, _info(slug)).decrypt(value[len(_SEALED):].encode()).decode()
    except InvalidToken:
        return None


def public_view(row: dict) -> dict:
    return {k: row.get(k) for k in _PUBLIC}


def _load_key(text: str, passphrase: str | None):
    import asyncssh
    try:
        return asyncssh.import_private_key(text, passphrase or None)
    except asyncssh.KeyEncryptionError:
        raise ValueError("La frase de paso de la clave no es correcta") from None
    except (asyncssh.KeyImportError, ValueError, TypeError) as e:
        if "assphrase" in str(e):       # asyncssh: "Passphrase must be specified to import encrypted…"
            raise ValueError("La clave está cifrada: indica su frase de paso") from None
        raise ValueError("No es una clave privada SSH válida (OpenSSH o PEM)") from None


def prepare(body: dict, key: str, slug: str, partial: bool = False) -> dict:
    """Campos a guardar a partir de la petición; ValueError con el motivo.

    Con partial=True (edición) solo se cambian los campos presentes; el secreto solo si se manda
    uno nuevo. Las claves se guardan sin frase de paso (ya van cifradas) y en formato OpenSSH."""
    out: dict = {}
    if not partial or "name" in body:
        name = str(body.get("name", "")).strip()
        if not name:
            raise ValueError("Ponle un nombre")
        out["name"] = name[:80]
    try:
        if not partial or "username" in body:
            out["username"] = InputValidator.ssh_username(str(body.get("username", "")).strip() or "root")
        if not partial or "port" in body:
            out["port"] = InputValidator.port(body.get("port", 22), "port")
    except ValidationError as e:
        raise ValueError(e.reason) from None
    kind = body.get("kind")
    if partial and kind is None:
        return out
    if kind not in KINDS:
        raise ValueError("kind: generate (generar un par de claves), key (pegar una clave) o password")
    if kind == "password":
        password = str(body.get("password") or "")
        if not password or len(password) > 1024:
            raise ValueError("Indica la contraseña")
        out.update(kind="password", secret=seal(password, key, slug), public_key="", fingerprint="")
        return out
    import asyncssh
    if kind == "generate":
        pkey = asyncssh.generate_private_key("ssh-ed25519", comment=f"cyberhound-{slug}")
    else:
        text = str(body.get("private_key") or "").strip()
        if not text or len(text) > 16384:
            raise ValueError("Pega la clave privada")
        pkey = _load_key(text, body.get("passphrase"))
    out.update(kind="key", secret=seal(pkey.export_private_key("openssh").decode(), key, slug),
               public_key=pkey.export_public_key("openssh").decode().strip(), fingerprint=pkey.get_fingerprint())
    return out


def to_ssh_credentials(row: dict, key: str, slug: str):
    """SSHCredentials listas para conectar; ValueError si el secreto no se puede descifrar."""
    from cyberhound.scanners.ssh_audit import SSHCredentials
    secret = unseal(row["secret"], key, slug)
    if secret is None:
        raise ValueError(f"No se puede descifrar la credencial SSH '{row['name']}' "
                         "(¿ha cambiado auth.secret?): vuelve a guardarla")
    return SSHCredentials(username=row["username"], port=int(row["port"]), use_server_keys=False,
                          **({"private_key": secret} if row["kind"] == "key" else {"password": secret}))


class SSHCredentialsMixin:
    async def _run(self, sql: str, *args) -> int: ...
    async def _rows(self, sql: str, *args) -> list[dict]: ...
    async def _val(self, sql: str, *args): ...

    async def list_ssh_credentials(self) -> list[dict]:
        return [public_view(r) for r in await self._rows("SELECT * FROM ssh_credentials ORDER BY name")]

    async def get_ssh_credential(self, cred_id: str) -> dict | None:
        rows = await self._rows("SELECT * FROM ssh_credentials WHERE id=?", cred_id)
        return dict(rows[0]) if rows else None

    async def count_ssh_credentials(self) -> int:
        return int(await self._val("SELECT COUNT(*) FROM ssh_credentials") or 0)

    async def create_ssh_credential(self, data: dict, created_by: str = "") -> str:
        cid = secrets.token_hex(4)
        await self._run("INSERT INTO ssh_credentials (id,name,username,port,kind,secret,public_key,fingerprint,"
                        "created_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)", cid, data["name"], data["username"],
                        data["port"], data["kind"], data["secret"], data["public_key"], data["fingerprint"],
                        created_by, datetime.now(UTC).isoformat())
        return cid

    async def update_ssh_credential(self, cred_id: str, data: dict) -> bool:
        if not data:
            return await self.get_ssh_credential(cred_id) is not None
        sets = ", ".join(f"{k}=?" for k in data)
        return await self._run(f"UPDATE ssh_credentials SET {sets} WHERE id=?", *data.values(), cred_id) > 0

    async def delete_ssh_credential(self, cred_id: str) -> bool:
        return await self._run("DELETE FROM ssh_credentials WHERE id=?", cred_id) > 0

    async def touch_ssh_credential(self, cred_id: str) -> None:
        await self._run("UPDATE ssh_credentials SET last_used=? WHERE id=?", datetime.now(UTC).isoformat(), cred_id)

    async def schedules_using_credential(self, cred_id: str) -> list[str]:
        return [r["name"] for r in await self._rows("SELECT name FROM schedules WHERE ssh_credential=?", cred_id)]
