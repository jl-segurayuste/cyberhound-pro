"""
Autenticación de dos factores (2FA) con TOTP para CyberHound Pro.

Compatible con:
  - Google Authenticator
  - Authy
  - Bitwarden Authenticator
  - Cualquier app que soporte RFC 6238

Implementación:
  - Generación de secretos TOTP (base32)
  - Verificación de códigos con ventana de ±1 intervalo (tolerancia de reloj)
  - Generación de QR code como URI otpauth://
  - Almacenamiento del secreto TOTP por usuario en la BD
  - Códigos de recuperación de un solo uso (8 códigos)
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import time
from base64 import b32decode, b32encode
from urllib.parse import quote

from cyberhound.core.logging import get_logger

logger = get_logger("totp")

TOTP_ISSUER = "CyberHound Pro"
TOTP_DIGITS = 6
TOTP_PERIOD = 30  # segundos
TOTP_WINDOW = 1   # ±1 intervalo de tolerancia


# ── TOTP Core ─────────────────────────────────────────────────────────────────

def generate_secret() -> str:
    """Genera un secreto TOTP aleatorio en base32 (160 bits)."""
    raw = secrets.token_bytes(20)
    return b32encode(raw).decode("utf-8")


def _hotp(secret: str, counter: int) -> int:
    """HMAC-based One-Time Password (RFC 4226)."""
    key = b32decode(secret.upper().replace(" ", ""), casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0]
    code &= 0x7FFFFFFF
    return code % (10 ** TOTP_DIGITS)


def generate_totp(secret: str, timestamp: float | None = None) -> str:
    """Genera el TOTP actual para el secreto dado."""
    ts = timestamp or time.time()
    counter = int(ts) // TOTP_PERIOD
    code = _hotp(secret, counter)
    return str(code).zfill(TOTP_DIGITS)


def verify_totp(secret: str, code: str, timestamp: float | None = None) -> bool:
    """
    Verifica un código TOTP con tolerancia de ±TOTP_WINDOW intervalos.
    Devuelve True si el código es válido.
    """
    if not code or not isinstance(code, str):
        return False
    code = code.strip().replace(" ", "")
    if len(code) != TOTP_DIGITS or not code.isdigit():
        return False

    ts = timestamp or time.time()
    counter = int(ts) // TOTP_PERIOD

    for offset in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
        expected = str(_hotp(secret, counter + offset)).zfill(TOTP_DIGITS)
        if hmac.compare_digest(expected, code):
            return True
    return False


def get_totp_uri(secret: str, username: str) -> str:
    """
    Genera el URI otpauth:// para importar en apps de autenticación.
    Compatible con Google Authenticator, Authy, etc.
    """
    issuer  = quote(TOTP_ISSUER)
    account = quote(f"{TOTP_ISSUER}:{username}")
    return (
        f"otpauth://totp/{account}"
        f"?secret={secret}"
        f"&issuer={issuer}"
        f"&digits={TOTP_DIGITS}"
        f"&period={TOTP_PERIOD}"
        f"&algorithm=SHA1"
    )


def generate_qr_svg(uri: str) -> str:
    """
    Genera un QR code como SVG para mostrar en la interfaz web.
    Usa segno si está disponible, fallback a un SVG con el URI.
    """
    try:
        import segno
        qr = segno.make(uri, error="M")
        import io
        buf = io.StringIO()
        qr.save(buf, kind="svg", scale=4, border=2, svgclass="qr-code", xmldecl=False)
        return buf.getvalue()
    except ImportError:
        pass

    # Fallback: mostrar el URI como texto en SVG
    from html import escape
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 300 80"
         style="background:#fff;border:1px solid #ccc;border-radius:4px;padding:8px">
  <text x="150" y="20" text-anchor="middle" font-size="12" fill="#333">
    Escanea con tu app de autenticación:
  </text>
  <text x="10" y="50" font-size="8" fill="#666" word-spacing="0">
    {escape(uri[:80])}
  </text>
  <text x="10" y="65" font-size="8" fill="#666">
    {escape(uri[80:160] if len(uri) > 80 else '')}
  </text>
</svg>"""


# ── Códigos de recuperación ───────────────────────────────────────────────────

def generate_recovery_codes(count: int = 8) -> list[str]:
    """
    Genera códigos de recuperación de un solo uso.
    Formato: XXXX-XXXX-XXXX (12 chars hexadecimales con guiones)
    """
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(6).upper()
        codes.append(f"{raw[:4]}-{raw[4:8]}-{raw[8:12]}")
    return codes


def hash_recovery_code(code: str) -> str:
    """Hash SHA-256 de un código de recuperación para almacenamiento seguro."""
    normalized = code.strip().upper().replace("-", "").replace(" ", "")
    return hashlib.sha256(normalized.encode()).hexdigest()


def verify_recovery_code(code: str, hashed_codes: list[str]) -> str | None:
    """
    Verifica si un código de recuperación es válido.
    Devuelve el hash del código usado (para marcarlo como consumido) o None.
    """
    normalized = code.strip().upper().replace("-", "").replace(" ", "")
    code_hash = hashlib.sha256(normalized.encode()).hexdigest()
    for h in hashed_codes:
        if hmac.compare_digest(h, code_hash):
            return h
    return None


# ── Gestión de 2FA en DB ──────────────────────────────────────────────────────

class TOTPManager:
    """
    Gestiona el ciclo completo de 2FA para un usuario.
    Requiere que la tabla `users` tenga columnas totp_secret y recovery_codes.
    """

    def __init__(self, db) -> None:
        self.db = db

    async def setup_2fa(self, username: str) -> dict:
        """
        Inicia la configuración de 2FA para un usuario.
        Devuelve el secreto, URI y QR code SVG para mostrar al usuario.
        El 2FA NO se activa hasta que el usuario verifique el primer código.
        """
        secret = generate_secret()
        uri    = get_totp_uri(secret, username)
        qr_svg = generate_qr_svg(uri)
        recovery_codes = generate_recovery_codes()

        # Guardar en BD como pendiente de verificación (no activado aún)
        await self.db.set_totp_pending(username, secret, recovery_codes)
        logger.info("2FA setup iniciado para usuario '%s'", username)

        return {
            "secret":         secret,
            "uri":            uri,
            "qr_svg":         qr_svg,
            "recovery_codes": recovery_codes,  # mostrar UNA VEZ
        }

    async def activate_2fa(self, username: str, code: str) -> bool:
        """
        Activa el 2FA verificando que el usuario puede generar códigos correctos.
        """
        pending = await self.db.get_totp_pending(username)
        if not pending:
            return False

        if not verify_totp(pending["secret"], code):
            logger.warning("2FA activación fallida para '%s': código incorrecto", username)
            return False

        await self.db.activate_totp(username)
        logger.info("2FA activado para usuario '%s'", username)
        return True

    async def verify(self, username: str, code: str) -> tuple[bool, str]:
        """
        Verifica el código 2FA de un usuario.
        Devuelve (válido, razón).
        Acepta tanto códigos TOTP como códigos de recuperación.
        """
        user = await self.db.get_user(username)
        if not user or not user.get("totp_enabled"):
            return True, "2FA no activo"  # sin 2FA, pasa siempre

        secret = user.get("totp_secret")
        if not secret:
            return False, "2FA configurado pero sin secreto"

        # Verificar TOTP primero
        if verify_totp(secret, code):
            return True, "TOTP válido"

        # Verificar código de recuperación
        recovery_hashes = user.get("recovery_codes_json", "[]")
        import json
        hashes = json.loads(recovery_hashes) if isinstance(recovery_hashes, str) else recovery_hashes
        used_hash = verify_recovery_code(code, hashes)
        if used_hash:
            # Consumir el código (no puede usarse de nuevo)
            remaining = [h for h in hashes if h != used_hash]
            await self.db.update_recovery_codes(username, remaining)
            logger.info("2FA: código de recuperación usado por '%s' (%d restantes)",
                        username, len(remaining))
            return True, f"Código de recuperación válido ({len(remaining)} restantes)"

        logger.warning("2FA: código inválido para '%s'", username)
        return False, "Código 2FA incorrecto"

    async def disable_2fa(self, username: str) -> None:
        await self.db.disable_totp(username)
        logger.info("2FA desactivado para usuario '%s'", username)
