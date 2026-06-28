"""Hashing de contraseñas con KDF salado (PBKDF2-HMAC-SHA256).

Sustituye al SHA-256 sin sal previo (rápido → vulnerable a fuerza bruta y
rainbow tables). Mantiene **retrocompatibilidad**: los hashes antiguos en formato
SHA-256 (64 hex) se siguen verificando, de modo que ningún login existente se
rompe; al cambiar la contraseña se almacena ya en el formato nuevo.

Formato nuevo:  ``pbkdf2_sha256$<iteraciones>$<salt_hex>$<hash_hex>``
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

# OWASP (2023) recomienda >= 600k iteraciones para PBKDF2-HMAC-SHA256.
ITERATIONS = 600_000
_ALGO = "pbkdf2_sha256"
_SALT_BYTES = 16
_DKLEN = 32


def hash_password(password: str, *, iterations: int = ITERATIONS) -> str:
    """Devuelve el hash salado de la contraseña en el formato nuevo."""
    salt = secrets.token_bytes(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, _DKLEN)
    return f"{_ALGO}${iterations}${salt.hex()}${dk.hex()}"


def _verify_pbkdf2(password: str, stored: str) -> bool:
    try:
        algo, iter_s, salt_hex, hash_hex = stored.split("$")
        if algo != _ALGO:
            return False
        iterations = int(iter_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, AttributeError):
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, len(expected))
    return hmac.compare_digest(dk, expected)


def _verify_legacy_sha256(password: str, stored: str) -> bool:
    """Verifica el formato antiguo (SHA-256 sin sal, 64 hex)."""
    given = hashlib.sha256(password.encode()).hexdigest()
    return hmac.compare_digest(given, stored)


def verify_password(password: str, stored: str) -> bool:
    """Verifica la contraseña contra el hash almacenado (nuevo o antiguo).

    La comparación es de tiempo constante en ambos formatos.
    """
    if not stored:
        return False
    if stored.startswith(_ALGO + "$"):
        return _verify_pbkdf2(password, stored)
    # Compatibilidad: hash legacy SHA-256 (64 caracteres hex).
    if len(stored) == 64 and all(c in "0123456789abcdef" for c in stored.lower()):
        return _verify_legacy_sha256(password, stored)
    return False


def needs_rehash(stored: str) -> bool:
    """True si el hash está en el formato antiguo y conviene re-hashearlo."""
    return not (stored or "").startswith(_ALGO + "$")
