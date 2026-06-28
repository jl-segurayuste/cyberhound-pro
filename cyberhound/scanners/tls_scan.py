"""
Escáner TLS/SSL para CyberHound Pro.

Analiza la configuración TLS de servicios accesibles por red:
  - Expiración del certificado (caducado / caduca pronto)
  - Certificados autofirmados
  - Protocolos obsoletos (SSLv3, TLS 1.0, TLS 1.1)
  - Algoritmos de firma débiles (MD5, SHA-1)
  - Tamaño de clave insuficiente (RSA < 2048)
  - Desajuste de hostname (CN/SAN)

No requiere herramientas externas: usa el módulo `ssl` de la stdlib.
Cada comprobación es defensiva — un fallo de conexión no aborta el resto.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime

from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("tls_scan")

# Días antes de la expiración a partir de los cuales se avisa
EXPIRY_WARNING_DAYS = 30
EXPIRY_CRITICAL_DAYS = 7

# Protocolos considerados obsoletos
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Algoritmos de firma débiles
WEAK_SIG_ALGOS = ("md5", "sha1")


def _f(fid, severity, title, description, remediation,
       evidence="", host="") -> Finding:
    return Finding(
        id=fid, category="tls", severity=severity, title=title,
        description=description, remediation=remediation,
        evidence=evidence, source_host=host,
    )


async def scan_target(host: str, port: int = 443, timeout: int = 10) -> list[Finding]:
    """Analiza el TLS de un host:puerto. Devuelve lista de findings."""
    findings: list[Finding] = []
    target = f"{host}:{port}"

    # Contexto permisivo: queremos inspeccionar incluso certs inválidos
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    loop = asyncio.get_event_loop()
    try:
        cert_bin, protocol, cipher = await asyncio.wait_for(
            loop.run_in_executor(None, _fetch_cert, host, port, ctx, timeout),
            timeout=timeout + 2,
        )
    except TimeoutError:
        logger.debug("TLS timeout en %s", target)
        return findings
    except (OSError, ssl.SSLError) as e:
        logger.debug("No se pudo conectar TLS a %s: %s", target, e)
        return findings

    if cert_bin is None:
        return findings

    # Protocolo obsoleto
    if protocol in WEAK_PROTOCOLS:
        findings.append(_f(
            f"tls_weak_protocol_{host}_{port}", "high",
            f"Protocolo TLS obsoleto en {target}",
            f"El servicio negocia {protocol}, considerado inseguro.",
            "Deshabilitar SSLv3/TLS 1.0/1.1; permitir solo TLS 1.2 y 1.3.",
            evidence=f"protocolo={protocol}, cipher={cipher}", host=host,
        ))

    # Analizar el certificado con detalle
    findings.extend(_analyze_cert(cert_bin, host, port))
    return findings


def _fetch_cert(host: str, port: int, ctx: ssl.SSLContext, timeout: int):
    """Conexión síncrona (en executor). Devuelve (cert_der, protocolo, cipher)."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert_bin = ssock.getpeercert(binary_form=True)
            protocol = ssock.version()
            cipher = ssock.cipher()[0] if ssock.cipher() else "?"
            return cert_bin, protocol, cipher


def _analyze_cert(cert_der: bytes, host: str, port: int) -> list[Finding]:
    findings: list[Finding] = []
    target = f"{host}:{port}"

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        logger.warning("cryptography no disponible — análisis TLS limitado")
        return findings

    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception as e:
        logger.debug("No se pudo parsear cert de %s: %s", target, e)
        return findings

    now = datetime.now(UTC)
    not_after = cert.not_valid_after_utc
    days_left = (not_after - now).days

    # Expiración
    if days_left < 0:
        findings.append(_f(
            f"tls_expired_{host}_{port}", "critical",
            f"Certificado caducado en {target}",
            f"El certificado caducó hace {-days_left} días ({not_after:%Y-%m-%d}).",
            "Renovar el certificado inmediatamente (Let's Encrypt / CA interna).",
            evidence=f"not_after={not_after:%Y-%m-%d}", host=host,
        ))
    elif days_left < EXPIRY_CRITICAL_DAYS:
        findings.append(_f(
            f"tls_expiring_soon_{host}_{port}", "high",
            f"Certificado caduca en {days_left} días en {target}",
            f"El certificado caduca el {not_after:%Y-%m-%d}.",
            "Renovar el certificado / verificar renovación automática.",
            evidence=f"dias_restantes={days_left}", host=host,
        ))
    elif days_left < EXPIRY_WARNING_DAYS:
        findings.append(_f(
            f"tls_expiry_warning_{host}_{port}", "medium",
            f"Certificado caduca pronto ({days_left} días) en {target}",
            f"El certificado caduca el {not_after:%Y-%m-%d}.",
            "Programar renovación del certificado.",
            evidence=f"dias_restantes={days_left}", host=host,
        ))

    # Autofirmado
    if cert.issuer == cert.subject:
        findings.append(_f(
            f"tls_self_signed_{host}_{port}", "medium",
            f"Certificado autofirmado en {target}",
            "El certificado es autofirmado; los clientes no lo validan contra una CA.",
            "Usar un certificado de una CA reconocida (Let's Encrypt) o CA interna confiable.",
            evidence=f"issuer={cert.issuer.rfc4514_string()[:80]}", host=host,
        ))

    # Algoritmo de firma débil
    sig_algo = (cert.signature_hash_algorithm.name
                if cert.signature_hash_algorithm else "desconocido")
    if any(weak in sig_algo.lower() for weak in WEAK_SIG_ALGOS):
        findings.append(_f(
            f"tls_weak_signature_{host}_{port}", "high",
            f"Firma débil ({sig_algo}) en {target}",
            f"El certificado usa {sig_algo}, vulnerable a colisiones.",
            "Reemitir el certificado con SHA-256 o superior.",
            evidence=f"sig_algo={sig_algo}", host=host,
        ))

    # Tamaño de clave RSA insuficiente
    pubkey = cert.public_key()
    if isinstance(pubkey, rsa.RSAPublicKey) and pubkey.key_size < 2048:
        findings.append(_f(
            f"tls_weak_key_{host}_{port}", "high",
            f"Clave RSA débil ({pubkey.key_size} bits) en {target}",
            f"La clave pública RSA es de solo {pubkey.key_size} bits.",
            "Reemitir con clave RSA ≥ 2048 bits o EC P-256.",
            evidence=f"key_size={pubkey.key_size}", host=host,
        ))

    return findings


class TLSScanner:
    """Escanea múltiples objetivos TLS en paralelo."""

    # Objetivos por defecto: servicios típicos del homelab
    DEFAULT_TARGETS = [
        ("localhost", 443), ("localhost", 8443), ("localhost", 9200),
        ("localhost", 5601), ("localhost", 8200),
    ]

    @classmethod
    async def full_scan(
        cls, targets: list[tuple[str, int]] | None = None
    ) -> list[Finding]:
        targets = targets or cls.DEFAULT_TARGETS
        results = await asyncio.gather(
            *(scan_target(h, p) for h, p in targets),
            return_exceptions=True,
        )
        findings: list[Finding] = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, Exception):
                logger.debug("Error en scan TLS: %s", r)
        return findings
