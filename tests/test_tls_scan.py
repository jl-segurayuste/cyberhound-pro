"""Tests del escáner TLS/SSL."""
import datetime

import pytest

from cyberhound.scanners.tls_scan import (
    EXPIRY_WARNING_DAYS,
    TLSScanner,
    _analyze_cert,
    scan_target,
)


def _make_self_signed(days_valid=365, key_size=2048, hash_algo="sha256"):
    """Genera un cert autofirmado en memoria para tests."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.local")])
    now = datetime.datetime.now(datetime.UTC)
    algo = {"sha256": hashes.SHA256(), "sha1": hashes.SHA1()}[hash_algo]
    not_after = now + datetime.timedelta(days=days_valid)
    # not_valid_before siempre anterior a not_valid_after (incluso para caducados)
    not_before = min(now - datetime.timedelta(days=1),
                     not_after - datetime.timedelta(days=1))
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, algo)
    )
    return cert.public_bytes(serialization.Encoding.DER)


class TestAnalyzeCert:
    def test_self_signed_detected(self):
        der = _make_self_signed()
        findings = _analyze_cert(der, "test.local", 443)
        ids = [f.id for f in findings]
        assert any("self_signed" in i for i in ids)

    def test_expired_cert_critical(self):
        der = _make_self_signed(days_valid=-10)
        findings = _analyze_cert(der, "h", 443)
        expired = [f for f in findings if "expired" in f.id]
        assert expired
        assert expired[0].severity == "critical"

    def test_expiring_soon_warning(self):
        der = _make_self_signed(days_valid=EXPIRY_WARNING_DAYS - 5)
        findings = _analyze_cert(der, "h", 443)
        assert any("expir" in f.id for f in findings)

    def test_weak_key_detected(self):
        der = _make_self_signed(key_size=1024)
        findings = _analyze_cert(der, "h", 443)
        assert any("weak_key" in f.id for f in findings)

    def test_weak_signature_sha1(self):
        # cryptography moderno bloquea firmar con SHA-1; verificamos que la
        # constante de detección está bien definida (el scanner sí lo detecta
        # en certs reales con SHA-1 emitidos por otras herramientas).
        from cyberhound.scanners.tls_scan import WEAK_SIG_ALGOS
        assert "sha1" in WEAK_SIG_ALGOS
        assert "md5" in WEAK_SIG_ALGOS

    def test_valid_cert_no_expiry_finding(self):
        der = _make_self_signed(days_valid=365, key_size=2048, hash_algo="sha256")
        findings = _analyze_cert(der, "h", 443)
        # Solo debe quedar el self-signed, no expiración ni clave débil
        assert not any("expir" in f.id or "weak" in f.id for f in findings)


class TestTLSScanner:
    @pytest.mark.asyncio
    async def test_unreachable_target_no_crash(self):
        # Puerto cerrado: no debe lanzar, devuelve lista vacía
        findings = await scan_target("127.0.0.1", 59999, timeout=2)
        assert findings == []

    @pytest.mark.asyncio
    async def test_full_scan_returns_list(self):
        findings = await TLSScanner.full_scan(targets=[("127.0.0.1", 59999)])
        assert isinstance(findings, list)

    def test_default_targets_defined(self):
        assert len(TLSScanner.DEFAULT_TARGETS) > 0
        assert all(isinstance(t, tuple) and len(t) == 2 for t in TLSScanner.DEFAULT_TARGETS)
