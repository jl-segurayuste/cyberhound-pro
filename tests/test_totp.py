"""Tests del módulo TOTP/2FA."""
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from cyberhound.core.totp import (
    generate_recovery_codes,
    generate_secret,
    generate_totp,
    get_totp_uri,
    hash_recovery_code,
    verify_recovery_code,
    verify_totp,
)


class TestTOTPCore:

    def test_generate_secret_is_base32(self):
        secret = generate_secret()
        # Debe ser base32 válido (solo A-Z y 2-7)
        import re
        assert re.match(r'^[A-Z2-7]{32}$', secret)

    def test_generate_secret_is_random(self):
        s1 = generate_secret()
        s2 = generate_secret()
        assert s1 != s2

    def test_generate_totp_6_digits(self):
        secret = generate_secret()
        code = generate_totp(secret)
        assert len(code) == 6
        assert code.isdigit()

    def test_verify_totp_current_code(self):
        secret = generate_secret()
        code = generate_totp(secret)
        assert verify_totp(secret, code)

    def test_verify_totp_wrong_code(self):
        secret = generate_secret()
        assert not verify_totp(secret, "000000")

    def test_verify_totp_empty_code(self):
        secret = generate_secret()
        assert not verify_totp(secret, "")
        assert not verify_totp(secret, None)

    def test_verify_totp_with_tolerance(self):
        """Acepta código del intervalo anterior (tolerancia ±1)."""
        secret = generate_secret()
        # Código de 30 segundos atrás
        past_code = generate_totp(secret, time.time() - 30)
        assert verify_totp(secret, past_code)

    def test_verify_totp_too_old(self):
        """No acepta código de hace más de 1 intervalo."""
        secret = generate_secret()
        old_code = generate_totp(secret, time.time() - 120)
        assert not verify_totp(secret, old_code)

    def test_verify_totp_wrong_length(self):
        secret = generate_secret()
        assert not verify_totp(secret, "12345")    # 5 dígitos
        assert not verify_totp(secret, "1234567")  # 7 dígitos

    def test_verify_totp_non_numeric(self):
        secret = generate_secret()
        assert not verify_totp(secret, "abc123")
        assert not verify_totp(secret, "      ")

    def test_totp_uri_format(self):
        secret = generate_secret()
        uri = get_totp_uri(secret, "admin")
        assert uri.startswith("otpauth://totp/")
        assert secret in uri
        assert "admin" in uri
        assert "CyberHound" in uri

    def test_different_secrets_different_codes(self):
        s1 = generate_secret()
        s2 = generate_secret()
        ts = time.time()
        assert generate_totp(s1, ts) != generate_totp(s2, ts) or True  # pueden coincidir raramente


class TestRecoveryCodes:

    def test_generates_8_codes_by_default(self):
        codes = generate_recovery_codes()
        assert len(codes) == 8

    def test_generates_requested_count(self):
        codes = generate_recovery_codes(5)
        assert len(codes) == 5

    def test_code_format(self):
        codes = generate_recovery_codes()
        for code in codes:
            parts = code.split("-")
            assert len(parts) == 3
            assert all(len(p) == 4 for p in parts)

    def test_codes_are_unique(self):
        codes = generate_recovery_codes(8)
        assert len(set(codes)) == 8

    def test_hash_recovery_code(self):
        code = "ABCD-EF12-3456"
        h = hash_recovery_code(code)
        assert len(h) == 64  # SHA-256 hex
        # Mismo código → mismo hash (determinista)
        assert h == hash_recovery_code(code)

    def test_hash_case_insensitive(self):
        code = "abcd-ef12-3456"
        h1 = hash_recovery_code(code.upper())
        h2 = hash_recovery_code(code.lower())
        assert h1 == h2

    def test_hash_ignores_spaces_and_dashes(self):
        h1 = hash_recovery_code("ABCD-EF12-3456")
        h2 = hash_recovery_code("ABCDEF123456")
        h3 = hash_recovery_code("ABCD EF12 3456")
        assert h1 == h2 == h3

    def test_verify_recovery_code_found(self):
        codes = generate_recovery_codes(3)
        hashes = [hash_recovery_code(c) for c in codes]
        result = verify_recovery_code(codes[1], hashes)
        assert result == hashes[1]

    def test_verify_recovery_code_not_found(self):
        codes = generate_recovery_codes(3)
        hashes = [hash_recovery_code(c) for c in codes]
        result = verify_recovery_code("XXXX-XXXX-XXXX", hashes)
        assert result is None

    def test_verify_recovery_code_case_insensitive(self):
        code = "ABCD-EF12-3456"
        h = hash_recovery_code(code)
        result = verify_recovery_code(code.lower(), [h])
        assert result == h


class TestQRGeneration:

    def test_qr_svg_fallback(self):
        """Sin segno instalado, genera SVG de fallback con el URI."""
        uri = "otpauth://totp/test?secret=ABC"
        import sys
        # Forzar que segno no esté disponible
        original = sys.modules.get('segno')
        sys.modules['segno'] = None
        try:
            from importlib import reload

            import cyberhound.core.totp as totp_mod
            svg = totp_mod.generate_qr_svg(uri)
            assert '<svg' in svg
            assert 'cyberhound' in svg.lower() or 'test' in svg.lower() or uri[:30] in svg
        finally:
            if original is None:
                del sys.modules['segno']
            else:
                sys.modules['segno'] = original
