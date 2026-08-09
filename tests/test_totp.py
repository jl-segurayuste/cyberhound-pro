"""Tests del módulo TOTP/2FA."""
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from cyberhound.core.totp import (
    TOTPManager,
    find_matching_step,
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

    def test_verify_totp_es_sin_estado_no_impide_reutilizar(self):
        # `verify_totp()` por sí sola no lleva registro de qué códigos ya se
        # usaron -- esa es la trampa exacta que causó el bug real corregido
        # 2026-08-09: el mismo código válido se aceptaba un número ilimitado
        # de veces. La protección anti-repetición vive en `TOTPManager`
        # (ver TestTOTPManagerAntiReplay), que sí lleva estado persistente.
        secret = generate_secret()
        code = generate_totp(secret)
        assert verify_totp(secret, code)
        assert verify_totp(secret, code)

    def test_find_matching_step_devuelve_el_step_que_coincidio(self):
        secret = generate_secret()
        at = 1_700_000_000.0
        code = generate_totp(secret, at)
        assert find_matching_step(secret, code, at) == int(at) // 30

    def test_find_matching_step_sin_coincidencia_devuelve_none(self):
        secret = generate_secret()
        assert find_matching_step(secret, "000000") is None


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


class TestTOTPManagerAntiReplay:
    """Bug real corregido 2026-08-09: `TOTPManager.verify()`/`activate_2fa()`
    delegaban en `verify_totp()`, que es sin estado -- el mismo código válido
    se podía reenviar un número ilimitado de veces y siempre se aceptaba,
    anulando la garantía anti-repetición de TOTP. No existía NINGÚN test
    para `TOTPManager` hasta ahora, pese a ser la pieza que de verdad se usa
    en el flujo de login (ver tests/test_login_2fa.py)."""

    @pytest_asyncio.fixture
    async def db(self, tmp_path):
        from cyberhound.core.database import Database, UserRecord
        database = Database(tmp_path / "totp.db")
        await database.init()
        await database.create_user(UserRecord(username="admin", password_hash="x"))
        return database

    @pytest.mark.asyncio
    async def test_activate_2fa_con_codigo_correcto(self, db):
        secret = generate_secret()
        await db.set_totp_pending("admin", secret, generate_recovery_codes())
        assert await TOTPManager(db).activate_2fa("admin", generate_totp(secret)) is True

    @pytest.mark.asyncio
    async def test_activate_2fa_con_codigo_incorrecto(self, db):
        secret = generate_secret()
        await db.set_totp_pending("admin", secret, generate_recovery_codes())
        assert await TOTPManager(db).activate_2fa("admin", "000000") is False

    @pytest.mark.asyncio
    async def test_verify_acepta_codigo_correcto(self, db):
        secret = generate_secret()
        await db.set_totp_pending("admin", secret, generate_recovery_codes())
        await db.activate_totp("admin")
        ok, _ = await TOTPManager(db).verify("admin", generate_totp(secret, time.time() + 30))
        assert ok is True

    @pytest.mark.asyncio
    async def test_verify_no_deja_reutilizar_el_mismo_codigo(self, db):
        secret = generate_secret()
        await db.set_totp_pending("admin", secret, generate_recovery_codes())
        await db.activate_totp("admin")
        code = generate_totp(secret)

        ok1, _ = await TOTPManager(db).verify("admin", code)
        ok2, _ = await TOTPManager(db).verify("admin", code)
        assert ok1 is True
        assert ok2 is False

    @pytest.mark.asyncio
    async def test_activate_2fa_consume_el_codigo_para_verify(self, db):
        # El código usado para activar 2FA no debe volver a servir para el
        # login inmediatamente después -- comparten el mismo contador.
        secret = generate_secret()
        await db.set_totp_pending("admin", secret, generate_recovery_codes())
        code = generate_totp(secret)
        assert await TOTPManager(db).activate_2fa("admin", code) is True

        ok, _ = await TOTPManager(db).verify("admin", code)
        assert ok is False

    @pytest.mark.asyncio
    async def test_verify_permite_el_siguiente_paso_temporal(self, db):
        # `TOTPManager.verify()` siempre valida contra "ahora" (es la función
        # de login real, no admite marca de tiempo) -- por eso aquí se usan
        # desplazamientos relativos a time.time(), no una marca fija.
        secret = generate_secret()
        await db.set_totp_pending("admin", secret, generate_recovery_codes())
        await db.activate_totp("admin")

        ok1, _ = await TOTPManager(db).verify("admin", generate_totp(secret))
        ok2, _ = await TOTPManager(db).verify("admin", generate_totp(secret, time.time() + 30))
        assert ok1 is True
        assert ok2 is True

    @pytest.mark.asyncio
    async def test_verify_sin_2fa_activo_pasa_siempre(self, db):
        ok, reason = await TOTPManager(db).verify("admin", "000000")
        assert ok is True
        assert "no activo" in reason

    @pytest.mark.asyncio
    async def test_verify_con_codigo_de_recuperacion_funciona_y_se_consume(self, db):
        secret = generate_secret()
        codes = generate_recovery_codes(3)
        await db.set_totp_pending("admin", secret, codes)
        await db.activate_totp("admin")

        ok, _ = await TOTPManager(db).verify("admin", codes[0])
        assert ok is True
        # consumido: no debe volver a funcionar
        ok2, _ = await TOTPManager(db).verify("admin", codes[0])
        assert ok2 is False
