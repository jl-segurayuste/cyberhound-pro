"""
Sistema de licencias de CyberHound Pro.

Tipos de licencia:
  community  — gratuita, sin límite de hosts, sin SIEM, sin agentes
  starter    — hasta 5 hosts, sin agentes, con email
  professional — hasta 50 hosts, 3 agentes, SIEM, todas las funciones
  enterprise — ilimitado, agentes ilimitados, soporte prioritario

El token de licencia es un JWT firmado con la clave privada de CyberHound.
En modo community no se requiere token.

Verificación:
  1. Al arrancar el servidor se valida el token
  2. Cada scan comprueba si se excede el límite de hosts
  3. Los endpoints premium devuelven 402 si la licencia no lo permite
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cyberhound.core.logging import get_logger

logger = get_logger("licensing")

# Clave pública de verificación (en producción sería RSA/EC, aquí HMAC para simplicidad)
# La clave privada solo existe en el servidor de licencias de CyberHound
LICENSE_VERIFY_KEY = "cyberhound-pro-license-verification-key-v1"

LICENSE_PATH = Path.home() / ".cyberhound" / "license.json"


@dataclass
class LicenseLimits:
    max_hosts:       int   = 0      # 0 = ilimitado
    max_agents:      int   = 0      # 0 = ilimitado
    siem_enabled:    bool  = True
    agent_enabled:   bool  = True
    code_audit:      bool  = True
    intel_enabled:   bool  = True
    reports_enabled: bool  = True
    support_tier:    str   = "community"  # community | standard | priority


TIER_LIMITS: dict[str, LicenseLimits] = {
    "community": LicenseLimits(
        max_hosts=0, max_agents=0,
        siem_enabled=False, agent_enabled=False,
        intel_enabled=False, support_tier="community",
    ),
    "starter": LicenseLimits(
        max_hosts=5, max_agents=0,
        siem_enabled=True, agent_enabled=False,
        support_tier="standard",
    ),
    "professional": LicenseLimits(
        max_hosts=50, max_agents=3,
        siem_enabled=True, agent_enabled=True,
        support_tier="standard",
    ),
    "enterprise": LicenseLimits(
        max_hosts=0, max_agents=0,
        siem_enabled=True, agent_enabled=True,
        support_tier="priority",
    ),
}


@dataclass
class License:
    tier:        str              = "community"
    licensee:    str              = "Community User"
    valid_until: str | None   = None    # ISO date, None = perpetua
    issued_at:   str             = field(default_factory=lambda: datetime.now(UTC).isoformat())
    license_id:  str             = ""
    features:    list[str]       = field(default_factory=list)
    limits:      LicenseLimits   = field(default_factory=LicenseLimits)

    @property
    def is_expired(self) -> bool:
        if not self.valid_until:
            return False
        try:
            exp = datetime.fromisoformat(self.valid_until).replace(tzinfo=UTC)
            return datetime.now(UTC) > exp
        except (ValueError, TypeError):
            return True

    @property
    def days_remaining(self) -> int | None:
        if not self.valid_until:
            return None
        try:
            exp = datetime.fromisoformat(self.valid_until).replace(tzinfo=UTC)
            delta = exp - datetime.now(UTC)
            return max(0, delta.days)
        except (ValueError, TypeError):
            return 0

    def can_scan_host(self, current_host_count: int) -> bool:
        if self.limits.max_hosts == 0:
            return True
        return current_host_count < self.limits.max_hosts

    def to_dict(self) -> dict:
        return {
            "tier":          self.tier,
            "licensee":      self.licensee,
            "valid_until":   self.valid_until,
            "issued_at":     self.issued_at,
            "license_id":    self.license_id,
            "is_expired":    self.is_expired,
            "days_remaining":self.days_remaining,
            "limits": {
                "max_hosts":      self.limits.max_hosts,
                "max_agents":     self.limits.max_agents,
                "siem_enabled":   self.limits.siem_enabled,
                "agent_enabled":  self.limits.agent_enabled,
                "intel_enabled":  self.limits.intel_enabled,
                "support_tier":   self.limits.support_tier,
            },
        }


class LicenseManager:
    def __init__(self) -> None:
        self._license: License | None = None

    def load(self, path: Path = LICENSE_PATH) -> License:
        """Carga y valida la licencia. Devuelve community si no hay licencia."""
        if not path.exists():
            self._license = self._community_license()
            return self._license

        try:
            raw = json.loads(path.read_text())
            # Verificar firma HMAC
            raw.get("token", "")
            payload  = raw.get("payload", {})
            sig      = raw.get("signature", "")
            expected = self._sign(json.dumps(payload, sort_keys=True))
            if sig != expected:
                logger.warning("Licencia con firma inválida — usando community")
                self._license = self._community_license()
                return self._license

            tier = payload.get("tier", "community")
            limits = TIER_LIMITS.get(tier, TIER_LIMITS["community"])
            self._license = License(
                tier=tier,
                licensee=payload.get("licensee", ""),
                valid_until=payload.get("valid_until"),
                issued_at=payload.get("issued_at", ""),
                license_id=payload.get("license_id", ""),
                limits=limits,
            )
            if self._license.is_expired:
                logger.warning("Licencia expirada (%s) — usando community", self._license.valid_until)
                self._license = self._community_license()
            else:
                logger.info(
                    "Licencia '%s' cargada — %s (%s)",
                    tier, self._license.licensee,
                    f"expira en {self._license.days_remaining} días" if self._license.valid_until else "perpetua",
                )
        except Exception as e:
            logger.error("Error leyendo licencia: %s — usando community", e)
            self._license = self._community_license()

        return self._license

    def get(self) -> License:
        if self._license is None:
            return self.load()
        return self._license

    def activate(self, license_key: str, path: Path = LICENSE_PATH) -> tuple[bool, str]:
        """
        Activa una licencia a partir de una clave de activación.
        La clave es un JSON base64 firmado.
        """
        import base64
        try:
            decoded = base64.b64decode(license_key.encode()).decode()
            data    = json.loads(decoded)
        except Exception:
            return False, "Clave de licencia inválida (formato incorrecto)"

        payload = data.get("payload", {})
        sig     = data.get("signature", "")
        expected = self._sign(json.dumps(payload, sort_keys=True))

        if sig != expected:
            return False, "Clave de licencia inválida (firma incorrecta)"

        tier = payload.get("tier", "community")
        if tier not in TIER_LIMITS:
            return False, f"Tier desconocido: {tier}"

        # Verificar expiración del periodo de activación
        valid_until = payload.get("valid_until")
        if valid_until:
            try:
                exp = datetime.fromisoformat(valid_until).replace(tzinfo=UTC)
                if datetime.now(UTC) > exp:
                    return False, "Esta licencia ha expirado"
            except ValueError:
                return False, "Fecha de expiración inválida"

        # Guardar
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "payload":   payload,
            "signature": sig,
        }, indent=2))
        path.chmod(0o600)

        # Recargar
        self.load(path)
        logger.info("Licencia '%s' activada para '%s'", tier, payload.get("licensee",""))
        return True, f"Licencia {tier} activada correctamente para {payload.get('licensee','')}"

    def _community_license(self) -> License:
        return License(
            tier="community",
            licensee="Community",
            limits=TIER_LIMITS["community"],
        )

    @staticmethod
    def _sign(payload_str: str) -> str:
        import hmac as _hmac
        return _hmac.new(
            LICENSE_VERIFY_KEY.encode(),
            payload_str.encode(),
            hashlib.sha256,
        ).hexdigest()

    # ── Helpers de acceso rápido ──────────────────────────────────────────────

    def check_feature(self, feature: str) -> tuple[bool, str]:
        """
        Verifica si una feature está disponible.
        Devuelve (permitido, mensaje).
        """
        lic = self.get()
        checks = {
            "siem":    (lic.limits.siem_enabled,   "SIEM requiere licencia Starter o superior"),
            "agent":   (lic.limits.agent_enabled,  "Modo agente requiere licencia Professional"),
            "intel":   (lic.limits.intel_enabled,  "Threat Intel requiere licencia Starter o superior"),
            "reports": (lic.limits.reports_enabled, "Informes avanzados requieren licencia Starter"),
        }
        if feature in checks:
            allowed, msg = checks[feature]
            return allowed, ("" if allowed else msg)
        return True, ""


# Instancia global
license_manager = LicenseManager()
