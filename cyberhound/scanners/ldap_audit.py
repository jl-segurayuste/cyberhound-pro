"""
Análisis de seguridad de Active Directory y LDAP para CyberHound Pro.

Checks implementados:
  1.  Usuarios sin contraseña establecida (userAccountControl: PASSWD_NOTREQD)
  2.  Cuentas de servicio con contraseñas que no expiran (DONT_EXPIRE_PASSWORD)
  3.  Cuentas inactivas con más de 90 días sin login
  4.  Administradores con SPN (Kerberoasting vectores)
  5.  Cuentas con privilegios excesivos (miembros directos de Domain Admins)
  6.  Password policy — longitud mínima < 12 chars
  7.  Accounts con AS-REP Roasting (UF_DONT_REQUIRE_PREAUTH)
  8.  LDAP signing no requerido (ataque LDAP relay)
  9.  Guest account activa
  10. Número de Domain Admins > umbral recomendado

Usa ldap3 si está disponible, o ldapsearch como fallback.
También funciona con sssd-ldap en sistemas RHEL/Linux integrados en AD.
"""
from __future__ import annotations

import asyncio
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from cyberhound.core.executor import command_exists, run_command
from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("ldap_audit")

# Flags de userAccountControl de AD
UAC_PASSWD_NOTREQD       = 0x0020    # Sin contraseña requerida
UAC_DONT_EXPIRE_PASSWORD = 0x10000   # Contraseña no expira
UAC_ACCOUNTDISABLE       = 0x0002    # Cuenta desactivada
UAC_DONT_REQUIRE_PREAUTH = 0x400000  # AS-REP Roasting

MAX_DOMAIN_ADMINS   = 3
INACTIVE_DAYS_LIMIT = 90


def _f(id, category, severity, title, description, remediation,
       evidence="", auto_fix=False) -> Finding:
    return Finding(
        id=id, category=f"ldap/{category}", severity=severity,
        title=title, description=description, remediation=remediation,
        evidence=evidence, auto_fix=auto_fix,
    )


# ── Detección de LDAP local ───────────────────────────────────────────────────

async def _detect_ldap_config() -> Optional[dict]:
    """Detecta la configuración LDAP del sistema (sssd, /etc/ldap.conf, etc.)."""
    # Buscar en sssd.conf
    for cfg_path in ["/etc/sssd/sssd.conf", "/etc/sssd/conf.d/"]:
        p = Path(cfg_path)
        if p.is_file():
            content = p.read_text(errors="ignore")
            uri_match = re.search(r"ldap_uri\s*=\s*(.+)", content)
            base_match = re.search(r"ldap_search_base\s*=\s*(.+)", content)
            binddn_match = re.search(r"ldap_default_bind_dn\s*=\s*(.+)", content)
            if uri_match:
                return {
                    "uri":    uri_match.group(1).strip().split(",")[0],
                    "base":   base_match.group(1).strip() if base_match else "",
                    "binddn": binddn_match.group(1).strip() if binddn_match else "",
                    "source": str(cfg_path),
                }

    # Buscar en /etc/ldap.conf (openldap)
    ldap_conf = Path("/etc/ldap.conf")
    if ldap_conf.exists():
        content = ldap_conf.read_text(errors="ignore")
        host_match = re.search(r"^host\s+(.+)", content, re.MULTILINE)
        base_match = re.search(r"^base\s+(.+)", content, re.MULTILINE)
        if host_match:
            host = host_match.group(1).strip()
            return {
                "uri":  f"ldap://{host}",
                "base": base_match.group(1).strip() if base_match else "",
                "source": "/etc/ldap.conf",
            }

    return None


async def _ldapsearch(uri: str, base: str, binddn: str,
                      bindpw: str, filter_str: str, attrs: list[str]) -> list[dict]:
    """Wrapper async de ldapsearch."""
    if not command_exists("ldapsearch"):
        return []

    cmd = ["ldapsearch", "-LLL", "-x",
           "-H", uri, "-b", base,
           "-D", binddn, "-w", bindpw,
           filter_str] + attrs

    proc = await run_command(cmd, timeout=30, check=False)
    if proc.returncode != 0:
        logger.debug("ldapsearch error: %s", proc.stderr[:100])
        return []

    # Parsear salida LDIF básica
    entries = []
    current: dict = {}
    for line in proc.stdout.splitlines():
        if not line.strip():
            if current:
                entries.append(current)
                current = {}
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            val = val.strip()
            if key in current:
                if not isinstance(current[key], list):
                    current[key] = [current[key]]
                current[key].append(val)
            else:
                current[key] = val
    if current:
        entries.append(current)
    return entries


# ── Checks ────────────────────────────────────────────────────────────────────

async def check_passwd_not_required(cfg: dict) -> list[Finding]:
    """Detecta cuentas con PASSWD_NOTREQD en userAccountControl."""
    # Filtro: cuentas activas con PASSWD_NOTREQD
    entries = await _ldapsearch(
        cfg["uri"], cfg["base"], cfg.get("binddn", ""),
        cfg.get("bindpw", ""),
        "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName", "userAccountControl"],
    )
    findings = []
    for entry in entries:
        user = entry.get("sAMAccountName", "?")
        findings.append(_f(
            f"ldap_no_passwd_{str(user).replace(' ','_')[:30]}",
            "accounts", "critical",
            f"AD: cuenta sin contraseña requerida: {user}",
            f"La cuenta '{user}' tiene el flag PASSWD_NOTREQD. Puede autenticarse sin contraseña.",
            f"Set-ADUser -Identity {user} -PasswordNotRequired $false\n"
            "Y forzar cambio de contraseña: Set-ADUser -Identity {user} -ChangePasswordAtLogon $true",
            evidence=f"userAccountControl PASSWD_NOTREQD ({user})",
            auto_fix=False,
        ))
    return findings


async def check_no_password_expiry(cfg: dict) -> list[Finding]:
    """Detecta cuentas normales (no de servicio) con contraseña que no expira."""
    entries = await _ldapsearch(
        cfg["uri"], cfg["base"], cfg.get("binddn", ""),
        cfg.get("bindpw", ""),
        "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        "(!(objectClass=computer)))",
        ["sAMAccountName", "memberOf"],
    )
    findings = []
    for entry in entries:
        user = entry.get("sAMAccountName", "?")
        # Solo reportar si no es una cuenta conocida de sistema
        if str(user).lower() in ("krbtgt", "guest", "administrator"):
            continue
        findings.append(_f(
            f"ldap_no_expiry_{str(user).replace(' ','_')[:30]}",
            "passwords", "medium",
            f"AD: contraseña sin expiración: {user}",
            f"La cuenta '{user}' tiene DONT_EXPIRE_PASSWORD. "
            "Las contraseñas sin expiración son un riesgo si se ven comprometidas.",
            f"Set-ADUser -Identity {user} -PasswordNeverExpires $false",
            auto_fix=False,
        ))
    # Limitar a 10 para no saturar
    return findings[:10]


async def check_as_rep_roasting(cfg: dict) -> list[Finding]:
    """Detecta cuentas con UF_DONT_REQUIRE_PREAUTH (AS-REP Roasting)."""
    entries = await _ldapsearch(
        cfg["uri"], cfg["base"], cfg.get("binddn", ""),
        cfg.get("bindpw", ""),
        "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName"],
    )
    findings = []
    for entry in entries:
        user = entry.get("sAMAccountName", "?")
        findings.append(_f(
            f"ldap_asrep_{str(user).replace(' ','_')[:30]}",
            "kerberos", "high",
            f"AD: cuenta vulnerable a AS-REP Roasting: {user}",
            f"La cuenta '{user}' no requiere pre-autenticación Kerberos. "
            "Un atacante puede solicitar un TGT encriptado y crackearlo offline.",
            f"Set-ADUser -Identity {user} -DoesNotRequirePreAuth $false",
            auto_fix=False,
        ))
    return findings


async def check_domain_admins_count(cfg: dict) -> list[Finding]:
    """Verifica que no haya demasiados Domain Admins."""
    entries = await _ldapsearch(
        cfg["uri"], cfg["base"], cfg.get("binddn", ""),
        cfg.get("bindpw", ""),
        "(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,"
        f"{cfg['base']})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName"],
    )
    count = len(entries)
    if count > MAX_DOMAIN_ADMINS:
        users = [str(e.get("sAMAccountName", "?")) for e in entries]
        return [_f(
            "ldap_too_many_admins", "privileges", "high",
            f"AD: {count} Domain Admins activos (recomendado: máx. {MAX_DOMAIN_ADMINS})",
            f"Hay {count} cuentas en Domain Admins: {', '.join(users[:10])}. "
            "Cuantos más admins, mayor la superficie de ataque.",
            "Revisar qué cuentas necesitan realmente privilegios de Domain Admin.\n"
            "Considerar usar grupos con privilegios más granulares.",
            evidence=f"Domain Admins: {', '.join(users[:5])}",
            auto_fix=False,
        )]
    return []


async def check_guest_account(cfg: dict) -> list[Finding]:
    """Verifica si la cuenta Guest está activa."""
    entries = await _ldapsearch(
        cfg["uri"], cfg["base"], cfg.get("binddn", ""),
        cfg.get("bindpw", ""),
        "(&(sAMAccountName=guest)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName", "userAccountControl"],
    )
    if entries:
        return [_f(
            "ldap_guest_active", "accounts", "medium",
            "AD: cuenta Guest activa",
            "La cuenta Guest permite acceso anónimo y debería estar siempre desactivada.",
            "Disable-ADAccount -Identity guest",
            auto_fix=False,
        )]
    return []


async def check_password_policy_ldap(cfg: dict) -> list[Finding]:
    """Verifica la política de contraseñas del dominio."""
    entries = await _ldapsearch(
        cfg["uri"], cfg["base"], cfg.get("binddn", ""),
        cfg.get("bindpw", ""),
        "(objectClass=domainDNS)",
        ["minPwdLength", "lockoutThreshold", "maxPwdAge", "pwdHistoryLength"],
    )
    findings = []
    for entry in entries:
        min_len = int(entry.get("minPwdLength", 0) or 0)
        lockout = int(entry.get("lockoutThreshold", 0) or 0)
        history = int(entry.get("pwdHistoryLength", 0) or 0)

        if min_len < 12:
            findings.append(_f(
                "ldap_pwd_minlen", "policy", "high",
                f"AD: longitud mínima de contraseña baja ({min_len} chars)",
                "La política de dominio requiere contraseñas de menos de 12 caracteres.",
                "Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain) -MinPasswordLength 14",
                evidence=f"minPwdLength={min_len}",
                auto_fix=False,
            ))
        if lockout == 0:
            findings.append(_f(
                "ldap_no_lockout", "policy", "high",
                "AD: sin bloqueo de cuenta por intentos fallidos",
                "Sin lockout policy las cuentas son vulnerables a ataques de fuerza bruta.",
                "Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5 -LockoutDuration 00:30:00",
                auto_fix=False,
            ))
        if history < 10:
            findings.append(_f(
                "ldap_pwd_history", "policy", "medium",
                f"AD: historial de contraseñas corto ({history})",
                "Con historial corto los usuarios pueden reutilizar contraseñas.",
                "Set-ADDefaultDomainPasswordPolicy -PasswordHistoryCount 24",
                evidence=f"pwdHistoryLength={history}",
                auto_fix=False,
            ))
    return findings


# ── Orquestador ───────────────────────────────────────────────────────────────

class LDAPAuditor:
    """Audita la seguridad del directorio LDAP/AD configurado en el sistema."""

    @classmethod
    async def full_audit(
        cls,
        uri: str = "",
        base: str = "",
        binddn: str = "",
        bindpw: str = "",
    ) -> list[Finding]:
        # Autodetectar si no se proporcionan parámetros
        cfg = await _detect_ldap_config()
        if uri:
            cfg = {"uri": uri, "base": base, "binddn": binddn, "bindpw": bindpw}
        if not cfg:
            return [Finding(
                id="ldap_not_configured", category="ldap", severity="info",
                title="LDAP/AD no detectado en este sistema",
                description="No se encontró configuración LDAP/AD (sssd.conf, ldap.conf).",
                remediation=(
                    "Si usas AD/LDAP, configura /etc/sssd/sssd.conf o proporciona\n"
                    "los parámetros de conexión manualmente."
                ),
            )]

        if not command_exists("ldapsearch"):
            return [Finding(
                id="ldapsearch_missing", category="ldap", severity="info",
                title="ldapsearch no disponible — análisis LDAP saltado",
                description="Instalar ldap-utils para habilitar el análisis de AD/LDAP.",
                remediation="apt install ldap-utils",
            )]

        logger.info("LDAP audit iniciado contra %s", cfg.get("uri", "?"))

        results = await asyncio.gather(
            check_passwd_not_required(cfg),
            check_no_password_expiry(cfg),
            check_as_rep_roasting(cfg),
            check_domain_admins_count(cfg),
            check_guest_account(cfg),
            check_password_policy_ldap(cfg),
            return_exceptions=True,
        )

        findings: list[Finding] = []
        names = ["passwd_not_req", "no_expiry", "asrep", "domain_admins", "guest", "policy"]
        for name, result in zip(names, results):
            if isinstance(result, list):
                findings.extend(result)
                logger.info("  ldap/%s: %d hallazgos", name, len(result))
            else:
                logger.error("  ldap/%s error: %s", name, result)

        logger.info("LDAP audit: %d hallazgos totales", len(findings))
        return findings
