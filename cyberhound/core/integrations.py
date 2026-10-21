"""
Integraciones (notificaciones, SIEM, ticketing) de la plataforma o de cada organización.

La plataforma usa las secciones de config.yaml. En multi-tenant cada organización guarda las
suyas en tenants.json (0600) y avisa a su propio correo, SIEM o Jira; antes todas compartían
las de la plataforma, así que los hallazgos de un cliente acababan en el SIEM de otro.

Los gestores se construyen a partir del dataclass de ajustes copiando los campos con el mismo
nombre: antes la recarga en caliente copiaba campos a mano y se dejaba unos cuantos (servidor
SMTP, usuario y contraseña de la API de Wazuh, índice y credenciales de Elasticsearch, índice de
Splunk) que no se aplicaban hasta reiniciar.
"""
from __future__ import annotations

import dataclasses
import ipaddress

from cyberhound.core.config import NotificationSettings, SIEMSettings, TicketingSettings
from cyberhound.core.notifications import NotificationConfig, NotificationManager
from cyberhound.core.scope import Scope, _resolve, host_of
from cyberhound.core.siem import SIEMConfig, SIEMIntegration
from cyberhound.core.ticketing import TicketingConfig, TicketingIntegration

KINDS = ("notifications", "siem", "ticketing")
SETTINGS = {"notifications": NotificationSettings, "siem": SIEMSettings, "ticketing": TicketingSettings}

# Campos que nunca se devuelven por la API y que no se pisan con "" al guardar
SECRETS = {
    "notifications": ("smtp_password",),
    "siem": ("wazuh_api_pass", "elk_pass", "elk_api_key", "splunk_hec_token"),
    "ticketing": ("jira_api_token", "servicenow_password"),
}

# Destinos de salida de cada canal: (campo que lo activa, campos con host o URL)
OUTBOUND = {
    "notifications": (("email_enabled", ("smtp_host",)), ("webhook_enabled", ("webhook_url",))),
    "siem": (("wazuh_enabled", ("wazuh_host", "wazuh_api_url")), ("elk_enabled", ("elk_url",)),
             ("splunk_enabled", ("splunk_hec_url",))),
    "ticketing": (("jira_enabled", ("jira_url",)), ("servicenow_enabled", ("servicenow_instance_url",))),
}

_TYPES = {"notifications": (NotificationConfig, NotificationManager), "siem": (SIEMConfig, SIEMIntegration),
          "ticketing": (TicketingConfig, TicketingIntegration)}


def _copy_into(cls, settings):
    names = {f.name for f in dataclasses.fields(cls)}
    return cls(**{k: v for k, v in dataclasses.asdict(settings).items() if k in names})


def build(kind: str, settings, db=None):
    cfg_cls, mgr_cls = _TYPES[kind]
    cfg = _copy_into(cfg_cls, settings)
    return mgr_cls(cfg, db=db) if kind == "notifications" else mgr_cls(cfg)


def settings_from_dict(kind: str, data: dict | None):
    cls = SETTINGS[kind]
    names = {f.name for f in dataclasses.fields(cls)}
    return cls(**{k: v for k, v in (data or {}).items() if k in names})


def public_view(kind: str, settings) -> dict:
    """Lo que devuelve GET /api/config/<kind>: todo menos los secretos (se indica si hay uno guardado)."""
    d = dataclasses.asdict(settings)
    out = {k: v for k, v in d.items() if k not in SECRETS[kind]}
    out["secrets_set"] = sorted(k for k in SECRETS[kind] if d.get(k))
    return out


def apply_update(kind: str, settings, body: dict) -> None:
    """Copia los campos conocidos del cuerpo; un secreto vacío no borra el guardado. ValueError si un tipo no cuadra."""
    for f in dataclasses.fields(settings):
        if f.name not in body:
            continue
        value, current = body[f.name], getattr(settings, f.name)
        if f.name in SECRETS[kind] and not value:
            continue
        if isinstance(current, bool):
            if not isinstance(value, bool):
                raise ValueError(f"{f.name} debe ser true/false")
        elif isinstance(current, int):
            try:
                value = int(value)
            except (TypeError, ValueError):
                raise ValueError(f"{f.name} debe ser un número") from None
        elif isinstance(current, list):
            if isinstance(value, str):
                value = [v.strip() for v in value.replace(";", ",").split(",") if v.strip()]
            if not isinstance(value, list):
                raise ValueError(f"{f.name} debe ser una lista")
            value = [str(v)[:200] for v in value][:20]
        else:
            value = str(value)[:2048]
        setattr(settings, f.name, value)


async def outbound_problem(kind: str, settings, allowed: list[str]) -> str | None:
    """Organizaciones: un destino activo solo puede ser público o estar dentro de su ámbito.

    Sin esto un tenant apuntaba el webhook o el "SIEM" a http://127.0.0.1:… o a la LAN del
    servidor y CyberHound hacía las peticiones por él (SSRF)."""
    scope = Scope(allowed or [])
    for enabled, fields in OUTBOUND[kind]:
        if not getattr(settings, enabled):
            continue
        for name in fields:
            value = str(getattr(settings, name) or "").strip()
            if not value:
                continue
            host = host_of(value)
            if not host:
                return f"{name}: destino no válido"
            try:
                addrs = [ipaddress.ip_address(host)]
            except ValueError:
                addrs = await _resolve(host)
                if not addrs:
                    return f"{name}: {host} no resuelve"
            for a in addrs:
                if not a.is_global and not scope._ip_allowed(a):
                    return (f"{name}: {host} es una dirección interna ({a}) fuera de las redes "
                            "permitidas a la organización")
    return None


class GuardedIntegration:
    """Envoltorio para la integración de una organización: antes de cada envío vuelve a resolver
    los destinos (un nombre puede cambiar de IP después de guardarlo) y, si alguno ya no es
    válido, no envía nada."""

    _SENDERS = {"send", "send_finding", "send_scan_summary", "create_ticket", "test"}

    def __init__(self, kind: str, inner, settings, allowed: list[str], logger=None) -> None:
        self._kind, self._inner, self._settings, self._allowed, self._logger = kind, inner, settings, allowed, logger

    def __getattr__(self, name):
        attr = getattr(self._inner, name)
        if name not in self._SENDERS or not callable(attr):
            return attr

        async def guarded(*args, **kwargs):
            if problem := await outbound_problem(self._kind, self._settings, self._allowed):
                if self._logger:
                    self._logger.warning("Integración %s bloqueada: %s", self._kind, problem)
                if name == "test":
                    return {"error": problem}
                return [] if name == "create_ticket" else None
            return await attr(*args, **kwargs)
        return guarded
