"""
Ámbito de análisis de una organización: qué redes y dominios puede analizar.

En multi-tenant todas las organizaciones comparten el servidor y su red. Sin esto, un
tenant podía lanzar un escaneo de red, SSH, web o LDAP contra la LAN del propio servidor o
contra las redes de otro cliente. El superadmin fija la lista en Organizaciones; una lista
vacía significa que la organización no puede lanzar análisis activos.

Entradas: redes CIDR o IPs ("10.10.0.0/24", "203.0.113.7") y dominios ("ejemplo-demo.es",
que incluye sus subdominios; "*.ejemplo-demo.es" equivale). Un nombre permitido que resuelve
a una IP privada solo vale si esa IP está en una red permitida: así un dominio propio no sirve
para llegar a la red interna del servidor.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from urllib.parse import urlsplit

MAX_ENTRIES = 100
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_NET = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_scope(entries) -> list[str]:
    """Normaliza la lista que guarda el superadmin; ValueError con la entrada que no vale."""
    if isinstance(entries, str):
        entries = re.split(r"[\s,]+", entries)
    if not isinstance(entries, list):
        raise ValueError("allowed_targets debe ser una lista")
    out: list[str] = []
    for raw in entries:
        e = str(raw).strip().lower().removeprefix("*.")
        if not e:
            continue
        try:
            net = ipaddress.ip_network(e, strict=False)
        except ValueError:
            if not _DOMAIN_RE.match(e):
                raise ValueError(f"No es una red ni un dominio: {raw}") from None
            out.append(e)
            continue
        if net.version == 4 and net.prefixlen < 16:
            raise ValueError(f"Red demasiado grande: {raw} (mínimo /16)")
        if net.is_loopback or net.overlaps(ipaddress.ip_network("169.254.0.0/16")):
            raise ValueError(f"No se permite el loopback ni link-local: {raw}")
        out.append(str(net))
    if len(out) > MAX_ENTRIES:
        raise ValueError(f"Máximo {MAX_ENTRIES} entradas")
    return list(dict.fromkeys(out))


def host_of(target: str) -> str:
    """Host de una URL, host:puerto, usuario@host o ldap://host:389."""
    t = target.strip()
    if "://" not in t:
        t = "//" + t
    try:
        host = urlsplit(t).hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".")


class Scope:
    def __init__(self, entries: list[str]) -> None:
        self.networks: list[_NET] = []
        self.domains: list[str] = []
        for e in entries:
            try:
                self.networks.append(ipaddress.ip_network(e, strict=False))
            except ValueError:
                self.domains.append(e)

    def _ip_allowed(self, ip) -> bool:
        return any(ip.version == n.version and ip in n for n in self.networks)

    def _domain_allowed(self, host: str) -> bool:
        return any(host == d or host.endswith("." + d) for d in self.domains)

    async def check(self, target: str) -> str | None:
        """None si el objetivo está dentro del ámbito; si no, el motivo."""
        t = target.strip()
        if "/" in t and "://" not in t:          # red CIDR (escaneo de red)
            try:
                net = ipaddress.ip_network(t, strict=False)
            except ValueError:
                net = None
            if net is not None:
                if any(net.version == n.version and net.subnet_of(n) for n in self.networks):
                    return None
                return f"{t} está fuera de las redes permitidas a esta organización"
        host = host_of(t)
        if not host:
            return f"Objetivo no válido: {t[:60]}"
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None:
            return None if self._ip_allowed(ip) else f"{host} está fuera de las redes permitidas"
        if not self._domain_allowed(host):
            return f"{host} no está entre los dominios permitidos a esta organización"
        for addr in await _resolve(host):
            if not addr.is_global and not self._ip_allowed(addr):
                return f"{host} resuelve a {addr}, una dirección interna fuera de las redes permitidas"
        return None

    async def check_all(self, targets) -> str | None:
        for t in targets:
            if err := await self.check(str(t)):
                return err
        return None


async def _resolve(host: str) -> list:
    """IPs del nombre; si no resuelve, el análisis fallará por sí solo y no hay nada que comprobar."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout=5)
    except (OSError, TimeoutError):
        return []
    out = []
    for info in infos:
        try:
            out.append(ipaddress.ip_address(info[4][0].split("%")[0]))
        except ValueError:
            continue
    return out


def ws_targets(msg: dict) -> list[str] | None:
    """Objetivos de un mensaje WS ya validado; None para tareas que no tocan la red de nadie."""
    task = msg["task"]
    if task == "network":
        return [n for n in msg.get("networks", "").split(",") if n]
    if task == "ssh":
        return msg.get("hosts", "").split()
    if task in ("web_exposure", "api_security", "web_headers", "nuclei"):
        return msg.get("urls", [])
    if task in ("subdomain_enum", "dns"):
        return msg.get("domains", [])
    if task == "tls":
        return msg.get("targets", [])
    return None
