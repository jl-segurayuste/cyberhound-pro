"""
Clientes de APIs de inteligencia externa.
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import aiohttp

from cyberhound.core.logging import get_logger
from cyberhound.core.models import ExternalIntel

if TYPE_CHECKING:
    pass

logger = get_logger("intel")


class IntelScanner:
    def __init__(self, api_keys) -> None:
        self.keys = api_keys

    async def scan(self, target: str, modules: list[str]) -> list[ExternalIntel]:
        results: list[ExternalIntel] = []
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
            tasks = {}
            if "shodan" in modules and getattr(self.keys, "shodan", None):
                tasks["shodan"] = self._shodan(session, target)
            if "virustotal" in modules and getattr(self.keys, "virustotal", None):
                tasks["virustotal"] = self._virustotal(session, target)
            if "abuseipdb" in modules and getattr(self.keys, "abuseipdb", None):
                tasks["abuseipdb"] = self._abuseipdb(session, target)
            if "greynoise" in modules and getattr(self.keys, "greynoise", None):
                tasks["greynoise"] = self._greynoise(session, target)
            if "hibp" in modules and "@" in target and getattr(self.keys, "hibp", None):
                tasks["hibp"] = self._hibp(session, target)

            gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for source, res in zip(tasks.keys(), gathered, strict=False):
                if isinstance(res, Exception):
                    logger.warning("Intel %s error: %s", source, res)
                elif res is not None:
                    results.append(ExternalIntel(source=source, indicator=target, data=res))
        return results

    async def _shodan(self, s, ip):
        async with s.get(f"https://api.shodan.io/shodan/host/{ip}?key={self.keys.shodan}") as r:
            return await r.json() if r.status == 200 else None

    async def _virustotal(self, s, ip):
        async with s.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": self.keys.virustotal},
        ) as r:
            return await r.json() if r.status == 200 else None

    async def _abuseipdb(self, s, ip):
        async with s.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": self.keys.abuseipdb},
            params={"ipAddress": ip, "maxAgeInDays": 90},
        ) as r:
            return await r.json() if r.status == 200 else None

    async def _greynoise(self, s, ip):
        async with s.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": self.keys.greynoise},
        ) as r:
            return await r.json() if r.status == 200 else None

    async def _hibp(self, s, email):
        headers = {"hibp-api-key": self.keys.hibp, "user-agent": "cyberhound"}
        async with s.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=headers,
        ) as r:
            if r.status == 200:
                return await r.json()
            if r.status == 404:
                return {"breaches": []}
            return None
