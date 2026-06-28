"""
Software Bill of Materials (SBOM) para CyberHound Pro.

Genera un inventario completo del software instalado en el sistema:
  - Paquetes del sistema (apt/dpkg, rpm/yum, apk)
  - Paquetes Python (pip)
  - Paquetes Node.js (npm)
  - Imágenes Docker
  - Binarios con versión detectada

Formatos de salida: JSON (interno), CycloneDX (estándar SBOM), SPDX básico.

El SBOM se puede comparar entre scans para detectar cambios en el software
instalado — útil para auditorías de cumplimiento normativo (ENS, ISO 27001).
"""
from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cyberhound.core.executor import command_exists, run_command
from cyberhound.core.logging import get_logger

logger = get_logger("sbom")


# ── Colectores por gestor de paquetes ────────────────────────────────────────

async def collect_dpkg() -> list[dict]:
    """Paquetes Debian/Ubuntu."""
    if not command_exists("dpkg-query"):
        return []
    proc = await run_command(
        ["dpkg-query", "-W", "-f=${Package}|${Version}|${Architecture}|${Status}\n"],
        timeout=30, check=False,
    )
    packages = []
    for line in proc.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < 4:
            continue
        name, version, arch, status = parts[0], parts[1], parts[2], parts[3]
        if "install ok installed" not in status:
            continue
        packages.append({
            "name":      name.strip(),
            "version":   version.strip(),
            "arch":      arch.strip(),
            "type":      "deb",
            "manager":   "dpkg",
        })
    logger.info("SBOM dpkg: %d paquetes", len(packages))
    return packages


async def collect_rpm() -> list[dict]:
    """Paquetes RHEL/CentOS/Fedora."""
    if not command_exists("rpm"):
        return []
    proc = await run_command(
        ["rpm", "-qa", "--queryformat", "%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}\n"],
        timeout=30, check=False,
    )
    packages = []
    for line in proc.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < 3:
            continue
        packages.append({
            "name":    parts[0].strip(),
            "version": parts[1].strip(),
            "arch":    parts[2].strip(),
            "type":    "rpm",
            "manager": "rpm",
        })
    logger.info("SBOM rpm: %d paquetes", len(packages))
    return packages


async def collect_pip(venvs: Optional[list[str]] = None) -> list[dict]:
    """Paquetes Python pip."""
    pips = ["pip3", "pip"]
    # Añadir venvs si se especifican
    if venvs:
        for venv in venvs:
            pip_path = Path(venv) / "bin" / "pip"
            if pip_path.exists():
                pips.insert(0, str(pip_path))

    for pip_cmd in pips:
        if not command_exists(pip_cmd):
            continue
        proc = await run_command(
            [pip_cmd, "list", "--format=json"],
            timeout=30, check=False,
        )
        if proc.returncode != 0:
            continue
        try:
            raw = json.loads(proc.stdout)
            packages = [
                {"name": p["name"], "version": p["version"], "type": "python", "manager": "pip"}
                for p in raw
            ]
            logger.info("SBOM pip: %d paquetes", len(packages))
            return packages
        except (json.JSONDecodeError, KeyError):
            continue
    return []


async def collect_npm_global() -> list[dict]:
    """Paquetes Node.js npm globales."""
    if not command_exists("npm"):
        return []
    proc = await run_command(
        ["npm", "list", "-g", "--depth=0", "--json"],
        timeout=30, check=False,
    )
    try:
        data = json.loads(proc.stdout)
        deps = data.get("dependencies", {})
        packages = [
            {"name": name, "version": info.get("version", "?"), "type": "nodejs", "manager": "npm"}
            for name, info in deps.items()
        ]
        logger.info("SBOM npm-global: %d paquetes", len(packages))
        return packages
    except (json.JSONDecodeError, AttributeError):
        return []


async def collect_docker_images() -> list[dict]:
    """Imágenes Docker instaladas."""
    if not command_exists("docker"):
        return []
    proc = await run_command(
        ["docker", "images", "--format",
         '{"name":"{{.Repository}}","tag":"{{.Tag}}","id":"{{.ID}}","size":"{{.Size}}","created":"{{.CreatedAt}}"}'],
        timeout=15, check=False,
    )
    images = []
    for line in proc.stdout.splitlines():
        try:
            data = json.loads(line)
            if "<none>" in (data.get("name","") + data.get("tag","")):
                continue
            images.append({
                "name":    data["name"],
                "version": data["tag"],
                "type":    "docker-image",
                "manager": "docker",
                "id":      data.get("id", ""),
                "size":    data.get("size", ""),
                "created": data.get("created", ""),
            })
        except (json.JSONDecodeError, KeyError):
            continue
    logger.info("SBOM docker: %d imágenes", len(images))
    return images


async def collect_kernel() -> list[dict]:
    """Versión del kernel."""
    proc = await run_command(["uname", "-r"], timeout=5, check=False)
    if proc.returncode == 0:
        return [{"name": "linux-kernel", "version": proc.stdout.strip(), "type": "kernel", "manager": "system"}]
    return []


# ── Generador de SBOM ─────────────────────────────────────────────────────────

class SBOMGenerator:
    @staticmethod
    async def generate(
        include: Optional[list[str]] = None,
        pip_venvs: Optional[list[str]] = None,
    ) -> "SBOM":
        """
        Genera el SBOM completo del sistema.
        include: lista de gestores a incluir (None = todos)
        """
        collectors = {
            "dpkg":   lambda: collect_dpkg(),
            "rpm":    lambda: collect_rpm(),
            "pip":    lambda: collect_pip(pip_venvs),
            "npm":    lambda: collect_npm_global(),
            "docker": lambda: collect_docker_images(),
            "kernel": lambda: collect_kernel(),
        }
        if include:
            collectors = {k: v for k, v in collectors.items() if k in include}

        results = await asyncio.gather(
            *[fn() for fn in collectors.values()],
            return_exceptions=True,
        )

        components: list[dict] = []
        for name, result in zip(collectors.keys(), results):
            if isinstance(result, list):
                components.extend(result)
            else:
                logger.error("SBOM collector %s error: %s", name, result)

        return SBOM(components=components)


class SBOM:
    def __init__(self, components: list[dict]) -> None:
        self.components  = components
        self.generated_at = datetime.now(timezone.utc).isoformat()
        self.total        = len(components)

    def to_dict(self) -> dict:
        """Formato interno JSON."""
        return {
            "generated_at": self.generated_at,
            "total":         self.total,
            "components":    self.components,
            "summary": {
                mgr: sum(1 for c in self.components if c.get("manager") == mgr)
                for mgr in {c.get("manager","?") for c in self.components}
            },
        }

    def to_cyclonedx(self) -> dict:
        """
        Formato CycloneDX 1.4 (estándar OWASP/NIST para SBOMs).
        Compatible con herramientas como Dependency-Track.
        """
        return {
            "bomFormat":   "CycloneDX",
            "specVersion": "1.4",
            "version":     1,
            "metadata": {
                "timestamp": self.generated_at,
                "tools": [{"vendor": "CyberHound", "name": "CyberHound Pro", "version": "6.1.0"}],
            },
            "components": [
                {
                    "type":    "library",
                    "name":    c["name"],
                    "version": c.get("version", ""),
                    "purl":    self._make_purl(c),
                    "properties": [
                        {"name": "cyberhound:manager", "value": c.get("manager", "")},
                        {"name": "cyberhound:arch",    "value": c.get("arch", "")},
                    ],
                }
                for c in self.components
            ],
        }

    def to_spdx_basic(self) -> str:
        """Formato SPDX 2.3 básico (texto plano)."""
        lines = [
            "SPDXVersion: SPDX-2.3",
            "DataLicense: CC0-1.0",
            f"SPDXID: SPDXRef-DOCUMENT",
            f"DocumentName: CyberHound-SBOM",
            f"DocumentNamespace: https://cyberhound.local/sbom/{self.generated_at}",
            f"Creator: Tool: CyberHound Pro 6.1.0",
            f"Created: {self.generated_at}",
            "",
        ]
        for i, c in enumerate(self.components):
            lines += [
                f"PackageName: {c['name']}",
                f"SPDXID: SPDXRef-Package-{i}",
                f"PackageVersion: {c.get('version','')}",
                f"PackageDownloadLocation: NOASSERTION",
                f"FilesAnalyzed: false",
                "",
            ]
        return "\n".join(lines)

    @staticmethod
    def _make_purl(component: dict) -> str:
        """Genera un Package URL (purl) estándar."""
        pkg_type = {
            "deb":          "deb",
            "rpm":          "rpm",
            "python":       "pypi",
            "nodejs":       "npm",
            "docker-image": "docker",
            "kernel":       "generic",
        }.get(component.get("type",""), "generic")
        name    = component["name"]
        version = component.get("version", "")
        return f"pkg:{pkg_type}/{name}@{version}"

    def diff(self, other: "SBOM") -> dict:
        """
        Compara dos SBOMs y devuelve los cambios:
        paquetes añadidos, eliminados y actualizados.
        """
        self_map  = {c["name"]: c for c in self.components}
        other_map = {c["name"]: c for c in other.components}

        added   = [c for name, c in other_map.items() if name not in self_map]
        removed = [c for name, c in self_map.items()  if name not in other_map]
        updated = [
            {"name": name, "from": self_map[name]["version"], "to": other_map[name]["version"]}
            for name in self_map
            if name in other_map and self_map[name].get("version") != other_map[name].get("version")
        ]
        return {
            "added":   added,
            "removed": removed,
            "updated": updated,
            "summary": {
                "added":   len(added),
                "removed": len(removed),
                "updated": len(updated),
            },
        }
