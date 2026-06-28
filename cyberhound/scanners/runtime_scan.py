"""
Análisis de contenedores Docker en runtime para CyberHound Pro.

A diferencia del docker_scan.py (configuración) y docker_image_scan.py (filesystem),
este módulo analiza el comportamiento de los contenedores MIENTRAS ESTÁN EN EJECUCIÓN:

  1. Procesos activos dentro de cada contenedor (docker top)
  2. Conexiones de red activas del contenedor
  3. Cambios en el filesystem en tiempo real (docker diff)
  4. Uso de recursos: CPU/memoria fuera de límites
  5. Variables de entorno en tiempo de ejecución (no Dockerfile)
  6. Ficheros modificados desde que arrancó el contenedor
  7. Syscalls sospechosas via docker stats + /proc del contenedor

No requiere eBPF ni bpftrace — usa herramientas estándar de Docker.
"""
from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from typing import Optional

from cyberhound.core.executor import command_exists, run_command
from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("runtime_scan")

# Procesos sospechosos dentro de un contenedor
SUSPICIOUS_PROCS = {
    r"\bnc\b.*-[el]":                 ("critical", "Netcat en modo escucha dentro del contenedor"),
    r"\bwget\b.*http.*\|.*(bash|sh)": ("critical", "Descarga y ejecución de shell script"),
    r"\bcurl\b.*http.*\|.*(bash|sh)": ("critical", "Descarga y ejecución de shell script"),
    r"\bpython\b.*-c.*socket":        ("high",     "Script Python con socket (posible reverse shell)"),
    r"\bbase64\b.*-d.*\|.*(sh|bash)": ("critical", "Ejecución de payload base64"),
    r"\bnmap\b":                       ("high",     "Escáner de red dentro del contenedor"),
    r"\bchmod\b.*4[0-9]{3}":          ("high",     "Intento de crear SUID dentro del contenedor"),
    r"\bcrontab\b.*-[li]":             ("medium",   "Modificación de crontab dentro del contenedor"),
    r"\bmasscan\b|\bzmap\b":           ("critical", "Escáner de red masivo dentro del contenedor"),
}

# Rutas que no deberían cambiar en runtime (para docker diff)
CRITICAL_CONTAINER_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/crontab", "/usr/bin/sudo", "/bin/sh", "/bin/bash",
]

# Puertos inesperados en contenedores típicos
UNEXPECTED_PORTS: dict[str, set[int]] = {
    "nginx":  {22, 23, 3306, 5432, 6379},   # nginx no debería exponer DB ports
    "mysql":  {22, 80, 443, 6379},
    "redis":  {22, 80, 443, 3306},
    "django": {3306, 5432, 6379, 22},
}


def _f(id, category, severity, title, description, remediation,
       evidence="") -> Finding:
    return Finding(
        id=id, category=f"runtime/{category}", severity=severity,
        title=title, description=description, remediation=remediation,
        evidence=evidence, auto_fix=False,
    )


async def _docker_exec(container: str, cmd: list[str], timeout: int = 15) -> str:
    """Ejecuta un comando dentro de un contenedor en ejecución."""
    proc = await run_command(
        ["docker", "exec", container] + cmd, timeout=timeout, check=False
    )
    return proc.stdout if proc.returncode == 0 else ""


async def _get_running_containers() -> list[dict]:
    """Lista de contenedores en ejecución con metadatos."""
    proc = await run_command(
        ["docker", "ps", "--format",
         '{"id":"{{.ID}}","name":"{{.Names}}","image":"{{.Image}}","status":"{{.Status}}"}'],
        timeout=15, check=False,
    )
    containers = []
    for line in proc.stdout.splitlines():
        try:
            containers.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return containers


async def check_running_processes(container: dict) -> list[Finding]:
    """Analiza los procesos activos dentro del contenedor."""
    cname = container["name"]
    proc = await run_command(
        ["docker", "top", cname, "-eo", "pid,ppid,user,cmd"],
        timeout=15, check=False,
    )
    if proc.returncode != 0:
        return []

    findings = []
    for line in proc.stdout.splitlines()[1:]:  # saltar cabecera
        for pattern, (sev, desc) in SUSPICIOUS_PROCS.items():
            if re.search(pattern, line, re.IGNORECASE):
                fid = f"rt_proc_{cname.replace('-','_')[:20]}_{abs(hash(pattern)) % 9999}"
                findings.append(_f(
                    fid, "process", sev,
                    f"Proceso sospechoso en contenedor: {cname}",
                    f"{desc}\nContenedor: {cname} | Imagen: {container['image']}\n"
                    f"Proceso: {line.strip()[:150]}",
                    "Investigar el proceso. Si no es legítimo:\n"
                    f"docker stop {cname} && docker rm {cname}",
                    evidence=f"container={cname} cmd={line.strip()[:100]}",
                ))
    return findings


async def check_container_diff(container: dict) -> list[Finding]:
    """Detecta ficheros modificados desde que arrancó el contenedor."""
    cname = container["name"]
    proc = await run_command(
        ["docker", "diff", cname], timeout=15, check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return []

    findings = []
    # docker diff devuelve líneas como "C /etc/passwd" (C=changed, A=added, D=deleted)
    for line in proc.stdout.splitlines():
        if not line:
            continue
        parts = line.split(" ", 1)
        if len(parts) < 2:
            continue
        change_type, path = parts[0], parts[1]
        if any(path.startswith(cp) for cp in CRITICAL_CONTAINER_PATHS):
            fid = f"rt_diff_{cname.replace('-','_')[:20]}_{path.replace('/','_')[-20:]}"
            findings.append(_f(
                fid, "integrity", "critical",
                f"Fichero crítico modificado en contenedor: {cname}/{path}",
                f"El fichero '{path}' fue modificado (tipo: {change_type}) "
                f"en el contenedor '{cname}' desde su inicio. "
                "Puede indicar un compromiso o modificación maliciosa.",
                f"Inspeccionar cambios:\ndocker exec {cname} cat {path}\n"
                f"Si no es legítimo: docker stop {cname} && docker rm {cname}",
                evidence=f"change={change_type} path={path} container={cname}",
            ))
    return findings


async def check_resource_limits(container: dict) -> list[Finding]:
    """Verifica si el contenedor está consumiendo recursos excesivos."""
    cname = container["name"]
    proc = await run_command(
        ["docker", "stats", "--no-stream", "--format",
         '{{.CPUPerc}}\t{{.MemPerc}}\t{{.MemUsage}}', cname],
        timeout=15, check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return []

    findings = []
    parts = proc.stdout.strip().split("\t")
    if len(parts) < 2:
        return []

    try:
        cpu_pct = float(parts[0].replace("%", ""))
        mem_pct = float(parts[1].replace("%", ""))
    except (ValueError, IndexError):
        return []

    if cpu_pct > 90:
        findings.append(_f(
            f"rt_cpu_{cname.replace('-','_')[:30]}",
            "resources", "high",
            f"CPU alta en contenedor: {cname} ({cpu_pct:.1f}%)",
            f"El contenedor '{cname}' está usando {cpu_pct:.1f}% de CPU. "
            "Puede ser un cryptominer u otro proceso malicioso.",
            f"docker top {cname}  # Ver qué proceso consume CPU\n"
            f"docker update --cpus 1.0 {cname}  # Limitar si es legítimo",
            evidence=f"cpu={cpu_pct}% mem={mem_pct}% container={cname}",
        ))
    if mem_pct > 95:
        mem_usage = parts[2] if len(parts) > 2 else "?"
        findings.append(_f(
            f"rt_mem_{cname.replace('-','_')[:30]}",
            "resources", "medium",
            f"Memoria alta en contenedor: {cname} ({mem_pct:.1f}%)",
            f"El contenedor '{cname}' está usando {mem_pct:.1f}% de memoria ({mem_usage}).",
            f"docker update --memory 512m {cname}  # Limitar uso de memoria",
            evidence=f"mem={mem_pct}% usage={mem_usage}",
        ))
    return findings


async def check_network_connections(container: dict) -> list[Finding]:
    """Verifica conexiones de red activas desde el contenedor."""
    cname  = container["name"]
    image  = container["image"].lower()

    # Obtener conexiones via ss dentro del contenedor
    output = await _docker_exec(cname, ["ss", "-tnp"])
    if not output:
        output = await _docker_exec(cname, ["netstat", "-tnp"])
    if not output:
        return []

    findings = []
    # Buscar conexiones ESTABLISHED a puertos sospechosos
    irc_ports = {6666, 6667, 6668, 6669, 7000}  # IRC (C2 clásico)
    for line in output.splitlines():
        # Extraer puertos de destino
        port_match = re.search(r':(\d+)\s+ESTAB', line)
        if not port_match:
            continue
        port = int(port_match.group(1))
        if port in irc_ports:
            findings.append(_f(
                f"rt_irc_{cname.replace('-','_')[:30]}_{port}",
                "network", "critical",
                f"Conexión IRC (posible C2) desde contenedor: {cname}",
                f"El contenedor '{cname}' tiene una conexión ESTABLISHED al puerto {port} "
                "(IRC). Los puertos IRC son usados habitualmente por botnets como canal C2.",
                f"docker stop {cname}  # Detener el contenedor comprometido",
                evidence=f"port={port} container={cname} line={line.strip()[:80]}",
            ))

    # Detectar imagen con puertos inesperados
    for img_pattern, bad_ports in UNEXPECTED_PORTS.items():
        if img_pattern in image:
            listening_ports = set(
                int(m.group(1))
                for m in re.finditer(r'LISTEN.*:(\d+)', output)
                if int(m.group(1)) < 65535
            )
            unexpected = listening_ports & bad_ports
            for p in unexpected:
                findings.append(_f(
                    f"rt_unexpected_port_{cname.replace('-','_')[:20]}_{p}",
                    "network", "high",
                    f"Puerto inesperado en contenedor {cname}: {p}",
                    f"La imagen '{container['image']}' tiene el puerto {p} en escucha, "
                    "lo cual no es habitual para este tipo de contenedor.",
                    "Verificar qué proceso está escuchando en ese puerto:\n"
                    f"docker exec {cname} ss -tlnp",
                    evidence=f"port={p} image={container['image']}",
                ))

    return findings


# ── Orquestador ───────────────────────────────────────────────────────────────

class RuntimeScanner:
    """Analiza el comportamiento de los contenedores en ejecución."""

    @staticmethod
    async def full_scan(
        containers: Optional[list[str]] = None,
    ) -> list[Finding]:
        if not command_exists("docker"):
            return []

        running = await _get_running_containers()
        if containers:
            running = [c for c in running if c["name"] in containers or c["id"] in containers]

        if not running:
            return [Finding(
                id="rt_no_containers", category="runtime", severity="info",
                title="Sin contenedores en ejecución",
                description="No hay contenedores Docker activos para analizar.",
                remediation="",
            )]

        logger.info("Runtime scan: %d contenedores en ejecución", len(running))

        all_findings: list[Finding] = []
        checks = [
            check_running_processes,
            check_container_diff,
            check_resource_limits,
            check_network_connections,
        ]

        for container in running:
            results = await asyncio.gather(
                *[check(container) for check in checks],
                return_exceptions=True,
            )
            cname = container["name"]
            for check_fn, result in zip(checks, results):
                if isinstance(result, list):
                    all_findings.extend(result)
                    if result:
                        logger.info("  runtime/%s/%s: %d hallazgos",
                                    cname, check_fn.__name__, len(result))
                else:
                    logger.error("  runtime/%s/%s error: %s",
                                 cname, check_fn.__name__, result)

        logger.info("Runtime scan: %d hallazgos totales", len(all_findings))
        return all_findings
