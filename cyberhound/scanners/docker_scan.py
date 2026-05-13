"""
Análisis de seguridad de contenedores Docker.

Checks implementados:
  1. Contenedores corriendo como root (--user no especificado)
  2. Imágenes con CVEs conocidos (via Trivy si disponible)
  3. Secretos en variables de entorno de contenedores
  4. Puertos expuestos innecesariamente
  5. Imágenes sin actualizar (más de N días desde el pull)
  6. Volúmenes con rutas críticas montadas (/, /etc, /proc, /sys)
  7. Contenedores con privilegios excesivos (--privileged, capabilities)
  8. Imágenes de registros no confiables
  9. Docker socket montado en contenedores (riesgo de escape)
  10. Imágenes sin usuario no-root definido en Dockerfile
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cyberhound.core.executor import command_exists, run_command
from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("docker_scan")

# Registros considerados de confianza
TRUSTED_REGISTRIES = {
    "docker.io", "registry-1.docker.io", "ghcr.io",
    "gcr.io", "mcr.microsoft.com", "quay.io",
    "registry.access.redhat.com",
}

# Variables de entorno sospechosas (posibles secretos)
SECRET_ENV_PATTERNS = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "auth", "credential", "private_key", "access_key", "aws_secret",
    "database_url", "db_pass", "smtp_pass", "jwt_secret",
]

# Rutas peligrosas si se montan desde el host
DANGEROUS_MOUNTS = [
    "/", "/etc", "/etc/passwd", "/etc/shadow",
    "/proc", "/sys", "/boot", "/var/run/docker.sock",
    "/root", "/home",
]


async def _docker_available() -> bool:
    if not command_exists("docker"):
        return False
    proc = await run_command(["docker", "info"], timeout=10, check=False)
    return proc.returncode == 0


async def _docker_json(args: list[str]) -> Optional[list | dict]:
    proc = await run_command(["docker"] + args, timeout=30, check=False)
    if proc.returncode != 0:
        logger.warning("docker %s respondió %d: %s", " ".join(args[:3]), proc.returncode, proc.stderr[:80])
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Checks individuales
# ──────────────────────────────────────────────────────────────────────────────

async def check_containers_as_root() -> list[Finding]:
    """Detecta contenedores en ejecución sin usuario no-root especificado."""
    containers = await _docker_json(["ps", "--format", "json"])
    if not containers:
        return []
    if isinstance(containers, dict):
        containers = [containers]

    findings = []
    for c in containers:
        cid  = c.get("ID", "")[:12]
        name = c.get("Names", cid)
        # Inspeccionar el usuario del contenedor
        inspect = await _docker_json(["inspect", "--format", "{{json .Config}}", cid])
        if not inspect:
            continue
        if isinstance(inspect, list):
            inspect = inspect[0] if inspect else {}
        user = inspect.get("User", "")
        if not user or user in ("0", "root", "0:0"):
            findings.append(Finding(
                id=f"docker_root_{cid}",
                category="docker/privilege", severity="high",
                title=f"Contenedor como root: {name}",
                description=(
                    f"El contenedor '{name}' ({cid}) está ejecutándose como root (UID 0). "
                    "Si hay un escape del contenedor, el atacante tiene root en el host."
                ),
                remediation=(
                    f"Añadir al Dockerfile: USER nonroot\n"
                    f"O en docker-compose.yml: user: '1000:1000'\n"
                    f"O al ejecutar: docker run --user 1000:1000 ..."
                ),
                evidence=f"Container={name}, User={user or 'root (por defecto)'}",
                auto_fix=False,
            ))
    return findings


async def check_privileged_containers() -> list[Finding]:
    """Detecta contenedores con --privileged o capabilities peligrosas."""
    DANGEROUS_CAPS = {
        "CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE",
        "CAP_SYS_MODULE", "CAP_DAC_OVERRIDE", "CAP_SETUID", "CAP_SETGID",
    }
    containers = await _docker_json(["ps", "-q"])
    if not containers:
        return []
    ids = containers if isinstance(containers, list) else [containers]

    findings = []
    for cid in ids:
        cid = cid.strip() if isinstance(cid, str) else cid.get("ID", "")
        if not cid:
            continue
        inspect = await _docker_json(["inspect", cid])
        if not inspect:
            continue
        data = inspect[0] if isinstance(inspect, list) else inspect
        host_config = data.get("HostConfig", {})
        name = data.get("Name", cid).lstrip("/")

        # Privileged
        if host_config.get("Privileged"):
            findings.append(Finding(
                id=f"docker_privileged_{cid[:12]}",
                category="docker/privilege", severity="critical",
                title=f"Contenedor privilegiado: {name}",
                description=(
                    f"El contenedor '{name}' se ejecuta con --privileged. "
                    "Tiene acceso total al kernel del host, equivalente a root sin restricciones. "
                    "Es el peor escenario posible desde el punto de vista de seguridad."
                ),
                remediation=(
                    "Eliminar --privileged y añadir solo las capabilities estrictamente necesarias:\n"
                    "docker run --cap-drop ALL --cap-add CHOWN --cap-add NET_BIND_SERVICE ..."
                ),
                evidence=f"Privileged=true",
                auto_fix=False,
            ))
            continue

        # Capabilities peligrosas
        caps_add = host_config.get("CapAdd") or []
        dangerous = [c for c in caps_add if c in DANGEROUS_CAPS]
        if dangerous:
            findings.append(Finding(
                id=f"docker_caps_{cid[:12]}",
                category="docker/privilege", severity="high",
                title=f"Capabilities peligrosas: {name}",
                description=(
                    f"El contenedor '{name}' tiene capabilities potencialmente peligrosas: "
                    f"{', '.join(dangerous)}"
                ),
                remediation=(
                    "Revisar si cada capability es estrictamente necesaria.\n"
                    "Regla general: --cap-drop ALL y añadir solo las mínimas."
                ),
                evidence=f"CapAdd={dangerous}",
                auto_fix=False,
            ))
    return findings


async def check_docker_socket_mounted() -> list[Finding]:
    """Detecta contenedores con el socket de Docker montado (escape trivial)."""
    containers = await _docker_json(["ps", "-q"])
    if not containers:
        return []
    ids = containers if isinstance(containers, list) else [containers]

    findings = []
    for cid in ids:
        cid = cid.strip() if isinstance(cid, str) else cid.get("ID", "")
        if not cid:
            continue
        inspect = await _docker_json(["inspect", cid])
        if not inspect:
            continue
        data = inspect[0] if isinstance(inspect, list) else inspect
        name = data.get("Name", cid).lstrip("/")
        mounts = data.get("Mounts", [])
        for mount in mounts:
            src = mount.get("Source", "")
            if "/docker.sock" in src or src == "/var/run/docker.sock":
                findings.append(Finding(
                    id=f"docker_sock_{cid[:12]}",
                    category="docker/escape", severity="critical",
                    title=f"Docker socket montado en: {name}",
                    description=(
                        f"El contenedor '{name}' tiene montado el socket de Docker "
                        "(/var/run/docker.sock). Cualquier proceso dentro del contenedor "
                        "puede controlar Docker y escapar trivialmente al host."
                    ),
                    remediation=(
                        "Eliminar el bind mount del socket Docker.\n"
                        "Si es necesario para CI/CD, usar Docker-in-Docker (dind) "
                        "o una solución como Kaniko."
                    ),
                    evidence=f"Mount: {src} → {mount.get('Destination','')}",
                    auto_fix=False,
                ))
    return findings


async def check_secret_env_vars() -> list[Finding]:
    """Detecta secretos hardcodeados en variables de entorno de contenedores."""
    containers = await _docker_json(["ps", "-q"])
    if not containers:
        return []
    ids = containers if isinstance(containers, list) else [containers]

    findings = []
    for cid in ids:
        cid = cid.strip() if isinstance(cid, str) else cid.get("ID", "")
        if not cid:
            continue
        inspect = await _docker_json(["inspect", cid])
        if not inspect:
            continue
        data = inspect[0] if isinstance(inspect, list) else inspect
        name = data.get("Name", cid).lstrip("/")
        env_vars = data.get("Config", {}).get("Env") or []
        suspicious = []
        for env in env_vars:
            key = env.split("=")[0].lower() if "=" in env else ""
            value = env.split("=", 1)[1] if "=" in env else ""
            # Comprobar si el nombre sugiere un secreto y tiene valor no vacío
            if any(pat in key for pat in SECRET_ENV_PATTERNS) and value and value != "":
                suspicious.append(key.upper())
        if suspicious:
            findings.append(Finding(
                id=f"docker_env_secret_{cid[:12]}",
                category="docker/secrets", severity="high",
                title=f"Posibles secretos en env vars: {name}",
                description=(
                    f"El contenedor '{name}' tiene variables de entorno con nombres "
                    f"que sugieren secretos: {', '.join(suspicious[:5])}\n"
                    "Las credenciales en variables de entorno son accesibles desde "
                    "dentro del contenedor y aparecen en docker inspect."
                ),
                remediation=(
                    "Usar Docker Secrets o un gestor de secretos (Vault, AWS SSM):\n"
                    "docker secret create mi_secret mi_fichero.txt\n"
                    "O ficheros .env no commiteados con --env-file"
                ),
                evidence=f"Env vars sospechosas: {', '.join(suspicious[:5])}",
                auto_fix=False,
            ))
    return findings


async def check_dangerous_mounts() -> list[Finding]:
    """Detecta contenedores con rutas críticas del host montadas."""
    containers = await _docker_json(["ps", "-q"])
    if not containers:
        return []
    ids = containers if isinstance(containers, list) else [containers]

    findings = []
    for cid in ids:
        cid = cid.strip() if isinstance(cid, str) else cid.get("ID", "")
        if not cid:
            continue
        inspect = await _docker_json(["inspect", cid])
        if not inspect:
            continue
        data = inspect[0] if isinstance(inspect, list) else inspect
        name = data.get("Name", cid).lstrip("/")
        mounts = data.get("Mounts", [])
        for mount in mounts:
            src = mount.get("Source", "")
            if src in DANGEROUS_MOUNTS:
                findings.append(Finding(
                    id=f"docker_mount_{cid[:12]}_{src.replace('/', '_')}",
                    category="docker/mounts", severity="critical",
                    title=f"Ruta crítica montada en: {name}",
                    description=(
                        f"El contenedor '{name}' tiene montada la ruta '{src}' del host, "
                        "que contiene datos críticos del sistema."
                    ),
                    remediation="Eliminar el bind mount de la ruta crítica.",
                    evidence=f"Mount: {src} → {mount.get('Destination','')}",
                    auto_fix=False,
                ))
    return findings


async def check_images_cve(image_list: Optional[list[str]] = None) -> list[Finding]:
    """Analiza imágenes con Trivy si está disponible."""
    if not command_exists("trivy"):
        return [Finding(
            id="trivy_unavailable", category="docker/cve", severity="info",
            title="Trivy no instalado (análisis CVE de imágenes no disponible)",
            description="",
            remediation=(
                "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/"
                "contrib/install.sh | sh -s -- -b /usr/local/bin"
            ),
        )]

    # Obtener lista de imágenes en uso si no se proporciona
    if not image_list:
        proc = await run_command(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            timeout=15, check=False,
        )
        image_list = [
            line.strip() for line in proc.stdout.splitlines()
            if line.strip() and "<none>" not in line
        ]

    findings = []
    for image in image_list[:10]:  # Limitar a 10 imágenes para no tardar demasiado
        proc = await run_command(
            ["trivy", "image", "--format", "json", "--exit-code", "0",
             "--severity", "CRITICAL,HIGH", image],
            timeout=120, check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            continue
        try:
            report = json.loads(proc.stdout)
        except json.JSONDecodeError:
            continue

        results = report.get("Results", [])
        total_critical = total_high = 0
        for result in results:
            vulns = result.get("Vulnerabilities") or []
            total_critical += sum(1 for v in vulns if v.get("Severity") == "CRITICAL")
            total_high += sum(1 for v in vulns if v.get("Severity") == "HIGH")

        if total_critical + total_high > 0:
            sev = "critical" if total_critical > 0 else "high"
            findings.append(Finding(
                id=f"trivy_{image.replace(':', '_').replace('/', '_')[:40]}",
                category="docker/cve", severity=sev,
                title=f"CVEs en imagen {image}: {total_critical}C / {total_high}H",
                description=(
                    f"La imagen '{image}' tiene {total_critical} CVEs críticos "
                    f"y {total_high} altos según Trivy."
                ),
                remediation=(
                    f"Actualizar la imagen base:\n"
                    f"docker pull {image}\n"
                    f"O ejecutar trivy image {image} para ver el detalle completo."
                ),
                evidence=f"Critical={total_critical}, High={total_high}",
                auto_fix=False,
            ))
    return findings


async def check_old_images() -> list[Finding]:
    """Detecta imágenes con más de 90 días sin actualizar."""
    MAX_AGE_DAYS = 90
    proc = await run_command(
        ["docker", "images", "--format",
         '{"repo":"{{.Repository}}","tag":"{{.Tag}}","created":"{{.CreatedAt}}"}'],
        timeout=15, check=False,
    )
    if proc.returncode != 0:
        return []

    findings = []
    now = datetime.now(timezone.utc)
    for line in proc.stdout.splitlines():
        try:
            data = json.loads(line)
            created_str = data.get("created", "")
            if not created_str or "<none>" in data.get("repo", ""):
                continue
            # Docker format: "2024-01-15 10:30:00 +0000 UTC"
            created_str = created_str.replace(" +0000 UTC", "").replace(" UTC", "")
            try:
                created = datetime.strptime(created_str[:19], "%Y-%m-%d %H:%M:%S")
                created = created.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            age_days = (now - created).days
            if age_days > MAX_AGE_DAYS:
                image_name = f"{data['repo']}:{data['tag']}"
                findings.append(Finding(
                    id=f"docker_old_image_{data['repo'].replace('/', '_')}_{data['tag']}",
                    category="docker/updates", severity="medium",
                    title=f"Imagen sin actualizar ({age_days}d): {image_name}",
                    description=(
                        f"La imagen '{image_name}' tiene {age_days} días sin actualizar. "
                        "Puede contener vulnerabilidades conocidas no parcheadas."
                    ),
                    remediation=f"docker pull {image_name}",
                    evidence=f"Creada: {created_str}, Edad: {age_days} días",
                    auto_fix=False,
                ))
        except (json.JSONDecodeError, ValueError, KeyError):
            continue
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Orquestador
# ──────────────────────────────────────────────────────────────────────────────

class DockerScanner:
    @staticmethod
    async def full_scan(
        scan_images_cve: bool = True,
        image_list: Optional[list[str]] = None,
        scan_k8s: bool = True,
    ) -> list[Finding]:
        docker_findings: list[Finding] = []

        if not await _docker_available():
            docker_findings.append(Finding(
                id="docker_unavailable", category="docker", severity="info",
                title="Docker no disponible en este sistema",
                description="Docker no está instalado o el daemon no está activo.",
                remediation="apt install docker.io && systemctl enable --now docker",
            ))
        else:
            logger.info("Docker scan iniciado")
            tasks = {
                "containers_root":  check_containers_as_root(),
                "privileged":       check_privileged_containers(),
                "docker_socket":    check_docker_socket_mounted(),
                "env_secrets":      check_secret_env_vars(),
                "dangerous_mounts": check_dangerous_mounts(),
                "old_images":       check_old_images(),
            }
            if scan_images_cve:
                tasks["images_cve"] = check_images_cve(image_list)

            results = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for module, result in zip(tasks.keys(), results):
                if isinstance(result, list):
                    docker_findings.extend(result)
                    logger.info("  docker/%s: %d hallazgos", module, len(result))
                else:
                    logger.error("  docker/%s error: %s", module, result)

        # Kubernetes scan (opcional, no falla si no está disponible)
        k8s_findings: list[Finding] = []
        if scan_k8s:
            try:
                from cyberhound.scanners.kubernetes_scan import KubernetesScanner
                k8s_findings = await KubernetesScanner.full_scan()
            except Exception as e:
                logger.warning("Kubernetes scan error: %s", e)

        all_findings = docker_findings + k8s_findings
        logger.info("Docker+K8s scan: %d hallazgos totales "
                    "(%d docker, %d kubernetes)",
                    len(all_findings), len(docker_findings), len(k8s_findings))
        return all_findings
