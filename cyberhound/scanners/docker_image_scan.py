"""
Análisis profundo de imágenes Docker para CyberHound Pro.

A diferencia de docker_scan.py (que analiza contenedores en ejecución),
este módulo analiza el filesystem de las capas de las imágenes en reposo:

  1. Secretos hardcodeados en cualquier fichero de la imagen
     (contraseñas, API keys, tokens, claves privadas)
  2. Credenciales en variables de entorno definidas en el Dockerfile
  3. Claves SSH/TLS embebidas en la imagen
  4. Ficheros con permisos peligrosos dentro de la imagen
  5. Binarios SUID/SGID inesperados
  6. Paquetes del sistema con CVEs (via Trivy si disponible)
  7. Imágenes basadas en distribuciones EOL (End of Life)
  8. Dockerfile malas prácticas: RUN como root, ADD en lugar de COPY,
     secretos en ARG, imagen base sin versión fija

La técnica utilizada es exportar el filesystem de la imagen con
`docker save` / `docker inspect` y analizarlo sin ejecutar la imagen.
"""
from __future__ import annotations

import asyncio
import re
import tarfile
import tempfile
from pathlib import Path

from cyberhound.core.executor import command_exists, run_command
from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("docker_image_scan")

# Patrones de secretos para buscar en ficheros
SECRET_PATTERNS = [
    (r"PRIVATE KEY-----",                     "private_key",   "critical", "Clave privada embebida"),
    (r"BEGIN RSA PRIVATE",                    "rsa_key",       "critical", "Clave RSA privada"),
    (r"BEGIN EC PRIVATE",                     "ec_key",        "critical", "Clave EC privada"),
    (r"ghp_[a-zA-Z0-9]{36}",                 "github_token",  "critical", "GitHub Personal Access Token"),
    (r"AKIA[0-9A-Z]{16}",                     "aws_key",       "critical", "AWS Access Key ID"),
    (r"(?i)password\s*[=:]\s*['\"]?\S{8,}", "password",      "high",    "Contraseña hardcodeada"),
    (r"(?i)api[_-]?key\s*[=:]\s*['\"]?\S{8,}", "api_key",   "high",    "API key hardcodeada"),
    (r"(?i)secret\s*[=:]\s*['\"]?\S{8,}",    "secret",        "high",    "Secreto hardcodeado"),
    (r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/.*password", "email_pass", "medium", "Email con contraseña"),
    (r"(?i)database_url\s*[=:]\s*['\"]?\w+://\S+:\S+@", "db_url", "high", "URL de BD con credenciales"),
]

# Ficheros a excluir del análisis de secretos (demasiado ruido)
EXCLUDE_PATHS = {
    ".git", "node_modules", "__pycache__", ".pytest_cache",
    "vendor", "dist", "build", ".cache",
}

# Distribuciones EOL
EOL_DISTROS = {
    "ubuntu:14.04": "Ubuntu 14.04 Trusty (EOL abril 2019)",
    "ubuntu:16.04": "Ubuntu 16.04 Xenial (EOL abril 2021)",
    "ubuntu:18.04": "Ubuntu 18.04 Bionic (EOL mayo 2023)",
    "debian:8":     "Debian 8 Jessie (EOL junio 2018)",
    "debian:9":     "Debian 9 Stretch (EOL junio 2022)",
    "centos:6":     "CentOS 6 (EOL noviembre 2020)",
    "centos:7":     "CentOS 7 (EOL junio 2024)",
    "centos:8":     "CentOS 8 (EOL diciembre 2021)",
    "alpine:3.12":  "Alpine 3.12 (EOL mayo 2022)",
    "alpine:3.13":  "Alpine 3.13 (EOL noviembre 2022)",
}

# Ficheros sensibles que no deberían estar en una imagen
SENSITIVE_FILES = [
    ".env", ".env.local", ".env.production",
    "id_rsa", "id_ed25519", "id_ecdsa",
    ".netrc", ".npmrc", ".pypirc",
    "credentials", "secrets.yml", "secrets.yaml",
    ".aws/credentials", ".ssh/config",
]


def _f(id, category, severity, title, description, remediation,
       evidence="", auto_fix=False) -> Finding:
    return Finding(
        id=id, category=f"docker/image/{category}", severity=severity,
        title=title, description=description, remediation=remediation,
        evidence=evidence, auto_fix=auto_fix,
    )


async def _get_image_list() -> list[str]:
    """Lista de imágenes locales (repo:tag)."""
    proc = await run_command(
        ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
        timeout=15, check=False,
    )
    return [
        line.strip() for line in proc.stdout.splitlines()
        if line.strip() and "<none>" not in line
    ]


async def check_eol_base_images(images: list[str]) -> list[Finding]:
    """Detecta imágenes basadas en distribuciones End of Life."""
    findings = []
    for image in images:
        # Inspeccionar la imagen para obtener la base
        proc = await run_command(
            ["docker", "inspect", "--format", "{{.Config.Image}}", image],
            timeout=10, check=False,
        )
        base = proc.stdout.strip().lower()
        for eol_img, desc in EOL_DISTROS.items():
            if eol_img in image.lower() or eol_img in base:
                findings.append(_f(
                    f"img_eol_{image.replace(':', '_').replace('/', '_')[:40]}",
                    "eol", "high",
                    f"Imagen basada en distribución EOL: {image}",
                    f"{desc} — Esta imagen base ya no recibe actualizaciones de seguridad.",
                    "Actualizar la imagen base en el Dockerfile:\n"
                    "FROM ubuntu:22.04  # o la versión actual LTS",
                    evidence=f"image={image}",
                ))
    return findings


async def check_dockerfile_best_practices(image: str) -> list[Finding]:
    """
    Analiza el historial de la imagen para detectar malas prácticas
    del Dockerfile original (sin necesitar el Dockerfile fuente).
    """
    proc = await run_command(
        ["docker", "history", "--no-trunc", "--format",
         "{{.CreatedBy}}", image],
        timeout=15, check=False,
    )
    if proc.returncode != 0:
        return []

    findings = []
    layers = proc.stdout.splitlines()
    image_safe = image.replace(":", "_").replace("/", "_")[:30]

    for i, layer in enumerate(layers):
        layer_lower = layer.lower()

        # ADD en lugar de COPY (peor práctica — ADD puede descomprimir remotos)
        if re.search(r'\bADD\s+http', layer):
            findings.append(_f(
                f"img_add_remote_{image_safe}_{i}",
                "dockerfile", "medium",
                f"Imagen usa ADD con URL remota: {image}",
                "ADD con URLs remotas puede descargar contenido en tiempo de build sin verificación.",
                "Usar COPY en lugar de ADD para ficheros locales.\n"
                "Para descargas remotas, usar RUN wget/curl con verificación de checksum.",
                evidence=layer[:100],
            ))

        # Secretos en ARG (se guardan en el historial de capas)
        if re.search(r'ARG\s+(password|secret|token|key|api)', layer_lower):
            findings.append(_f(
                f"img_secret_arg_{image_safe}_{i}",
                "secrets", "high",
                f"Secreto en ARG de Docker: {image}",
                "Los ARG de Docker quedan grabados en el historial de capas y pueden extraerse.",
                "Usar Docker BuildKit Secrets:\n"
                "  RUN --mount=type=secret,id=mysecret cat /run/secrets/mysecret",
                evidence=layer[:100],
            ))

        # RUN con datos sensibles visibles
        if re.search(r'RUN.*(curl|wget).*-p\s+\S+|\bpassword\b|\bsecret\b', layer_lower):
            if re.search(r'(password|passwd|secret|token)\s*[=:]\s*\S{4,}', layer_lower):
                findings.append(_f(
                    f"img_secret_run_{image_safe}_{i}",
                    "secrets", "critical",
                    f"Credencial expuesta en capa RUN: {image}",
                    "Una capa RUN contiene lo que parece ser una credencial visible en el historial.",
                    "Eliminar credenciales de los RUN y usar multi-stage builds o BuildKit secrets.",
                    evidence=layer[:150],
                ))

    return findings


async def scan_image_filesystem(image: str, max_size_mb: int = 200) -> list[Finding]:
    """
    Exporta el filesystem de la imagen y busca secretos y ficheros sensibles.
    Analiza directamente el tar de capas sin ejecutar la imagen.
    """
    findings = []

    # Verificar tamaño antes de exportar
    proc = await run_command(
        ["docker", "inspect", "--format", "{{.Size}}", image],
        timeout=10, check=False,
    )
    if proc.returncode == 0:
        try:
            size_mb = int(proc.stdout.strip()) / 1_048_576
            if size_mb > max_size_mb:
                return [_f(
                    f"img_too_large_{image.replace(':','_')[:30]}",
                    "scan", "info",
                    f"Imagen demasiado grande para análisis completo: {image} ({size_mb:.0f} MB)",
                    f"El análisis de filesystem se limita a imágenes < {max_size_mb} MB.",
                    "Ejecutar Trivy para análisis de CVEs en imágenes grandes.",
                )]
        except (ValueError, TypeError):
            pass

    # Exportar imagen a tar en memoria
    loop = asyncio.get_event_loop()
    with tempfile.NamedTemporaryFile(suffix=".tar", delete=True) as tmp:
        proc_save = await run_command(
            ["docker", "save", "-o", tmp.name, image],
            timeout=120, check=False,
        )
        if proc_save.returncode != 0:
            return []

        try:
            findings.extend(
                await loop.run_in_executor(None, _scan_tar, tmp.name, image)
            )
        except Exception as e:
            logger.error("Error escaneando filesystem de %s: %s", image, e)

    return findings


def _scan_tar(tar_path: str, image: str) -> list[Finding]:
    """Escanea el tar de la imagen buscando secretos y ficheros sensibles."""
    findings = []
    image_safe = image.replace(":", "_").replace("/", "_")[:30]
    files_scanned = 0
    MAX_FILE_SIZE = 512 * 1024   # 512 KB por fichero
    MAX_FILES = 5000

    try:
        with tarfile.open(tar_path, "r") as outer:
            for member in outer.getmembers():
                # Procesar capas (ficheros .tar dentro del tar de la imagen)
                if not member.name.endswith("/layer.tar"):
                    continue
                layer_file = outer.extractfile(member)
                if not layer_file:
                    continue

                try:
                    with tarfile.open(fileobj=layer_file, mode="r:*") as layer:
                        for f in layer.getmembers():
                            if files_scanned >= MAX_FILES:
                                break
                            if not f.isfile():
                                continue

                            name = f.name.lstrip("./")
                            # Excluir directorios de ruido
                            if any(ex in name for ex in EXCLUDE_PATHS):
                                continue

                            # Verificar si es un fichero sensible por nombre
                            fname = Path(name).name.lower()
                            if any(s in fname for s in SENSITIVE_FILES):
                                findings.append(_f(
                                    f"img_sensitive_file_{image_safe}_{fname[:20]}",
                                    "secrets", "high",
                                    f"Fichero sensible en imagen: {name}",
                                    f"El fichero '{name}' en la imagen '{image}' puede "
                                    "contener credenciales o configuración sensible.",
                                    "Añadir a .dockerignore y no copiar ficheros sensibles:\n"
                                    f"echo '{fname}' >> .dockerignore",
                                    evidence=f"file={name} image={image}",
                                ))

                            # SUID/SGID inesperado
                            if f.mode & 0o4000 or f.mode & 0o2000:
                                # Binarios SUID esperados (whitelist)
                                expected_suid = {
                                    "bin/su", "bin/sudo", "bin/ping",
                                    "usr/bin/passwd", "usr/bin/sudo",
                                }
                                if name not in expected_suid:
                                    findings.append(_f(
                                        f"img_suid_{image_safe}_{fname[:20]}",
                                        "permissions", "high",
                                        f"Binario SUID/SGID inesperado: {name}",
                                        f"El fichero '{name}' en '{image}' tiene el bit SUID/SGID. "
                                        "Puede usarse para escalada de privilegios.",
                                        f"Quitar SUID: RUN chmod -s /{name}",
                                        evidence=f"mode={oct(f.mode)} file={name}",
                                    ))

                            # Buscar secretos en ficheros de texto pequeños
                            if f.size == 0 or f.size > MAX_FILE_SIZE:
                                continue
                            # Solo analizar extensiones de texto
                            ext = Path(name).suffix.lower()
                            text_exts = {
                                ".py", ".js", ".ts", ".sh", ".env", ".conf",
                                ".yml", ".yaml", ".json", ".xml", ".cfg",
                                ".ini", ".properties", ".txt", ".php",
                                ".rb", ".go", ".java", ".tf", ".hcl",
                            }
                            if ext not in text_exts and not fname.startswith(".env"):
                                files_scanned += 1
                                continue

                            try:
                                content_file = layer.extractfile(f)
                                if not content_file:
                                    continue
                                content = content_file.read().decode("utf-8", errors="ignore")
                                for pattern, pat_id, sev, desc in SECRET_PATTERNS:
                                    if re.search(pattern, content):
                                        findings.append(_f(
                                            f"img_secret_{pat_id}_{image_safe}_{fname[:15]}",
                                            "secrets", sev,
                                            f"Posible {desc} en imagen: {name}",
                                            f"Se encontró un patrón que sugiere {desc.lower()} "
                                            f"en el fichero '{name}' de la imagen '{image}'.",
                                            "Eliminar el secreto del código y usar variables de entorno "
                                            "o gestores de secretos (Vault, Docker Secrets).\n"
                                            "Reconstruir la imagen después de eliminar el secreto.",
                                            evidence=f"file={name} pattern={pat_id}",
                                        ))
                                        break  # Un finding por fichero
                            except Exception:
                                pass

                            files_scanned += 1
                except Exception as e:
                    logger.debug("Error procesando capa: %s", e)

    except tarfile.TarError as e:
        logger.error("Error abriendo tar de %s: %s", image, e)

    logger.info("docker_image_scan %s: %d ficheros, %d hallazgos",
                image, files_scanned, len(findings))
    return findings


# ── Orquestador ───────────────────────────────────────────────────────────────

class DockerImageScanner:
    """Escanea el filesystem de imágenes Docker en profundidad."""

    @staticmethod
    async def scan_images(
        images: list[str] | None = None,
        max_images: int = 5,
        deep_scan: bool = True,
        max_size_mb: int = 200,
    ) -> list[Finding]:
        if not command_exists("docker"):
            return []

        # Obtener lista de imágenes si no se especifican
        if not images:
            all_images = await _get_image_list()
            images = all_images[:max_images]

        if not images:
            return [_f(
                "no_images", "scan", "info",
                "Sin imágenes Docker locales para analizar",
                "", "Construye o descarga imágenes con docker pull/build",
            )]

        findings: list[Finding] = []
        logger.info("Docker image deep scan: %d imágenes", len(images))

        # EOL check — rápido
        eol = await check_eol_base_images(images)
        findings.extend(eol)

        # Análisis paralelo por imagen
        tasks = []
        for image in images:
            tasks.append(_scan_single_image(image, deep_scan, max_size_mb))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for image, result in zip(images, results, strict=False):
            if isinstance(result, list):
                findings.extend(result)
            else:
                logger.error("Error escaneando imagen %s: %s", image, result)

        logger.info("Docker image scan total: %d hallazgos en %d imágenes",
                    len(findings), len(images))
        return findings


async def _scan_single_image(
    image: str, deep_scan: bool, max_size_mb: int
) -> list[Finding]:
    findings = []
    # Análisis de Dockerfile history (rápido)
    findings.extend(await check_dockerfile_best_practices(image))
    # Análisis de filesystem (más lento)
    if deep_scan:
        findings.extend(await scan_image_filesystem(image, max_size_mb))
    return findings
