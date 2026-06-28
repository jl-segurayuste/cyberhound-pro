"""
Detección de secretos con herramientas consolidadas.

Jerarquía de herramientas (de más a menos precisa):
1. Gitleaks   — alta precisión, reglas TOML, excelente para repos git
2. Trufflehog — bueno para historial git y S3/GCS
3. Semgrep    — análisis de código estático, reglas de secretos
4. Regex propios — fallback cuando no hay ninguna herramienta instalada

Cada herramienta se invoca como subproceso con timeout controlado.
"""
from __future__ import annotations

import asyncio
import json
import re
import tempfile
from pathlib import Path

from cyberhound.core.executor import command_exists, run_command
from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("secrets")

# Herramientas y sus comandos de instalación
TOOL_INSTALL = {
    "gitleaks":   "https://github.com/gitleaks/gitleaks/releases (o: brew install gitleaks)",
    "trufflehog": "pip install trufflehog3  |  o binario en github.com/trufflesecurity/trufflehog",
    "semgrep":    "pip install semgrep",
}


class SecretScanner:

    @staticmethod
    async def scan(target_path: str) -> list[Finding]:
        """
        Ejecuta todas las herramientas disponibles en paralelo.
        Siempre informa qué herramientas se usaron y cuáles no estaban disponibles.
        """
        path = Path(target_path)
        if not path.exists():
            logger.error("Ruta no existe: %s", target_path)
            return []

        available = []
        unavailable = []
        for tool in TOOL_INSTALL:
            if command_exists(tool):
                available.append(tool)
            else:
                unavailable.append(tool)

        if unavailable:
            logger.warning(
                "Herramientas de secretos no disponibles: %s\n"
                "Para instalarlas: %s",
                unavailable,
                {t: TOOL_INSTALL[t] for t in unavailable},
            )

        if not available:
            logger.warning(
                "Sin herramientas especializadas. Usando regex básicos (mayor tasa de falsos positivos)."
            )
            return await SecretScanner._regex_scan(path)

        tasks = []
        if "gitleaks" in available:
            tasks.append(SecretScanner._gitleaks_scan(path))
        if "trufflehog" in available:
            tasks.append(SecretScanner._trufflehog_scan(path))
        if "semgrep" in available:
            tasks.append(SecretScanner._semgrep_scan(path))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings: list[Finding] = []
        for res in results:
            if isinstance(res, list):
                findings.extend(res)
            elif isinstance(res, Exception):
                logger.error("Error en scan de secretos: %s", res, exc_info=True)

        # Deduplicar por fichero+línea
        seen: set[tuple] = set()
        unique = []
        for f in findings:
            key = (f.file_path, f.line_number, f.title)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        logger.info("SecretScanner: %d secretos únicos detectados", len(unique))
        return unique

    @staticmethod
    async def _gitleaks_scan(path: Path) -> list[Finding]:
        findings = []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            cmd = [
                "gitleaks", "detect",
                "--source", str(path),
                "--report-format", "json",
                "--report-path", tmp_path,
                "--no-git",    # escanear directorio sin necesidad de repo git
                "--exit-code", "0",  # no fallar aunque encuentre secretos
            ]
            proc = await run_command(cmd, timeout=120, check=False)

            # Gitleaks escribe JSON independientemente del exit code
            try:
                with open(tmp_path, encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                if proc.returncode not in (0, 1):
                    logger.error("gitleaks error: %s", proc.stderr[:300])
                return findings

            for item in (data or []):
                # Enmascarar el secreto detectado en el log (no queremos loguear credenciales)
                secret_preview = (item.get("Secret", "")[:4] + "***") if item.get("Secret") else "***"
                findings.append(Finding(
                    id=f"gitleaks_{item.get('RuleID','unknown')}_{item.get('StartLine',0)}",
                    category="code/secrets/gitleaks",
                    severity="critical" if "key" in item.get("RuleID","").lower() else "high",
                    title=f"Secreto detectado: {item.get('Description', item.get('RuleID',''))}",
                    description=(
                        f"Regla: {item.get('RuleID','')}\n"
                        f"Preview: {secret_preview}\n"
                        f"Commit: {item.get('Commit','N/A')}"
                    ),
                    remediation=(
                        "1. Eliminar el secreto del código.\n"
                        "2. Rotar la credencial inmediatamente.\n"
                        "3. Limpiar historial git con: git filter-repo o BFG Repo Cleaner.\n"
                        "4. Usar variables de entorno o un gestor de secretos (Vault, SOPS)."
                    ),
                    evidence=f"Fichero: {item.get('File','')}:{item.get('StartLine','')}",
                    file_path=item.get("File", ""),
                    line_number=item.get("StartLine", 0),
                    auto_fix=False,
                ))
        except Exception as e:
            logger.error("gitleaks scan error: %s", e, exc_info=True)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        return findings

    @staticmethod
    async def _trufflehog_scan(path: Path) -> list[Finding]:
        findings = []
        try:
            cmd = [
                "trufflehog", "filesystem", str(path),
                "--json", "--no-update",
            ]
            proc = await run_command(cmd, timeout=180, check=False)
            # Trufflehog emite JSON lines (un JSON por línea)
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    det = item.get("DetectorName", "unknown")
                    src = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
                    findings.append(Finding(
                        id=f"trufflehog_{det}_{src.get('line',0)}",
                        category="code/secrets/trufflehog",
                        severity="critical",
                        title=f"Secreto verificado: {det}",
                        description=(
                            f"Detector: {det}\n"
                            f"Verificado: {item.get('Verified', False)}"
                        ),
                        remediation=(
                            "1. Rotar la credencial inmediatamente.\n"
                            "2. Eliminar del código fuente.\n"
                            "3. Auditar accesos con esta credencial en los últimos 90 días."
                        ),
                        evidence=f"Fichero: {src.get('file','')}:{src.get('line','')}",
                        file_path=src.get("file", ""),
                        line_number=src.get("line", 0),
                        auto_fix=False,
                    ))
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            logger.error("trufflehog scan error: %s", e, exc_info=True)
        return findings

    @staticmethod
    async def _semgrep_scan(path: Path) -> list[Finding]:
        findings = []
        try:
            cmd = [
                "semgrep", "--config", "p/secrets",
                "--json", "--quiet",
                str(path),
            ]
            proc = await run_command(cmd, timeout=180, check=False)
            if not proc.stdout.strip():
                return findings
            data = json.loads(proc.stdout)
            for result in data.get("results", []):
                findings.append(Finding(
                    id=f"semgrep_{result.get('check_id','').replace('.','_')}_{result.get('start',{}).get('line',0)}",
                    category="code/secrets/semgrep",
                    severity="high",
                    title=f"Secreto detectado: {result.get('extra',{}).get('message','')}",
                    description=result.get("extra", {}).get("message", ""),
                    remediation=(
                        "Mover a variable de entorno o gestor de secretos.\n"
                        f"Regla: {result.get('check_id','')}"
                    ),
                    file_path=result.get("path", ""),
                    line_number=result.get("start", {}).get("line", 0),
                    auto_fix=False,
                ))
        except Exception as e:
            logger.error("semgrep scan error: %s", e, exc_info=True)
        return findings

    @staticmethod
    async def _regex_scan(path: Path) -> list[Finding]:
        """
        Fallback de regex cuando no hay herramientas instaladas.
        Alta tasa de falsos positivos — se informa al usuario.
        """
        logger.warning(
            "Usando detección básica de secretos por regex. "
            "Instala gitleaks para mayor precisión: "
            "https://github.com/gitleaks/gitleaks/releases"
        )
        findings = []

        PATTERNS = [
            (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']',
             "Posible contraseña hardcodeada", "critical"),
            (r'(?i)(api_key|apikey|api-key)\s*[=:]\s*["\'][A-Za-z0-9_\-]{16,}["\']',
             "Posible API key hardcodeada", "critical"),
            (r'(?i)(secret|token|auth)\s*[=:]\s*["\'][A-Za-z0-9_\-\.]{20,}["\']',
             "Posible token/secret hardcodeado", "high"),
            (r'-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----',
             "Clave privada en código fuente", "critical"),
            (r'(?i)aws_secret_access_key\s*[=:]\s*["\'][^"\']+["\']',
             "AWS Secret Access Key", "critical"),
        ]

        CODE_EXTENSIONS = {
            ".py", ".js", ".ts", ".sh", ".bash", ".env",
            ".yml", ".yaml", ".json", ".tf", ".php",
        }

        try:
            for filepath in path.rglob("*"):
                if not filepath.is_file():
                    continue
                if filepath.suffix.lower() not in CODE_EXTENSIONS:
                    continue
                try:
                    if filepath.stat().st_size > 2 * 1024 * 1024:
                        continue
                    content = filepath.read_text(errors="ignore")
                    for pattern, title, severity in PATTERNS:
                        for m in re.finditer(pattern, content):
                            line_num = content[:m.start()].count("\n") + 1
                            findings.append(Finding(
                                id=f"regex_secret_{filepath.name}_{line_num}",
                                category="code/secrets/regex",
                                severity=severity,
                                title=f"{title} en {filepath.name}",
                                description=f"Patrón detectado: {m.group(0)[:50]}…",
                                remediation=(
                                    "ADVERTENCIA: Detección por regex (posible falso positivo).\n"
                                    "Verifica manualmente y migra a variables de entorno."
                                ),
                                file_path=str(filepath),
                                line_number=line_num,
                                auto_fix=False,
                            ))
                except PermissionError:
                    logger.warning(
                        "Sin permisos para leer %s — posible restricción SELinux/AppArmor.", filepath
                    )
                except OSError as e:
                    logger.debug("Error leyendo %s: %s", filepath, e)
        except Exception as e:
            logger.error("regex_scan error: %s", e, exc_info=True)

        return findings
