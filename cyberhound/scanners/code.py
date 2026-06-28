"""
Análisis estático de código fuente.
Delega en herramientas especializadas: bandit, shellcheck, eslint.
Los errores de herramientas faltantes se reportan como info, no como excepciones.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from cyberhound.core.executor import command_exists, read_file_async, run_command
from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("code")


async def _analyze_python(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    py_files = list(path.rglob("*.py"))
    if not py_files:
        return findings

    if not command_exists("bandit"):
        logger.info("bandit no instalado. Instala con: pip install bandit")
        findings.append(Finding(
            id="bandit_unavailable", category="code/python", severity="info",
            title="bandit no instalado (análisis Python limitado)",
            description="",
            remediation="pip install bandit",
        ))
    else:
        try:
            proc = await run_command(
                ["bandit", "-r", "-f", "json", "-q"] + [str(f) for f in py_files],
                timeout=300, check=False,
            )
            if proc.stdout.strip():
                data = json.loads(proc.stdout)
                for issue in data.get("results", []):
                    findings.append(Finding(
                        id=f"bandit_{issue['test_id']}_{Path(issue.get('filename','')).name}_{issue.get('line_number',0)}",
                        category="code/python/bandit",
                        severity=issue["issue_severity"].lower(),
                        title=issue["issue_text"],
                        description=issue.get("more_info", ""),
                        remediation="Ver: https://bandit.readthedocs.io/en/latest/",
                        evidence=issue.get("code", ""),
                        file_path=issue.get("filename", ""),
                        line_number=issue.get("line_number", 1),
                        code_snippet=issue.get("code", ""),
                    ))
        except Exception as e:
            logger.error("bandit error: %s", e, exc_info=True)

    return findings


async def _analyze_shell(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    shell_files = list(path.rglob("*.sh")) + list(path.rglob("*.bash"))
    if not shell_files:
        return findings

    if not command_exists("shellcheck"):
        findings.append(Finding(
            id="shellcheck_unavailable", category="code/shell", severity="info",
            title="shellcheck no instalado",
            description="",
            remediation="apt install shellcheck",
        ))
        return findings

    SEV_MAP = {"error": "high", "warning": "medium", "info": "low", "style": "info"}
    for sf in shell_files:
        try:
            proc = await run_command(
                ["shellcheck", "-f", "json", str(sf)], timeout=60, check=False,
            )
            if not proc.stdout.strip():
                continue
            issues = json.loads(proc.stdout)
            for issue in issues:
                code = issue.get("code", "")
                findings.append(Finding(
                    id=f"shellcheck_SC{code}_{sf.name}_{issue.get('line',0)}",
                    category="code/shell",
                    severity=SEV_MAP.get(issue.get("level", "warning"), "medium"),
                    title=issue.get("message", ""),
                    description=issue.get("message", ""),
                    remediation=f"https://www.shellcheck.net/wiki/SC{code}",
                    file_path=str(sf),
                    line_number=issue.get("line", 1),
                ))
        except Exception as e:
            logger.error("shellcheck error %s: %s", sf, e, exc_info=True)

    return findings


async def _analyze_javascript(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    js_files = list(path.rglob("*.js")) + list(path.rglob("*.ts"))
    if not js_files:
        return findings

    if not command_exists("eslint"):
        findings.append(Finding(
            id="eslint_unavailable", category="code/javascript", severity="info",
            title="eslint no instalado",
            description="",
            remediation="npm install -g eslint",
        ))
        return findings

    try:
        proc = await run_command(
            ["eslint", "--format", "json"] + [str(f) for f in js_files],
            timeout=120, check=False,
        )
        if not proc.stdout.strip():
            return findings
        data = json.loads(proc.stdout)
        for file_entry in data:
            for msg in file_entry.get("messages", []):
                rule = msg.get("ruleId", "unknown")
                findings.append(Finding(
                    id=f"eslint_{rule}_{msg.get('line',0)}_{Path(file_entry.get('filePath','')).name}",
                    category="code/javascript",
                    severity="high" if msg.get("severity", 2) >= 2 else "low",
                    title=msg.get("message", ""),
                    description=msg.get("message", ""),
                    remediation=f"Regla eslint: {rule}",
                    file_path=file_entry.get("filePath", ""),
                    line_number=msg.get("line", 1),
                    code_snippet=msg.get("source", ""),
                ))
    except Exception as e:
        logger.error("eslint error: %s", e, exc_info=True)

    return findings


async def _analyze_generic(path: Path) -> list[Finding]:
    """Busca ficheros .env expuestos y claves privadas."""
    findings: list[Finding] = []
    for env_file in path.rglob(".env*"):
        if env_file.is_file():
            findings.append(Finding(
                id=f"env_exposed_{env_file.name}",
                category="code/secrets", severity="medium",
                title=f"Fichero .env presente: {env_file.name}",
                description="Puede contener credenciales o tokens.",
                remediation="Añadir .env* a .gitignore y nunca commitear.",
                file_path=str(env_file),
            ))
    for key_pattern in ["*.pem", "*.key", "id_rsa", "id_ed25519"]:
        for key_file in path.rglob(key_pattern):
            if key_file.is_file():
                findings.append(Finding(
                    id=f"privkey_{key_file.name}",
                    category="code/secrets", severity="critical",
                    title=f"Posible clave privada: {key_file.name}",
                    description="Las claves privadas no deben estar en repositorios.",
                    remediation=(
                        "Eliminar del repo.\nRotar la clave.\n"
                        "Limpiar historial: git filter-repo"
                    ),
                    file_path=str(key_file),
                ))
    return findings


import asyncio


class CodeAuditor:
    @staticmethod
    async def full_analysis(path: Path) -> list[Finding]:
        results = await asyncio.gather(
            _analyze_python(path),
            _analyze_shell(path),
            _analyze_javascript(path),
            _analyze_generic(path),
            return_exceptions=True,
        )
        findings: list[Finding] = []
        for res in results:
            if isinstance(res, list):
                findings.extend(res)
            elif isinstance(res, Exception):
                logger.error("CodeAuditor error: %s", res, exc_info=True)
        logger.info("CodeAuditor: %d hallazgos en %s", len(findings), path)
        return findings
