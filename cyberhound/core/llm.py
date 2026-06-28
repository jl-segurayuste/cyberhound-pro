"""
Explicación de hallazgos en lenguaje llano con un LLM **local** (Ollama).

Traduce un hallazgo técnico a algo que un dueño de PYME sin conocimientos entienda:
qué significa, por qué es un riesgo para su negocio y qué hacer. Best-effort: si el
LLM no está disponible, devuelve None (la UI muestra el hallazgo técnico igualmente).
Nada sale del homelab: el LLM es local.
"""
from __future__ import annotations

import os

import aiohttp

from cyberhound.core.logging import get_logger

logger = get_logger("llm")

# LLM local (Ollama). Configurable por entorno; defaults al homelab.
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
LLM_MODEL = os.environ.get("CYBERHOUND_LLM_MODEL", "qwen2.5:7b-instruct")

_SYSTEM = (
    "Eres un consultor de ciberseguridad que explica hallazgos a un dueño de PYME SIN "
    "conocimientos técnicos. En español, claro y breve (3-5 frases): qué significa, por qué "
    "es un riesgo para su negocio, y qué debería hacer. Sin jerga innecesaria ni markdown."
)


def build_prompt(finding: dict) -> str:
    """Texto de usuario para el LLM a partir de un hallazgo (puro, testeable)."""
    return (
        f"Hallazgo: {finding.get('title', '')}\n"
        f"Severidad: {finding.get('severity', '')}\n"
        f"Categoría: {finding.get('category', '')}\n"
        f"Descripción técnica: {finding.get('description', '')}\n"
        f"Remediación técnica: {finding.get('remediation', '')}"
    )


async def explain_finding(finding: dict) -> str | None:
    """Explicación en lenguaje llano del hallazgo. None si el LLM no responde."""
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=45)) as session:
            async with session.post(
                f"{OLLAMA_URL}/api/chat",
                json={
                    "model": LLM_MODEL,
                    "stream": False,
                    "options": {"temperature": 0.3},
                    "messages": [
                        {"role": "system", "content": _SYSTEM},
                        {"role": "user", "content": build_prompt(finding)},
                    ],
                },
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"ollama HTTP {resp.status}")
                data = await resp.json()
                content = ((data.get("message") or {}).get("content") or "").strip()
                return content or None
    except Exception as e:  # noqa: BLE001 — best-effort, nunca propaga
        logger.warning("explicación LLM no disponible: %s", e)
        return None
