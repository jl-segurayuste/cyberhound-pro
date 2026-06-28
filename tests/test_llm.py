"""Explicación de hallazgos con LLM local (build_prompt + degradación best-effort)."""
from cyberhound.core import llm


def test_build_prompt_incluye_campos_del_hallazgo():
    p = llm.build_prompt({
        "title": "SSH permite root",
        "severity": "critical",
        "category": "ssh",
        "description": "PermitRootLogin yes",
        "remediation": "PermitRootLogin no",
    })
    assert "SSH permite root" in p
    assert "critical" in p
    assert "PermitRootLogin yes" in p
    assert "PermitRootLogin no" in p


async def test_explain_finding_sin_ollama_devuelve_none(monkeypatch):
    # Apunta a un puerto cerrado → connection refused → best-effort None (no lanza).
    monkeypatch.setattr(llm, "OLLAMA_URL", "http://127.0.0.1:1")
    res = await llm.explain_finding(
        {"title": "x", "severity": "high", "category": "c", "description": "d", "remediation": "r"}
    )
    assert res is None
