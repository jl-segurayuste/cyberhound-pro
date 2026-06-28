"""Integridad estática del frontend (sin navegador).

Detecta la clase de bug que rompió varios paneles: handlers (onclick/onchange…)
que invocan funciones JS inexistentes, y el desajuste de nombres `_func` vs
`func`. Se ejecuta con la suite normal de pytest.
"""
import re
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "cyberhound" / "ui" / "static"
APP = (STATIC / "app.js").read_text(encoding="utf-8")
IDX = (STATIC / "index.html").read_text(encoding="utf-8")

_HANDLER_RE = re.compile(
    r'on(?:click|change|input|submit|keydown|keyup|focus|blur)\s*=\s*'
    r'[\\"\'`]\s*([A-Za-z_$][\w$]*)\s*\('
)


def _defined(text: str) -> set[str]:
    d = set(re.findall(r'function\s+([A-Za-z_$][\w$]*)\s*\(', text))
    d |= set(re.findall(r'(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=', text))
    d |= set(re.findall(r'window\.([A-Za-z_$][\w$]*)\s*=', text))
    return d


DEFINED = _defined(APP) | _defined(IDX)

# Palabras clave / globales que pueden aparecer como `palabra(` en un handler
# inline (p.ej. onkeydown="if(...)") y no son funciones de la app.
_JS_KEYWORDS = {"if", "for", "while", "switch", "return", "typeof", "void",
                "delete", "new", "throw", "do", "else", "function", "catch"}


def test_all_event_handlers_are_defined():
    """Cada función invocada desde un on*-handler debe existir en el JS."""
    handlers = set(_HANDLER_RE.findall(IDX)) | set(_HANDLER_RE.findall(APP))
    # Extras invocados tras stopPropagation() dentro de plantillas
    handlers |= set(re.findall(r'stopPropagation\(\);\s*([A-Za-z_$][\w$]*)\s*\(', APP))
    handlers -= _JS_KEYWORDS
    missing = sorted(h for h in handlers if h not in DEFINED)
    assert not missing, f"Handlers que llaman a funciones inexistentes: {missing}"


def test_no_underscore_prefix_mismatch():
    """No debe llamarse `func(` cuando solo existe `_func` (bug renderSummary)."""
    bad = []
    for u in (d for d in DEFINED if d.startswith("_") and len(d) > 1):
        plain = u[1:]
        if plain in DEFINED:
            continue
        # ¿se invoca `plain(` como función global (no como método .plain()) ?
        if re.search(r'(?<![.\w$])' + re.escape(plain) + r'\s*\(', APP):
            bad.append(f"{plain}() se invoca pero solo existe {u}()")
    assert not bad, bad


def test_no_duplicate_element_ids():
    """Ningún id de elemento debe estar duplicado en el HTML (DOM inválido)."""
    ids = re.findall(r'\sid="([^"]+)"', IDX)
    from collections import Counter
    dups = sorted(k for k, v in Counter(ids).items() if v > 1)
    assert not dups, f"IDs duplicados en index.html: {dups}"


def test_data_panel_loaders_exist():
    """Las funciones load* referenciadas en los mapas de carga deben existir."""
    referenced = set(re.findall(r'=>\s*(?:\{[^}]*?)?\b(load[A-Z][\w$]*)\s*\(', APP))
    missing = sorted(r for r in referenced if r not in DEFINED)
    assert not missing, f"Cargadores de panel inexistentes: {missing}"
