"""Integridad estática del frontend (sin navegador).

Detecta la clase de bug que rompió varios paneles: handlers (data-on-*/on())
que invocan funciones JS inexistentes, y el desajuste de nombres `_func` vs
`func`. Se ejecuta con la suite normal de pytest.
"""
import re
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "cyberhound" / "ui" / "static"
IDX = (STATIC / "index.html").read_text(encoding="utf-8")
# Los scripts de la UI, en el orden en que los carga index.html (comparten el ámbito global)
JS_FILES = re.findall(r'<script src="/static/(js/[\w.-]+\.js)"></script>', IDX)
APP = "\n".join((STATIC / f).read_text(encoding="utf-8") for f in JS_FILES)

# Los eventos se declaran como data-on-<evento>="función" (HTML) o con el helper
# on('<evento>', 'función', ...) (plantillas de static/js); el dispatcher los resuelve
# en window[función], así que deben ser declaraciones `function` (no const/let).
_DATA_ON_RE = re.compile(r'data-on-[a-z]+="([A-Za-z_$][\w$]*)"')
_ON_HELPER_RE = re.compile(r"\bon\('[a-z]+',\s*'([A-Za-z_$][\w$]*)'")
_ON_DYNAMIC_RE = re.compile(r"\bonclick:\s*'([A-Za-z_$][\w$]*)'")
_INLINE_ATTR_RE = re.compile(r'\son[a-z]+\s*=\s*["\']')


def _defined(text: str) -> set[str]:
    d = set(re.findall(r'function\s+([A-Za-z_$][\w$]*)\s*\(', text))
    d |= set(re.findall(r'(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=', text))
    d |= set(re.findall(r'window\.([A-Za-z_$][\w$]*)\s*=', text))
    return d


DEFINED = _defined(APP) | _defined(IDX)
# Lo que el dispatcher puede encontrar en window[...]
GLOBAL_FUNCS = set(re.findall(r'^\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(', APP + IDX, re.M)) | set(
    re.findall(r'window\.([A-Za-z_$][\w$]*)\s*=', APP + IDX))


def test_all_event_handlers_are_defined():
    """Cada función referenciada desde data-on-*/on() existe como función global."""
    handlers = set(_DATA_ON_RE.findall(IDX)) | set(_ON_HELPER_RE.findall(APP)) | set(_ON_DYNAMIC_RE.findall(APP))
    assert len(handlers) > 50, "no se encontraron los handlers: ¿ha cambiado la sintaxis?"
    missing = sorted(h for h in handlers if h not in GLOBAL_FUNCS)
    assert not missing, f"Handlers sin función global (window[...]) que los atienda: {missing}"


def test_no_inline_event_attributes():
    """La CSP tiene script-src-attr 'none': un onclick="..." no se ejecutaría."""
    found = _INLINE_ATTR_RE.findall(IDX) + _INLINE_ATTR_RE.findall(re.sub(r"\bon\(", "", APP))
    assert not found, f"Atributos de evento inline: {found[:5]}"


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


def test_index_carga_todos_los_scripts_y_cada_uno_es_estricto():
    on_disk = sorted(str(p.relative_to(STATIC)) for p in (STATIC / "js").glob("*.js"))
    assert JS_FILES == on_disk, "index.html debe cargar todos los ficheros de static/js, en orden"
    for f in JS_FILES:
        assert "\n'use strict';\n" in (STATIC / f).read_text()[:400], f


def test_ninguna_funcion_se_sobrescribe_en_tiempo_de_ejecucion():
    """Antes showPanel, loadDashboard (dos veces) y toast se reasignaban más abajo para añadirles
    pasos: el orden de carga decidía qué versión quedaba. Cada función se define una sola vez."""
    reassigned = re.findall(r"^\s*(?:window\.)?([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?function\b", APP, re.M)
    assert not reassigned, reassigned
    names = re.findall(r"^(?:async\s+)?function\s+([A-Za-z_$][\w$]*)", APP, re.M)
    assert not {n for n in names if names.count(n) > 1}
