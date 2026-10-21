"""
Configuración efectiva de sshd y cómo cambiar una opción para que de verdad surta efecto.

sshd se queda con el PRIMER valor de cada opción, lee los ficheros de Include en el sitio donde
aparecen (en Debian, Ubuntu y RHEL 9 sshd_config.d/*.conf va al principio, y cloud-init deja ahí
PasswordAuthentication yes) y lo que hay dentro de un bloque Match solo vale para esas conexiones.
Antes la auditoría leía solo sshd_config y el fix cambiaba su primera línea o añadía la opción al
final del fichero, dentro del último Match si lo había: el valor inseguro de un drop-in seguía
mandando y el fix decía "aplicado".

Este fichero se usa en el servidor y además viaja tal cual dentro de los scripts que se ejecutan
en los hosts auditados (scanners/ssh_audit.py), así que solo usa la biblioteca estándar y sintaxis
de Python 3.6 (el python3 de RHEL 8): nada de anotaciones con list[...] ni métodos de str de 3.9.
"""
import glob
import os
import re

SSHD_CONFIG = "/etc/ssh/sshd_config"
_MAX_INCLUDE_DEPTH = 8


def _split(line):
    """(opción en minúsculas, valor) de una línea de sshd_config; (None, None) si no tiene."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None, None
    m = re.match(r"([A-Za-z0-9]+)\s*(?:=\s*|\s+)(.*)$", s)
    if not m:
        return s.lower(), ""
    return m.group(1).lower(), m.group(2).strip()


def _walk(path, base, texts, depth=0, in_match=False):
    """Líneas en el orden en que sshd las procesa: (fichero, nº de línea, opción, valor, dentro de Match)."""
    if path not in texts:
        try:
            with open(path) as f:
                texts[path] = f.read()
        except OSError:
            texts[path] = None
    if texts[path] is None:
        return
    for i, line in enumerate(texts[path].splitlines()):
        kw, val = _split(line)
        if kw == "match":
            in_match = True
        yield path, i, kw, val, in_match
        if kw == "include" and depth < _MAX_INCLUDE_DEPTH:
            for pattern in val.split():
                full = pattern if pattern.startswith("/") else os.path.join(base, pattern)
                for inc in sorted(glob.glob(full)):
                    yield from _walk(inc, base, texts, depth + 1, in_match)


def effective(main=None):
    """Valor global de cada opción (la clave en minúsculas): {opción: (valor, fichero)}."""
    main = main or SSHD_CONFIG
    out = {}
    for path, _i, kw, val, in_match in _walk(main, os.path.dirname(main), {}):
        if kw and not in_match and kw not in ("include", "match") and kw not in out:
            out[kw] = (val, path)
    return out


def plan_set(param, value, main=None):
    """Cambios para que `param value` sea el valor efectivo.

    Cambia todas las líneas globales de la opción en sshd_config y en los ficheros incluidos que
    estén dentro de su directorio (sshd_config.d); las de los bloques Match no se tocan. Si no
    estaba en ninguno, la añade en sshd_config antes del primer Match. Devuelve
    ({fichero: texto nuevo}, [{"file": ruta relativa, "old": línea anterior o None, "new": línea}]).
    """
    main = main or SSHD_CONFIG
    base = os.path.dirname(main)
    texts = {}
    lines = {}
    changes = []
    new_line = param + " " + value
    key = param.lower()
    for path, i, kw, _val, in_match in list(_walk(main, base, texts)):
        if kw != key or in_match or not _inside(path, base):
            continue
        file_lines = lines.setdefault(path, texts[path].splitlines())
        old = file_lines[i]
        if old.strip() != new_line:
            file_lines[i] = new_line
            changes.append({"file": os.path.relpath(path, base), "old": old, "new": new_line})
    if not any(kw == key and not in_match for _p, _i, kw, _v, in_match in _walk(main, base, texts)):
        file_lines = lines.setdefault(main, (texts.get(main) or "").splitlines())
        at = next((n for n, ln in enumerate(file_lines) if _split(ln)[0] == "match"), len(file_lines))
        file_lines.insert(at, new_line)
        changes.append({"file": os.path.relpath(main, base), "old": None, "new": new_line})
    new_texts = {}
    for path, file_lines in lines.items():
        text = "\n".join(file_lines) + "\n"
        if text != texts.get(path):
            new_texts[path] = text
    return new_texts, changes


def plan_undo(changes, main=None):
    """Textos que deshacen `changes` (de plan_set): cada línea nueva vuelve a la anterior o se quita."""
    main = main or SSHD_CONFIG
    base = os.path.dirname(main)
    lines = {}
    for ch in changes:
        path = os.path.normpath(os.path.join(base, ch["file"]))
        if not _inside(path, base):
            continue
        if path not in lines:
            try:
                with open(path) as f:
                    lines[path] = f.read().splitlines()
            except OSError:
                continue
        file_lines = lines[path]
        idx = next((n for n, ln in enumerate(file_lines) if ln.strip() == ch["new"]), None)
        if idx is None:
            continue
        if ch["old"] is None:
            del file_lines[idx]
        else:
            file_lines[idx] = ch["old"]
    return {p: "\n".join(ls) + "\n" for p, ls in lines.items()}


def _inside(path, base):
    path, base = os.path.normpath(path), os.path.normpath(base)
    return path == base or path.startswith(base + os.sep)
