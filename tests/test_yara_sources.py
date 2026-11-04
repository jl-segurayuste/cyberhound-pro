"""Fuentes de reglas YARA: fijadas a un commit (antes, rama principal y ficheros que daban 404)."""
import re

from cyberhound.api.common import YARA_SOURCES


def test_fuentes_fijadas_a_un_commit():
    for source, entries in YARA_SOURCES.items():
        assert entries, source
        for url, filename in entries:
            assert url.startswith("https://raw.githubusercontent.com/")
            assert re.search(r"/[0-9a-f]{40}/", url), f"{url} no está fijada a un commit"
            assert filename.endswith(".yar") and "/" not in filename


def test_nombres_de_fichero_unicos():
    names = [n for entries in YARA_SOURCES.values() for _, n in entries]
    assert len(names) == len(set(names))
