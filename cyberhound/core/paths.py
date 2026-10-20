"""Directorio de datos persistentes: configuración, BD, licencia, cuarentena, reglas YARA y cachés.

CH_DATA_DIR lo fija (en la imagen Docker es /data, el volumen); si no, ~/.cyberhound. Antes cada
módulo usaba ~/.cyberhound por su cuenta y en Docker la licencia activada, la cuarentena y las reglas
YARA quedaban fuera del volumen: se perdían al recrear el contenedor.
"""
from __future__ import annotations

import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("CH_DATA_DIR") or Path.home() / ".cyberhound")
YARA_DIR = DATA_DIR / "yara"
