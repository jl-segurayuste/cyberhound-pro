"""Regenera las capturas del README (docs/img/capturas/) sobre instancias de demo con datos ficticios.

Levanta una instancia normal y otra multi-tenant en 127.0.0.1 (carpeta temporal, historial de
`seed.py`) y las recorre con Chrome sin interfaz. Los análisis los responde el WebSocket simulado de
`fakews.js`: no se lanza ninguno real.

    CH_PYTHON=.venv/bin/python /ruta/venv-playwright/bin/python scripts/e2e/capturas.py
"""
from __future__ import annotations

import os
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
OUT = REPO / "docs" / "img" / "capturas"
CH_PYTHON = os.environ.get("CH_PYTHON", sys.executable)
CHROME = os.environ.get("CH_E2E_CHROME") or None
PORT = int(os.environ.get("CH_E2E_PORT", "18443"))
PASSWORD = "demo-" + secrets.token_hex(6)
FAKE_WS = (HERE / "fakews.js").read_text()

PREFILL = {"net-networks": "10.10.0.0/24", "subenum-domains": "ejemplo-demo.es", "dnssec-domains": "ejemplo-demo.es",
           "code-path": "/srv/demo-app", "tls-targets": "www.ejemplo-demo.es", "webhdr-urls": "https://www.ejemplo-demo.es",
           "webexp-urls": "https://www.ejemplo-demo.es", "apisec-urls": "https://api.ejemplo-demo.es",
           "nuclei-urls": "https://intranet.ejemplo-demo.es"}
# Panel -> botón que lanza su análisis (None: solo se muestra el panel)
PANELS = {"dashboard": None, "network": "btn-network", "subenum": "btn-subenum", "dnssec": "btn-dnssec",
          "intel": None, "audit": "btn-audit", "malware": "btn-malware", "docker": "btn-docker", "code": "btn-code",
          "services": "btn-services", "tls": "btn-tls", "webhdr": "btn-webhdr", "webexp": "btn-webexp",
          "apisec": "btn-apisec", "nuclei": "btn-nuclei", "history": None, "monitor": None, "reports": None,
          "settings": None}
CONFIG_EDIT = """
import sys, yaml
d, mt = sys.argv[1], sys.argv[2] == "true"
c = yaml.safe_load(open(f"{d}/config.yaml"))
c["server"]["log_dir"] = d
c["db_path"] = f"{d}/cyberhound.db"
c["multi_tenant"] = {"enabled": mt}
yaml.safe_dump(c, open(f"{d}/config.yaml", "w"))
"""


def instance(work: Path, name: str, port: int, multi_tenant: bool) -> subprocess.Popen:
    d = work / name
    d.mkdir()
    env = {**os.environ, "CH_DATA_DIR": str(d)}
    subprocess.run([CH_PYTHON, "-m", "cyberhound", "setup", "--config", f"{d}/config.yaml", "--password-stdin",
                    "--username", "admin", "--host", "127.0.0.1", "--port", str(port)],
                   input=PASSWORD + "\n", text=True, env=env, check=True, capture_output=True)
    subprocess.run([CH_PYTHON, "-c", CONFIG_EDIT, str(d), str(multi_tenant).lower()], check=True)
    subprocess.run([CH_PYTHON, str(HERE / "seed.py"), f"{d}/cyberhound.db"], cwd=REPO, env=env, check=True,
                   capture_output=True)
    log = open(d / "web.log", "w")
    proc = subprocess.Popen([CH_PYTHON, "-m", "cyberhound", "web", "--config", f"{d}/config.yaml"], cwd=d,
                            env={**env, "CH_TLS_DIR": f"{d}/tls"}, stdout=log, stderr=subprocess.STDOUT)
    ctx = ssl._create_unverified_context()
    for _ in range(60):
        try:
            urllib.request.urlopen(f"https://127.0.0.1:{port}/health", context=ctx, timeout=2)
            return proc
        except OSError:
            time.sleep(0.5)
    proc.terminate()
    raise SystemExit(f"la instancia {name} no arranca:\n{(d / 'web.log').read_text()[-2000:]}")


def login(ctx, base: str, tenant: str | None = None):
    pg = ctx.new_page()
    pg.goto(f"{base}/login")
    if tenant:
        pg.fill("input[name=tenant]", tenant)
    pg.fill("input[name=username], #username", "admin")
    pg.fill("input[type=password]", PASSWORD)
    pg.keyboard.press("Enter")
    pg.wait_for_load_state("networkidle")
    pg.wait_for_timeout(1000)
    return pg


def shot(pg, name: str, **kw) -> None:
    pg.screenshot(path=str(OUT / f"{name}.png"), **kw)
    print("ok", name)


def main() -> None:
    work = Path(tempfile.mkdtemp(prefix="ch-capturas-"))
    procs = [instance(work, "plataforma", PORT, False), instance(work, "multitenant", PORT + 1, True)]
    base, mt_base = f"https://127.0.0.1:{PORT}", f"https://127.0.0.1:{PORT + 1}"
    try:
        with sync_playwright() as p:
            b = p.chromium.launch(executable_path=CHROME) if CHROME else p.chromium.launch(channel="chrome")
            opts = {"ignore_https_errors": True, "color_scheme": "dark", "locale": "es-ES"}

            ctx = b.new_context(viewport={"width": 1440, "height": 900}, **opts)
            ctx.add_init_script(FAKE_WS)
            pg = ctx.new_page()
            pg.goto(f"{base}/login")
            pg.wait_for_timeout(500)
            shot(pg, "login")
            pg.close()
            login(ctx, base).close()

            def fresh():
                # Página nueva por sección: el panel de actividad no arrastra los análisis anteriores
                page = ctx.new_page()
                page.goto(f"{base}/")
                page.wait_for_load_state("networkidle")
                page.wait_for_timeout(800)
                return page

            for panel, button in PANELS.items():
                pg = fresh()
                pg.evaluate(f"showPanel('{panel}')")
                pg.wait_for_timeout(800)
                if button:
                    pg.evaluate("p => Object.entries(p).forEach(([i, v]) => { const e = document.getElementById(i);"
                                " if (e) e.value = v; })", PREFILL)
                    pg.click(f"#{button}")
                    pg.wait_for_timeout(2000)
                pg.evaluate("window.scrollTo(0, 0)")
                shot(pg, panel, full_page=panel in ("dashboard", "network", "history", "monitor", "reports"))
                pg.close()
            # Menú desplegado (grupo Sistema) sobre el inicio
            pg = fresh()
            pg.locator('.nav-tab[data-panel="audit"]').locator("xpath=ancestor::details[1]").locator("summary").click()
            pg.wait_for_timeout(400)
            shot(pg, "menu", clip={"x": 0, "y": 0, "width": 1440, "height": 360})

            mob = b.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=1,
                                storage_state=ctx.storage_state(), **opts)
            mob.add_init_script(FAKE_WS)
            mp = mob.new_page()
            mp.goto(f"{base}/")
            mp.wait_for_load_state("networkidle")
            mp.wait_for_timeout(1200)
            shot(mp, "movil")

            mt = b.new_context(viewport={"width": 1440, "height": 900}, **opts)
            mt.add_init_script(FAKE_WS)
            pg = mt.new_page()
            pg.goto(f"{mt_base}/login")
            pg.wait_for_timeout(500)
            shot(pg, "login-organizacion")
            pg.close()
            pg = login(mt, mt_base)
            pg.evaluate("showPanel('settings')")
            pg.wait_for_timeout(500)
            pg.locator('[data-cfg="tenants"]').click()
            pg.wait_for_timeout(400)
            for slug, nombre, admin in (("acme-demo", "ACME Demo S.L.", "jefa"), ("talleres-demo", "Talleres Demo", "taller")):
                for sel, v in (("#tenant-slug", slug), ("#tenant-name", nombre), ("#tenant-email", "seguridad@ejemplo-demo.es"),
                               ("#tenant-admin-user", admin), ("#tenant-admin-pass", "clave-demo-" + secrets.token_hex(4))):
                    pg.fill(sel, v)
                pg.locator("#cfg-tenants button", has_text="Crear").click()
                pg.wait_for_timeout(1000)
            for sel in ("#tenant-slug", "#tenant-name", "#tenant-email", "#tenant-admin-user", "#tenant-admin-pass"):
                pg.fill(sel, "")
            pg.evaluate("document.querySelectorAll('#tenant-msg').forEach(e => e.textContent = '');"
                        " document.activeElement && document.activeElement.blur()")
            pg.evaluate("window.scrollTo(0, 0)")
            shot(pg, "organizaciones")
            b.close()
        # El manual de uso enseña el inicio y el menú con otro nombre
        shutil.copy(OUT / "dashboard.png", OUT.parent / "interfaz.png")
        shutil.copy(OUT / "menu.png", OUT.parent / "interfaz-navegacion.png")
    finally:
        for proc in procs:
            proc.terminate()
            proc.wait(timeout=10)


if __name__ == "__main__":
    main()
