"""Por rol: ningún 403 al navegar y pulsar, y lo no permitido aparece bloqueado."""
import json
from pathlib import Path
import sys
from playwright.sync_api import sync_playwright

import os
BASE = os.environ.get("CH_E2E_BASE", "https://127.0.0.1:18443")
PASSWORD = os.environ.get("CH_E2E_PASSWORD", "e2e-clave-demo")
CHROME = os.environ.get("CH_E2E_CHROME") or None   # vacío = el Chromium de Playwright
fake = Path(sys.argv[1]).read_text()
PANELS = ["dashboard", "network", "subenum", "dnssec", "intel", "audit", "malware", "docker", "code",
          "services", "tls", "webhdr", "webexp", "apisec", "nuclei", "history", "monitor", "reports", "settings"]
out = {}
with sync_playwright() as p:
    b = p.chromium.launch(executable_path=CHROME)
    adm = b.new_context(ignore_https_errors=True).new_page()
    adm.goto(f"{BASE}/login"); adm.fill("input[name=username]", "admin"); adm.fill("input[type=password]", PASSWORD)
    adm.keyboard.press("Enter"); adm.wait_for_load_state("networkidle")
    for u, role in (("lectora", "viewer"), ("operario", "operator")):
        adm.evaluate("([u, r]) => fetch('/api/users', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username:u, password:'clave-rol-1234', role:r})}).then(r=>r.status)", [u, role])
    for u, role in (("lectora", "viewer"), ("operario", "operator")):
        ctx = b.new_context(ignore_https_errors=True); ctx.add_init_script(fake)
        pg = ctx.new_page(); bad = []
        pg.on("response", lambda r: r.status == 403 and bad.append(f"403 {r.request.method} {r.url.replace(BASE,'')}"))
        pg.on("pageerror", lambda e: bad.append(f"js {e}"))
        pg.goto(f"{BASE}/login"); pg.fill("input[name=username]", u); pg.fill("input[type=password]", "clave-rol-1234")
        pg.keyboard.press("Enter"); pg.wait_for_load_state("networkidle"); pg.wait_for_timeout(800)
        res = {"role": pg.evaluate("USER.role"), "locked": {}, "clicked": 0}
        for name in PANELS:
            pg.evaluate(f"showPanel('{name}')"); pg.wait_for_timeout(500)
            res["locked"][name] = pg.evaluate(f"document.querySelectorAll('#panel-{name} .role-locked').length")
            # pulsar lo bloqueado: debe dar toast, no petición
            n = pg.evaluate(f"""() => {{ const els=[...document.querySelectorAll('#panel-{name} .role-locked')].filter(e=>e.offsetParent);
                 els.forEach(e => e.removeAttribute('disabled')); els.forEach(e => e.click()); return els.length; }}""")
            res["clicked"] += n; pg.wait_for_timeout(300)
        res["users_tab_hidden"] = pg.evaluate("document.querySelector('[data-cfg=\"users\"]').hidden")
        res["errores"] = bad
        out[u] = res
        ctx.close()
    b.close()
print(json.dumps(out, indent=1, ensure_ascii=False))
fallos = [f"{u}: {e}" for u, r in out.items() for e in r["errores"]]
if not sum(out["lectora"]["locked"].values()):
    fallos.append("viewer: no hay ningún control bloqueado")
if any(n for p, n in out["operario"]["locked"].items() if p != "settings"):
    fallos.append("operator: controles bloqueados fuera de Ajustes")
fallos += [f"{u}: la pestaña Usuarios se ve" for u, r in out.items() if not r["users_tab_hidden"]]
print(f"roles: {len(fallos)} fallos"); [print("  FALLO", f) for f in fallos]
sys.exit(1 if fallos else 0)
