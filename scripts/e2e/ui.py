"""Batería A: interfaz. Cada panel en 3 viewports (scroll, desbordamiento) + clic en cada control."""
import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

import os
BASE = os.environ.get("CH_E2E_BASE", "https://127.0.0.1:18443")
PASSWORD = os.environ.get("CH_E2E_PASSWORD", "e2e-clave-demo")
CHROME = os.environ.get("CH_E2E_CHROME") or None   # vacío = el Chromium de Playwright

fake = Path(sys.argv[1]).read_text()
out = Path(sys.argv[2])
PANELS = ["dashboard", "network", "subenum", "dnssec", "intel", "audit", "malware", "docker", "code",
          "services", "tls", "webhdr", "webexp", "apisec", "nuclei", "history", "monitor", "reports", "settings"]
VIEWPORTS = {"escritorio": (1440, 900), "tablet": (1024, 768), "movil": (390, 844)}
# Acciones que tocarían el sistema real: se responden con un stub
BLOCK = ("/api/fix/", "/api/rollback/local", "/api/ansible/run", "/api/license/activate", "/api/yara/update")
SKIP_TEXT = {"Salir"}
PREFILL = {"net-networks": "10.10.0.0/24", "subenum-domains": "ejemplo-demo.es", "dnssec-domains": "ejemplo-demo.es",
           "code-path": "/srv/demo-app", "tls-targets": "www.ejemplo-demo.es", "webhdr-urls": "https://www.ejemplo-demo.es",
           "webexp-urls": "https://www.ejemplo-demo.es", "apisec-urls": "https://api.ejemplo-demo.es",
           "nuclei-urls": "https://intranet.ejemplo-demo.es", "token-name": "barrido", "sched-name": "Barrido",
           "sched-targets": "https://www.ejemplo-demo.es"}  # logout se prueba aparte

issues = []
stats = {"por_panel": {}, "paneles": 0, "controles_clicados": 0, "dialogos": [], "stubs": []}


def issue(kind, where, detail):
    issues.append({"tipo": kind, "donde": where, "detalle": detail})


def attach(pg, where_ref):
    pg.on("pageerror", lambda e: issue("js_error", where_ref[0], str(e)))
    pg.on("console", lambda m: m.type == "error" and issue("console_error", where_ref[0], m.text))
    pg.on("response", lambda r: r.status >= 400 and "/api/" in r.url
          and issue(f"http_{r.status}", where_ref[0], f"{r.request.method} {r.url.replace(BASE, '')}"))
    pg.on("requestfailed", lambda r: issue("request_failed", where_ref[0], f"{r.method} {r.url}"))

    def on_dialog(d):
        stats["dialogos"].append(f"{where_ref[0]}: {d.type}: {d.message[:80]}")
        d.dismiss()
    pg.on("dialog", on_dialog)


def stub(route):
    stats["stubs"].append(route.request.url.replace(BASE, ""))
    route.fulfill(status=200, content_type="application/json", body=json.dumps({"ok": True, "stub": True}))


with sync_playwright() as p:
    b = p.chromium.launch(executable_path=CHROME)
    ctx = b.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 900}, color_scheme="dark",
                        accept_downloads=True)
    for pat in BLOCK:
        ctx.route(f"**{pat}**", stub)
    where = ["login"]
    pg = ctx.new_page(); attach(pg, where)
    pg.goto(f"{BASE}/login")
    pg.fill("input[name=username], #username", "admin"); pg.fill("input[type=password]", PASSWORD)
    pg.keyboard.press("Enter"); pg.wait_for_load_state("networkidle")
    if "/login" in pg.url:
        issue("login", "login", "no se pudo iniciar sesión"); print(json.dumps(issues, indent=1)); sys.exit(1)

    # 1) Navegación real por el menú (clics, no showPanel)
    where[0] = "nav"
    for name in PANELS:
        tab = pg.locator(f'.nav-tab[data-panel="{name}"]')
        grp = tab.locator("xpath=ancestor::details[1]")
        if grp.count():
            grp.locator("summary").click()
        tab.click(); pg.wait_for_timeout(400)
        if not pg.locator(f"#panel-{name}.active").count():
            issue("nav", name, "el clic en el menú no activó el panel")

    # 2) Cada panel en cada viewport: scroll completo y desbordamiento horizontal
    for vp, (w, h) in VIEWPORTS.items():
        pg.set_viewport_size({"width": w, "height": h})
        for name in PANELS:
            where[0] = f"{vp}/{name}"
            pg.evaluate(f"showPanel('{name}')"); pg.wait_for_timeout(700)
            m = pg.evaluate("""() => {
                const de = document.documentElement;
                const over = [...document.querySelectorAll('#panel-%s *')].filter(e => {
                    const r = e.getBoundingClientRect(); return r.width && r.right > innerWidth + 1 &&
                      !e.closest('.table-area,[style*="overflow"],pre,code,.drawer');
                }).slice(0, 3).map(e => e.tagName + (e.id ? '#' + e.id : '') + '.' + (e.className || '').toString().split(' ')[0]);
                return {sw: de.scrollWidth, iw: innerWidth, sh: de.scrollHeight, over};
            }""" % name)
            if m["sw"] > m["iw"] + 1:
                issue("scroll_horizontal", where[0], f"scrollWidth {m['sw']} > {m['iw']}; elementos: {m['over']}")
            pg.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)"); pg.wait_for_timeout(150)
            y = pg.evaluate("scrollY")
            if m["sh"] > h + 5 and y == 0:
                issue("scroll_vertical", where[0], "la página no hace scroll aunque el contenido es más alto")
            pg.evaluate("window.scrollTo(0,0)")
            stats["paneles"] += 1
        if vp == "movil":
            where[0] = "movil/hamburguesa"
            pg.evaluate("showPanel('dashboard')")
            pg.locator("#nav-toggle").click(); pg.wait_for_timeout(300)
            if not pg.locator("#top-nav").is_visible():
                issue("nav_movil", where[0], "el botón ☰ no muestra el menú")
            hdr = pg.evaluate("""() => [...document.querySelectorAll('header button, header a, .topbar button')]
                .filter(e => e.offsetParent).map(e => e.getBoundingClientRect()).map(r => Math.round(r.top))""")
            if hdr and max(hdr) - min(hdr) > 40:
                issue("layout_movil", "movil/cabecera", f"botones de cabecera repartidos en varias filas (tops {sorted(set(hdr))})")

    # 3) Clic en cada control de cada panel (con WS simulado: no lanza escaneos reales)
    pg.close()
    ctx.add_init_script(fake)
    for name in PANELS:
        where[0] = f"clic/{name}"
        pg = ctx.new_page(); attach(pg, where)
        pg.goto(f"{BASE}/"); pg.wait_for_load_state("networkidle"); pg.wait_for_timeout(800)
        pg.evaluate(f"showPanel('{name}')"); pg.wait_for_timeout(600)
        pg.evaluate("p => Object.entries(p).forEach(([i, v]) => { const e = document.getElementById(i); if (e) e.value = v; })", PREFILL)
        # Ajustes: recorrer también cada subpestaña
        groups = [None]
        if name == "settings":
            # solo las pestañas que el usuario puede ver (p. ej. Organizaciones solo existe en multi-tenant)
            groups = pg.evaluate("""() => [...document.querySelectorAll('#panel-settings .cfg-tab')]
                .map((e, i) => e.hidden ? -1 : i).filter(i => i >= 0)""") or [None]
        for gi in groups:
            if gi is not None:
                pg.evaluate(f"document.querySelectorAll('#panel-settings .cfg-tab')[{gi}].click()")
                pg.wait_for_timeout(500)
            for _round in range(3):
                n = pg.evaluate(f"""() => {{
                    const sel = '#panel-{name} button, #panel-{name} [data-on-click], #panel-{name} [data-on-change], #panel-{name} summary, #panel-{name} select, #panel-{name} tbody tr';
                    const els = [...document.querySelectorAll(sel)]
                      .filter(e => e.offsetParent !== null && !e.disabled && !e.classList.contains('cfg-tab') && !e.dataset.done);
                    els.slice(0, 80).forEach((e, i) => e.setAttribute('data-bat', '{gi}-{_round}-' + i)); return Math.min(els.length, 80); }}""")
                if not n:
                    break
                for i in range(n):
                    el = pg.locator(f'#panel-{name} [data-bat="{gi}-{_round}-{i}"]')
                    if not el.count() or not el.first.is_visible():
                        continue
                    el.first.evaluate("e => e.dataset.done = '1'")
                    label = (el.first.inner_text() or el.first.get_attribute("data-on-click") or "")[:40].strip().split(chr(10))[0]
                    if label in SKIP_TEXT:
                        continue
                    where[0] = f"clic/{name}/{label or i}"
                    try:
                        tag = el.first.evaluate("e => e.tagName")
                        if tag == "SELECT":
                            opts = el.first.locator("option").all()
                            if len(opts) > 1:
                                el.first.select_option(index=len(opts) - 1)
                        else:
                            el.first.click(timeout=2500)
                        stats["controles_clicados"] += 1
                        stats["por_panel"][name] = stats["por_panel"].get(name, 0) + 1
                    except Exception as e:
                        issue("clic_fallido", where[0], str(e).split(chr(10))[0][:160])
                    pg.wait_for_timeout(300)
                    pg.keyboard.press("Escape")
                    pg.evaluate("window.closeDrawer && closeDrawer()")
                    if not pg.locator(f"#panel-{name}.active").count():
                        issue("clic_cambia_panel", where[0], "el control saca del panel (puede ser intencionado)")
                        pg.evaluate(f"showPanel('{name}')"); pg.wait_for_timeout(300)
                    if gi is not None and not pg.locator(f"#panel-settings .cfg-tab.active[data-cfg]").nth(0).count():
                        pass
        pg.close()

    # 4) Cabecera: búsqueda global, Log, API, atajos
    where[0] = "cabecera"
    pg = ctx.new_page(); attach(pg, where)
    pg.goto(f"{BASE}/"); pg.wait_for_load_state("networkidle")
    pg.fill("#global-search", "ssh"); pg.keyboard.press("Enter"); pg.wait_for_timeout(800)
    for txt in ("Log", "API"):
        try:
            with ctx.expect_page(timeout=2500) as newp:
                pg.locator(f"header >> text={txt}").first.click()
            np_ = newp.value; np_.wait_for_load_state();
            if txt == "API" and "docs" not in np_.url:
                issue("cabecera", "API", f"abre {np_.url}")
            np_.close()
        except Exception:
            pass  # Log abre un panel en la misma página
        pg.wait_for_timeout(300)
    where[0] = "logout"
    pg.locator("text=Salir").first.click(); pg.wait_for_timeout(800)
    r = pg.request.get(f"{BASE}/api/dashboard", max_redirects=0)
    if r.status not in (302, 401):
        issue("logout", "Salir", f"tras salir /api/dashboard devuelve {r.status}")
    b.close()

# deduplicar
seen, uniq = set(), []
for i in issues:
    k = (i["tipo"], i["donde"], i["detalle"])
    if k not in seen:
        seen.add(k); uniq.append(i)

# Lo que es correcto que pase al pulsarlo todo con datos de demo (sin API keys, sin SBOM…)
EXPECTED = (
    ("http_400", "/api/intel/scan"),            # sin API keys de threat intel: error claro
    ("http_400", "PATCH /api/users/admin"),     # el admin no puede quitarse su propio rol
    ("http_404", "/api/sbom/latest"),           # aún no se ha generado ningún SBOM
    ("clic_fallido", "✓ Listo"),                # botón ya desactivado tras aplicar el fix
    ("http_400", "/api/me/password"),           # cambiar contraseña con el formulario vacío
    ("http_400", "/api/config/ssh-credentials"),  # guardar una credencial SSH sin nombre
)


def is_expected(i):
    if i["tipo"] in ("clic_cambia_panel", "layout_movil"):   # navegación intencionada / detector aproximado
        return True
    return any(i["tipo"] == t and (d in i["detalle"] or d in i["donde"]) for t, d in EXPECTED)


# El error de consola que el navegador escribe por cada 4xx esperada tampoco es un fallo
ok_places = {(i["donde"], i["tipo"][-3:]) for i in uniq if i["tipo"].startswith("http_") and is_expected(i)}
uniq_ok = [i for i in uniq if i["tipo"] == "console_error"
           and any(d == i["donde"] and f"status of {code}" in i["detalle"] for d, code in ok_places)]
bad = [i for i in uniq if not is_expected(i) and i not in uniq_ok]
(out / "ui.json").write_text(json.dumps({"stats": stats, "issues": uniq, "fallos": bad}, indent=1, ensure_ascii=False))
print(f"interfaz: {stats['paneles']} paneles×viewport, {stats['controles_clicados']} controles pulsados, "
      f"{len(uniq) - len(bad)} incidencias esperadas, {len(bad)} fallos")
for i in bad:
    print("  FALLO", i)
sys.exit(1 if bad else 0)
