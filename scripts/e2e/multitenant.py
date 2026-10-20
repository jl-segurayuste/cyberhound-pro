"""Multi-tenant en el navegador: superadmin crea/cambia/da de baja; un tenant no ve nada de la plataforma."""
import json, sys
from pathlib import Path
from playwright.sync_api import sync_playwright

import os
BASE = os.environ.get("CH_E2E_BASE", "https://127.0.0.1:18443")
PASSWORD = os.environ.get("CH_E2E_PASSWORD", "e2e-clave-demo")
CHROME = os.environ.get("CH_E2E_CHROME") or None   # vacío = el Chromium de Playwright
fake = Path(sys.argv[1]).read_text()
PANELS = ["dashboard", "network", "subenum", "dnssec", "intel", "audit", "malware", "docker", "code",
          "services", "tls", "webhdr", "webexp", "apisec", "nuclei", "history", "monitor", "reports", "settings"]
R = {"errores": []}

def watch(pg, who):
    pg.on("response", lambda r: r.status in (401, 403, 500) and "/api/" in r.url and
          R["errores"].append(f"{who}: {r.status} {r.request.method} {r.url.replace(BASE, '')}"))
    pg.on("pageerror", lambda e: R["errores"].append(f"{who}: js {e}"))
    pg.on("dialog", lambda d: d.accept())

def login(ctx, user, pw, tenant=""):
    pg = ctx.new_page(); watch(pg, user + "@" + (tenant or "plataforma"))
    pg.goto(f"{BASE}/login"); pg.fill("input[name=tenant]", tenant); pg.fill("input[name=username]", user)
    pg.fill("input[type=password]", pw); pg.keyboard.press("Enter"); pg.wait_for_load_state("networkidle")
    pg.wait_for_timeout(1200)
    return pg

with sync_playwright() as p:
    b = p.chromium.launch(executable_path=CHROME)
    # 1) superadmin crea la organización desde la UI
    ctx = b.new_context(ignore_https_errors=True); ctx.add_init_script(fake)
    sa = login(ctx, "admin", PASSWORD)
    sa.evaluate("showPanel('settings')"); sa.wait_for_timeout(500)
    R["sa_tab_orgs_visible"] = sa.locator('[data-cfg="tenants"]').is_visible()
    sa.locator('[data-cfg="tenants"]').click(); sa.wait_for_timeout(400)
    for sel, v in (("#tenant-slug", "acme-demo"), ("#tenant-name", "ACME Demo S.L."), ("#tenant-email", "seguridad@ejemplo-demo.es"),
                   ("#tenant-admin-user", "jefa"), ("#tenant-admin-pass", "clave-demo-1234")):
        sa.fill(sel, v)
    sa.locator("#cfg-tenants button", has_text="Crear").click(); sa.wait_for_timeout(1000)
    R["crear_msg"] = sa.locator("#tenant-msg").inner_text()[:60]
    R["tabla"] = sa.locator("#tenants-tbody tr").count()
    R["selector"] = sa.evaluate("[...document.querySelectorAll('#tenant-switch option')].map(o => o.textContent)")
    # cambiar a la organización con el selector
    sa.select_option("#tenant-switch", "acme-demo"); sa.wait_for_load_state("networkidle"); sa.wait_for_timeout(1200)
    R["sa_badge_tras_cambio"] = sa.locator("#user-role-badge").inner_text()
    R["sa_historial_acme"] = sa.evaluate("fetch('/api/history').then(r => r.json()).then(h => h.length)")
    sa.select_option("#tenant-switch", "default"); sa.wait_for_load_state("networkidle"); sa.wait_for_timeout(1000)
    R["sa_historial_default"] = sa.evaluate("fetch('/api/history').then(r => r.json()).then(h => h.length)")
    # 2) la admin del tenant
    ctx2 = b.new_context(ignore_https_errors=True); ctx2.add_init_script(fake)
    t = login(ctx2, "jefa", "clave-demo-1234", "acme-demo")
    R["tenant_url"] = t.url.replace(BASE, "")
    R["tenant_badge"] = t.locator("#user-role-badge").inner_text()
    R["nav_visibles"] = t.evaluate("[...document.querySelectorAll('.nav-tab')].filter(e => !e.hidden && !e.closest('[hidden]')).map(e => e.dataset.panel)")
    R["grupo_sistema_oculto"] = t.evaluate("[...document.querySelectorAll('.nav-group')].find(g => g.textContent.includes('Sistema')).hidden")
    t.evaluate("showPanel('settings')"); t.wait_for_timeout(700)
    R["tabs_visibles"] = t.evaluate("[...document.querySelectorAll('#panel-settings .cfg-tab')].filter(e => !e.hidden).map(e => e.dataset.cfg)")
    R["tab_activa"] = t.evaluate("document.querySelector('#panel-settings .cfg-tab.active')?.dataset.cfg")
    t.locator('[data-cfg="agents"]').click(); t.wait_for_timeout(700)
    R["clave_agente_visible"] = t.locator("#tenant-agent-key-card").is_visible() and len(t.locator("#tenant-agent-key").inner_text()) > 20
    R["modo_agente_oculto"] = not t.locator("#agent-mode-card").is_visible()
    R["selector_oculto_tenant"] = not t.locator("#tenant-switch").is_visible()
    # recorrer todos los paneles y pulsar todo lo visible y no bloqueado
    clicked = 0
    for name in PANELS:
        t.evaluate(f"showPanel('{name}')"); t.wait_for_timeout(400)
        active = t.evaluate("document.querySelector('.panel.active').id")
        if name in ("audit", "malware", "docker", "code", "services", "monitor"):
            assert active == "panel-dashboard", (name, active)
            continue
        n = t.evaluate(f"""() => {{ const els=[...document.querySelectorAll('#panel-{name} button, #panel-{name} summary')]
              .filter(e => e.offsetParent && !e.disabled && !e.closest('[hidden]'));
              els.forEach((e,i)=>e.setAttribute('data-mt', i)); return els.length; }}""")
        for i in range(n):
            el = t.locator(f'#panel-{name} [data-mt="{i}"]')
            if el.count() and el.first.is_visible():
                txt = el.first.inner_text()[:20]
                if "Salir" in txt: continue
                try: el.first.click(timeout=2000); clicked += 1
                except Exception: pass
                t.wait_for_timeout(150); t.keyboard.press("Escape"); t.evaluate("window.closeDrawer && closeDrawer()")
                if t.evaluate("document.querySelector('.panel.active').id") != f"panel-{name}":
                    t.evaluate(f"showPanel('{name}')")
    R["tenant_clicados"] = clicked
    # 3) baja desde la UI
    sa.evaluate("showPanel('settings')"); sa.locator('[data-cfg="tenants"]').click(); sa.wait_for_timeout(500)
    sa.locator("#tenants-tbody button", has_text="Dar de baja").first.click(); sa.wait_for_timeout(1200)
    R["tabla_tras_baja"] = sa.locator("#tenants-tbody").inner_text()[:40]
    R["tenant_tras_baja"] = t.evaluate("fetch('/api/history').then(r => r.status)")
    b.close()
# los 401 del tenant tras la baja son lo esperado
R["errores"] = [e for e in R["errores"] if not ("jefa" in e and "401" in e)]
print(json.dumps(R, indent=1, ensure_ascii=False))
esperado = {
    "sa_tab_orgs_visible": True, "tabla": 1, "tenant_url": "/", "grupo_sistema_oculto": True,
    "tab_activa": "users", "clave_agente_visible": True, "modo_agente_oculto": True,
    "selector_oculto_tenant": True, "sa_historial_acme": 0, "tenant_tras_baja": 401,
}
fallos = [f"{k}: {R.get(k)!r} (esperado {v!r})" for k, v in esperado.items() if R.get(k) != v] + R["errores"]
if set(R["nav_visibles"]) & {"audit", "malware", "docker", "code", "services", "monitor"}:
    fallos.append(f"el tenant ve paneles del servidor: {R['nav_visibles']}")
if set(R["tabs_visibles"]) != {"users", "suppressions", "2fa", "agents", "ldap"}:
    fallos.append(f"pestañas del tenant: {R['tabs_visibles']}")
if not R["sa_historial_default"]:
    fallos.append("el superadmin no ve los datos de la plataforma")
print(f"multi-tenant: {len(fallos)} fallos"); [print("  FALLO", f) for f in fallos]
sys.exit(1 if fallos else 0)
