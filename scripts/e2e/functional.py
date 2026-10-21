"""Batería B: funcional contra el backend real (análisis reales sobre objetivos controlados + toda la API)."""
import base64
import hashlib
import hmac
import json
import struct
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

import os
BASE = os.environ.get("CH_E2E_BASE", "https://127.0.0.1:18443")
PASSWORD = os.environ.get("CH_E2E_PASSWORD", "e2e-clave-demo")
CHROME = os.environ.get("CH_E2E_CHROME") or None   # vacío = el Chromium de Playwright

T = Path(sys.argv[1])          # objetivos controlados (targets.py)
OUT = Path(sys.argv[2])
WEB = os.environ.get("CH_E2E_WEB", "http://127.0.0.1:18080")
results = []


def check(name, ok, detail=""):
    results.append({"prueba": name, "ok": bool(ok), "detalle": str(detail)[:300]})
    print(("OK  " if ok else "FALLO ") + name + ("" if ok else f"  → {str(detail)[:200]}"), flush=True)


def totp(secret_b32, t=None):
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    c = int((t or time.time()) // 30)
    h = hmac.new(key, struct.pack(">Q", c), hashlib.sha1).digest()
    o = h[-1] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


JS_HELPERS = """
window.__api = async (method, path, body) => {
  const opt = {method, headers: {}};
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  const txt = await r.text(); let data = null; try { data = JSON.parse(txt); } catch (e) { data = txt.slice(0, 300); }
  return {status: r.status, ct: r.headers.get('content-type') || '', data};
};
window.__ws = (msg, timeoutMs) => new Promise(res => {
  const ws = new WebSocket(`wss://${location.host}/ws`); const out = {msgs: [], findings: [], done: null, error: null, devices: null};
  const t = setTimeout(() => { out.error = out.error || 'TIMEOUT'; try { ws.close(); } catch (e) {} res(out); }, timeoutMs);
  ws.onopen = () => ws.send(JSON.stringify(msg));
  ws.onmessage = ev => { const m = JSON.parse(ev.data); out.msgs.push(m.type);
    if (m.type === 'finding') out.findings.push({id: m.data.id, sev: m.data.severity, title: m.data.title});
    if (m.type === 'devices') out.devices = m.data.length;
    if (m.type === 'done') out.done = m; if (m.type === 'error') out.error = m.text; };
  ws.onclose = () => { clearTimeout(t); res(out); };
});
"""


def login(ctx, code=None):
    pg = ctx.new_page()
    pg.goto(f"{BASE}/login")
    pg.fill("input[name=username], #username", "admin"); pg.fill("input[type=password]", PASSWORD)
    pg.keyboard.press("Enter"); pg.wait_for_load_state("networkidle")
    if code is not None and pg.locator("input[name=code], #code, input[name=totp]").count():
        pg.fill("input[name=code], #code, input[name=totp]", code); pg.keyboard.press("Enter"); pg.wait_for_load_state("networkidle")
    pg.evaluate(JS_HELPERS)
    return pg


with sync_playwright() as p:
    b = p.chromium.launch(executable_path=CHROME)
    mk = lambda: b.new_context(ignore_https_errors=True)

    # ── Seguridad / autenticación ──────────────────────────────────────────
    anon = mk()
    r = anon.request.get(f"{BASE}/api/dashboard", max_redirects=0)
    check("auth: API sin sesión rechazada", r.status in (302, 401), r.status)
    r = anon.request.get(f"{BASE}/", max_redirects=0)
    check("auth: / sin sesión redirige a /login", r.status in (302, 303) and "/login" in r.headers.get("location", ""), r.status)
    r = anon.request.get(f"{BASE}/metrics", max_redirects=0)
    mt = r.text() if r.status == 200 else ""
    check("auth: /metrics sin sesión solo desde el propio host y sin datos de seguridad", r.status == 200 and not any(w in mt for w in ("score", "finding", "critical", "password", "10.")), mt[:150])
    r = anon.request.get(f"{BASE}/metrics", headers={"X-Forwarded-For": "203.0.113.5"}, max_redirects=0)
    check("auth: /metrics a través de un proxy pide sesión", r.status == 401, r.status)
    r = anon.request.get(f"{BASE}/login")
    h = r.headers
    check("cabeceras: CSP con nonce/self", "default-src 'self'" in h.get("content-security-policy", ""), h.get("content-security-policy", "")[:120])
    check("cabeceras: X-Frame-Options DENY", h.get("x-frame-options", "").upper() == "DENY", h.get("x-frame-options"))
    check("cabeceras: nosniff", h.get("x-content-type-options") == "nosniff", h.get("x-content-type-options"))
    pg = anon.new_page(); pg.goto(f"{BASE}/login")
    pg.fill("input[name=username], #username", "admin"); pg.fill("input[type=password]", "incorrecta")
    pg.keyboard.press("Enter"); pg.wait_for_load_state("networkidle")
    check("auth: contraseña errónea no entra", "/login" in pg.url, pg.url)
    r = anon.request.post(f"{BASE}/login", form={"username": "admin", "password": PASSWORD}, max_redirects=0)
    check("csrf: POST /login sin token rechazado", r.status in (400, 403) or "/login" in r.headers.get("location", "/login"), r.status)
    anon.close()

    ctx = mk()
    pg = login(ctx)
    check("auth: login correcto", "/login" not in pg.url, pg.url)
    ck = {c["name"]: c for c in ctx.cookies()}
    sess = next((c for n, c in ck.items() if n not in ("ch_csrf",)), None)
    check("cookie de sesión HttpOnly+Secure+SameSite=Strict",
          sess and sess["httpOnly"] and sess["secure"] and sess["sameSite"] == "Strict", sess)
    api = lambda m, path, body=None: pg.evaluate("([m,p,b]) => __api(m,p,b===null?undefined:b)", [m, path, body])
    ws = lambda msg, tmo=120000: pg.evaluate("([m,t]) => __ws(m,t)", [msg, tmo])

    # ── Validación de entrada por WS ───────────────────────────────────────
    r = ws({"task": "rm -rf"}, 10000)
    check("ws: tarea no permitida rechazada", r["error"] and "no permitida" in r["error"], r)
    r = ws({"task": "web_headers", "urls": ["http://a.com; id"]}, 10000)
    check("ws: inyección en URLs rechazada", bool(r["error"]), r)

    # ── Análisis reales ────────────────────────────────────────────────────
    def scan(name, msg, expect=None, tmo=180000, allow_error=False):
        r = ws(msg, tmo)
        ids = " ".join(f"{f['id']}:{f['title']}" for f in r["findings"]).lower()
        ok = (r["done"] is not None) or (allow_error and r["error"] and "Error interno" not in r["error"] and r["error"] != "TIMEOUT")
        if ok and expect:
            ok = any(e in ids for e in expect)
        check(f"análisis {name}", ok, f"done={bool(r['done'])} err={r['error']} n={len(r['findings'])} dev={r['devices']} :: {ids[:220]}")
        return r

    scan("seguridad local (hardening)", {"task": "audit"})
    scan("malware (webshell plantada)", {"task": "malware", "web_roots": [str(T / "www")], "skip": ["auditd"]}, ["webshell", "php", "eval"])
    scan("código (secretos/shell=True plantados)", {"task": "code", "path": str(T / "code")}, ["akia", "aws", "password", "secreto", "b602", "b105", "shell"])
    scan("docker (sin docker instalado)", {"task": "docker"}, allow_error=True)
    scan("servicios", {"task": "services"})
    scan("tls (cert autofirmado local)", {"task": "tls", "targets": [BASE.split("//", 1)[1]]}, ["autofirm", "self", "signed", "conf"])
    scan("cabeceras web", {"task": "web_headers", "urls": [WEB]}, ["csp", "content-security", "hsts", "x-frame"])
    scan("exposición web (.git/.env plantados)", {"task": "web_exposure", "urls": [WEB]}, [".git", ".env", "git", "env"])
    scan("api/cors", {"task": "api_security", "urls": [WEB]})
    scan("nuclei (binario no instalado)", {"task": "nuclei", "urls": [WEB]}, allow_error=True)
    scan("dns (example.com)", {"task": "dns", "domains": ["example.com"]})
    scan("subdominios (example.com)", {"task": "subdomain_enum", "domains": ["example.com"]}, tmo=240000, allow_error=True)
    rn = scan("red (127.0.0.1/32, sin SSH)", {"task": "network", "networks": "127.0.0.1/32", "ssh_audit": False})
    check("red: detecta el dispositivo", (rn["devices"] or 0) >= 1, rn["devices"])
    scan("intel (sin API keys)", {"task": "intel", "target": "8.8.8.8", "modules": []}, allow_error=True)

    # ── API REST ───────────────────────────────────────────────────────────
    five = []

    def call(name, m, path, body=None, ok_status=(200,), pred=None):
        r = api(m, path, body)
        if r["status"] >= 500:
            five.append(f"{m} {path} → {r['status']}")
        ok = r["status"] in ok_status and (pred is None or pred(r["data"]))
        check(f"api {name}", ok, f"{r['status']} {json.dumps(r['data'], ensure_ascii=False)[:200]}")
        return r["data"]

    hist = call("historial", "GET", "/api/history", pred=lambda d: isinstance(d, list) and len(d) > 0)
    sid = next((h["id"] for h in hist if h.get("scan_type") == "audit" and h.get("status") == "completed"), hist[0]["id"])
    call("detalle de scan", "GET", f"/api/history/{sid}")
    call("comparar scan", "GET", f"/api/history/{sid}/compare")
    call("historial: id inexistente → vacío", "GET", "/api/history/999999", pred=lambda d: d == [] or d.get("error"))
    call("score trend", "GET", "/api/score/trend?type=audit&days=30", pred=lambda d: isinstance(d, list))
    call("score detail", "GET", "/api/score/detail")
    call("dashboard", "GET", "/api/dashboard", pred=lambda d: "last_scans" in d and len(d.get("score_trend", [])) > 0)
    call("activos", "GET", "/api/assets", pred=lambda d: isinstance(d, list) and len(d) > 0)
    call("autorizar activo", "POST", "/api/assets/10.10.0.42/authorize", {"authorized": True, "notes": "prueba"})
    call("descubrir red", "GET", "/api/network/discover?networks=127.0.0.1/32")
    call("supresión: crear", "POST", "/api/suppressions", {"pattern": "bateria_*", "reason": "prueba"})
    call("supresión: listar", "GET", "/api/suppressions", pred=lambda d: any("bateria_" in json.dumps(x) for x in (d if isinstance(d, list) else d.get("suppressions", []))))
    call("supresión: borrar", "DELETE", "/api/suppressions/bateria_*")
    call("usuario: crear", "POST", "/api/users", {"username": "analista1", "password": "Clave-Prueba-2026!", "role": "viewer"}, ok_status=(200, 201))
    call("usuario: listar", "GET", "/api/users", pred=lambda d: "analista1" in json.dumps(d))
    call("usuario: cambiar rol", "PATCH", "/api/users/analista1", {"role": "viewer"})
    call("usuario: rol inválido rechazado", "POST", "/api/users", {"username": "x2", "password": "Clave-Prueba-2026!", "role": "root"}, ok_status=(400, 422))
    cu = mk(); pu = cu.new_page(); pu.goto(f"{BASE}/login")
    pu.fill("input[name=username], #username", "analista1"); pu.fill("input[type=password]", "Clave-Prueba-2026!")
    pu.keyboard.press("Enter"); pu.wait_for_load_state("networkidle")
    r = cu.request.get(f"{BASE}/api/dashboard", max_redirects=0)
    check("usuario creado puede iniciar sesión", r.status == 200, r.status)
    r = cu.request.post(f"{BASE}/api/config/keys", data=json.dumps({"shodan": "x"}), headers={"Content-Type": "application/json"}, max_redirects=0)
    check("rbac: viewer NO puede cambiar la configuración", r.status in (401, 403), r.status)
    r = cu.request.post(f"{BASE}/api/users", data=json.dumps({"username": "intruso", "password": "Clave-Prueba-2026!", "role": "admin"}), headers={"Content-Type": "application/json"}, max_redirects=0)
    check("rbac: viewer NO puede crear usuarios", r.status in (401, 403), r.status)
    r = cu.request.get(f"{BASE}/api/history", max_redirects=0)
    check("rbac: viewer SÍ puede ver el historial", r.status == 200, r.status)
    cu.close()
    call("admin: no puede quitarse su propio rol", "PATCH", "/api/users/admin", {"role": "viewer"}, ok_status=(400, 403))
    call("usuario: borrar", "DELETE", "/api/users/analista1")
    call("usuario inexistente → 404", "PATCH", "/api/users/no-existe", {"role": "viewer"}, ok_status=(404,))
    me = call("api/me", "GET", "/api/me", pred=lambda d: d.get("role") == "admin" and d.get("superadmin") is True)
    sch = call("scheduler: listar", "GET", "/api/scheduler")
    names = [e.get("name") for e in (sch if isinstance(sch, list) else sch.get("entries", sch.get("jobs", [])))] if sch else []
    if names:
        call(f"scheduler: desactivar {names[0]}", "POST", f"/api/scheduler/{names[0]}/toggle", {"enabled": False})
        call(f"scheduler: reactivar {names[0]}", "POST", f"/api/scheduler/{names[0]}/toggle", {"enabled": True})
    call("scheduler: tarea inexistente rechazada", "POST", "/api/scheduler/no_existe/run", ok_status=(200, 404), pred=lambda d: d.get("ok") is False or d.get("error"))
    keys = call("api keys: leer", "GET", "/api/config/keys")
    call("api keys: guardar", "POST", "/api/config/keys", {"shodan": ""})
    call("notificaciones: leer", "GET", "/api/config/notifications")
    call("notificaciones: guardar", "POST", "/api/config/notifications", {"email": {"enabled": False}})
    call("notificaciones: test sin configurar (sin 500)", "POST", "/api/config/notifications/test", {}, ok_status=(200, 400, 422))
    call("siem: leer", "GET", "/api/config/siem")
    call("siem: test sin configurar (sin 500)", "POST", "/api/config/siem/test", {}, ok_status=(200, 400, 422, 502))
    call("ticketing: leer", "GET", "/api/config/ticketing")
    call("ticketing: test sin configurar (sin 500)", "POST", "/api/config/ticketing/test", {}, ok_status=(200, 400, 422, 502))
    call("agente: leer config", "GET", "/api/config/agent")
    call("agente: listar", "GET", "/api/agent/list")
    call("agente: guardar clave (modo manager)", "POST", "/api/config/agent", {"mode": "manager", "agent_key": "clave-agente-bateria"})
    ra = b.new_context(ignore_https_errors=True)
    r = ra.request.post(f"{BASE}/api/agent/heartbeat", data=json.dumps({"agent_name": "agente-bateria"}),
                        headers={"Authorization": "AgentKey clave-agente-bateria", "Content-Type": "application/json"}, max_redirects=0)
    check("agente remoto: heartbeat con su clave aceptado", r.status == 200, f"{r.status} {r.text()[:120]}")
    r = ra.request.post(f"{BASE}/api/agent/heartbeat", data="{}", headers={"Authorization": "AgentKey mala", "Content-Type": "application/json"}, max_redirects=0)
    check("agente remoto: clave errónea rechazada", r.status in (401, 403), r.status)
    ra.close()
    call("agente: aparece en el listado", "GET", "/api/agent/list", pred=lambda d: "agente-bateria" in json.dumps(d))
    call("agente: volver a standalone", "POST", "/api/config/agent", {"mode": "standalone"})
    call("informe html", "POST", "/api/report/html", {"source": "audit"}, ok_status=(200,))
    call("informe playbook ansible", "POST", "/api/report/ansible", {"source": "audit", "findings": [{"id": "ssh_root_login", "category": "ssh", "severity": "critical", "title": "t", "description": "", "remediation": "", "auto_fix": True}]})
    call("informe formato inválido → 4xx", "POST", "/api/report/exe", {"source": "audit"}, ok_status=(400, 404, 422))
    r = pg.evaluate("""async (sid) => { const r = await fetch('/api/report/pdf', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({scan_id: sid, scan_type:'audit'})}); const b = await r.arrayBuffer();
        return {s: r.status, ct: r.headers.get('content-type'), head: String.fromCharCode(...new Uint8Array(b.slice(0,5))), n: b.byteLength}; }""", sid)
    check("informe pdf (es un PDF real)", r["s"] == 200 and r["head"] == "%PDF-", r)
    call("compliance: calcular", "POST", "/api/compliance", {"scan_id": sid, "frameworks": ["ens", "iso27001", "pci-dss", "cis"]})
    call("compliance: leer", "GET", "/api/compliance")
    q = str(T / "quar" / "sospechoso.txt")
    qd = call("cuarentena: aislar fichero", "POST", "/api/quarantine", {"filepath": q, "finding_id": "bateria", "title": "prueba"})
    check("cuarentena: el original desaparece", not Path(q).exists(), Path(q).exists())
    ql = call("cuarentena: listar", "GET", "/api/quarantine")
    items = ql if isinstance(ql, list) else (ql or {}).get("items", (ql or {}).get("files", []))
    qname = next((i.get("quarantine_name") for i in items if "sospechoso" in json.dumps(i) and not i.get("restored") and not i.get("deleted")), None)
    if qname:
        call("cuarentena: restaurar", "POST", f"/api/quarantine/{qname}/restore", {})
        check("cuarentena: fichero restaurado íntegro", Path(q).exists() and Path(q).read_text().startswith("fichero de prueba"), Path(q).exists())
        call("cuarentena: aislar otra vez", "POST", "/api/quarantine", {"filepath": q, "finding_id": "bateria2", "title": "prueba"})
        ql = call("cuarentena: listar 2", "GET", "/api/quarantine")
        items = ql if isinstance(ql, list) else (ql or {}).get("items", (ql or {}).get("files", []))
        qname = next((i.get("quarantine_name") for i in items if "sospechoso" in json.dumps(i) and not i.get("restored") and not i.get("deleted")), None)
        if qname:
            call("cuarentena: borrar definitivamente", "DELETE", f"/api/quarantine/{qname}")
    else:
        check("cuarentena: elemento localizable en el listado", False, ql)
    call("cuarentena: estadísticas", "GET", "/api/quarantine/stats")
    call("cuarentena: ruta inexistente rechazada", "POST", "/api/quarantine", {"filepath": "/no/existe"}, ok_status=(200, 400, 404), pred=lambda d: d.get("ok") is False)
    call("openapi.json", "GET", "/api/openapi.json", pred=lambda d: isinstance(d, dict) and d.get("openapi", "").startswith("3"))
    r = api("GET", "/api/docs")
    check("swagger ui /api/docs", r["status"] == 200 and "swagger" in str(r["data"]).lower(), r["status"])
    call("ansible: plantillas (sin AWX → error claro)", "GET", "/api/ansible/templates", ok_status=(200, 400), pred=lambda d: isinstance(d, (list, dict)))
    call("ansible: jobs", "GET", "/api/ansible/jobs")
    call("tenants: listar", "GET", "/api/tenants")
    call("tenants: crear", "POST", "/api/tenants", {"slug": "demo-bateria", "name": "Demo", "plan": "starter",
                                                  "admin_email": "demo@ejemplo-demo.es"}, ok_status=(201,))
    call("tenants: leer", "GET", "/api/tenants/demo-bateria")
    call("tenants: nueva clave", "POST", "/api/tenants/demo-bateria/rotate-key", {}, pred=lambda d: len(d.get("api_key", "")) > 20)
    call("tenants: baja", "DELETE", "/api/tenants/demo-bateria")
    call("tenants: dado de baja ya no existe", "GET", "/api/tenants/demo-bateria", ok_status=(404,))
    fm = call("importar: formatos", "GET", "/api/import/formats")
    call("sbom: generar (pip)", "POST", "/api/sbom/generate", {"include": ["pip"], "format": "json"})
    call("sbom: último", "GET", "/api/sbom/latest")
    call("yara: reglas", "GET", "/api/yara/rules")
    call("rollback: listar", "GET", "/api/rollback")
    call("monitor: estado", "GET", "/api/monitor/status")
    call("fix local: finding inexistente (sin 500)", "POST", "/api/fix/local", {"finding_id": "no_existe", "scan_id": sid}, ok_status=(200, 400, 404, 422))
    call("explicar hallazgo sin LLM (sin 500)", "POST", "/api/findings/explain", {"finding_id": "ssh_root_login", "scan_id": sid}, ok_status=(200, 400, 404, 503))
    call("runtime scan (sin docker, sin 500)", "POST", "/api/scan/runtime", {}, ok_status=(200, 400, 503))
    call("docker-image scan (sin docker, sin 500)", "POST", "/api/scan/docker-image", {"images": []}, ok_status=(200, 400, 503))
    call("intel: config", "GET", "/api/intel/config")
    call("intel: historial", "GET", "/api/intel/history?limit=5")
    call("intel: sin API keys lo dice claro (400)", "POST", "/api/intel/scan", {"targets": [], "modules": []},
         ok_status=(400,), pred=lambda d: "API key" in d.get("error", ""))
    call("intel: indicador inválido rechazado", "POST", "/api/intel/scan", {"targets": ["1.2.3.4/../x"]}, ok_status=(400,))
    r = pg.evaluate("async () => { const r = await fetch('/metrics'); return {s: r.status, t: (await r.text()).slice(0, 400)}; }")
    check("métricas Prometheus", r["s"] == 200 and "# TYPE" in r["t"], r)

    # ── Mi cuenta, tokens de API, auditoría ────────────────────────────────
    call("sesiones: listar (incluye la actual)", "GET", "/api/sessions",
         pred=lambda d: isinstance(d, list) and any(s.get("current") for s in d) and all("jti" not in s for s in d))
    tok = call("tokens: crear (viewer, 30 días)", "POST", "/api/tokens", {"name": "e2e", "role": "viewer", "expires_days": 30},
               ok_status=(201,), pred=lambda d: d.get("token", "").startswith("cht_default."))
    if tok.get("token"):
        tc = mk()
        h = {"Authorization": f"Bearer {tok['token']}"}
        r = tc.request.get(f"{BASE}/api/me", headers=h)
        check("token: autentica con el rol del token", r.status == 200 and r.json().get("role") == "viewer", r.status)
        r = tc.request.post(f"{BASE}/api/suppressions", headers=h, data={"pattern": "x", "reason": "y"})
        check("token: no supera su rol", r.status == 403, r.status)
        r = tc.request.post(f"{BASE}/api/tokens", headers=h, data={"name": "otro"})
        check("token: no gestiona credenciales", r.status == 403, r.status)
        call("tokens: listar sin hash", "GET", "/api/tokens", pred=lambda d: any(t["id"] == tok["id"] for t in d)
             and all("token_hash" not in t for t in d))
        call("tokens: revocar", "DELETE", f"/api/tokens/{tok['id']}")
        r = tc.request.get(f"{BASE}/api/me", headers=h)
        check("token revocado ya no vale", r.status == 401, r.status)
        tc.close()
    call("contraseña: actual errónea rechazada", "POST", "/api/me/password", {"current": "mala", "new": "x" * 12}, ok_status=(400,))
    call("auditoría: registra el login", "GET", "/api/audit?action=login", pred=lambda d: any(e["username"] == "admin" for e in d))
    call("auditoría: filtro de fallos", "GET", "/api/audit?failures=1", pred=lambda d: all(e["ok"] == 0 for e in d))
    call("fixes remotos: historial", "GET", "/api/fix/remote/history", pred=lambda d: isinstance(d, list))

    # ── Integraciones: lo guardado se aplica sin reiniciar ────────────────
    call("notificaciones: guardar servidor SMTP", "POST", "/api/config/notifications",
         {"smtp_host": "smtp.ejemplo-demo.es", "smtp_password": "clave-smtp-demo"})
    call("notificaciones: se lee lo guardado sin devolver la contraseña", "GET", "/api/config/notifications",
         pred=lambda d: d.get("smtp_host") == "smtp.ejemplo-demo.es" and "smtp_password" not in d
         and "smtp_password" in d.get("secrets_set", []))

    # ── Análisis programados ──────────────────────────────────────────────
    sched = call("programados: crear (cabeceras web)", "POST", "/api/schedules",
                 {"name": "E2E cabeceras", "task": "web_headers", "targets": [WEB], "hour": 3, "minute": 0},
                 ok_status=(201,), pred=lambda d: d.get("id"))
    call("programados: tarea no programable rechazada", "POST", "/api/schedules",
         {"name": "x", "task": "audit", "targets": ["a"]}, ok_status=(400,))
    if sched.get("id"):
        call("programados: lanzar ahora", "POST", f"/api/schedules/{sched['id']}/run", {}, ok_status=(202,))
        done = None
        for _ in range(60):
            rows = api("GET", "/api/schedules")["data"]
            row = next((x for x in rows if x["id"] == sched["id"]), {})
            if row.get("last_status", "").startswith(("ok", "error")) and not row.get("running"):
                done = row; break
            time.sleep(1)
        check("programados: se ejecuta y deja su análisis en el historial", done and done["last_status"].startswith("ok")
              and done.get("last_scan_id"), done)
        call("programados: pausar", "PATCH", f"/api/schedules/{sched['id']}", {"enabled": False},
             pred=lambda d: d.get("enabled") is False)
        call("programados: borrar", "DELETE", f"/api/schedules/{sched['id']}")

    # ── 2FA de extremo a extremo ───────────────────────────────────────────
    call("2fa: estado inicial", "GET", "/api/auth/2fa/status")
    setup = call("2fa: setup", "POST", "/api/auth/2fa/setup", {})
    secret = (setup or {}).get("secret")
    if secret:
        call("2fa: código erróneo rechazado", "POST", "/api/auth/2fa/activate", {"code": "000000"}, ok_status=(200, 400, 401, 403, 422), pred=lambda d: d.get("ok") is False)
        call("2fa: activar", "POST", "/api/auth/2fa/activate", {"code": totp(secret)})
        c2 = mk(); p2 = c2.new_page(); p2.goto(f"{BASE}/login")
        p2.fill("input[name=username], #username", "admin"); p2.fill("input[type=password]", PASSWORD)
        p2.keyboard.press("Enter"); p2.wait_for_load_state("networkidle")
        r = c2.request.get(f"{BASE}/api/dashboard", max_redirects=0)
        check("2fa: solo contraseña NO da acceso", r.status in (302, 401), r.status)
        code_in = p2.locator("input[name=code], #code, input[name=totp], input[inputmode=numeric]")
        check("2fa: se pide el código", code_in.count() > 0, p2.url)
        if code_in.count():
            time.sleep(31 - time.time() % 30)   # ventana nueva: el código de la activación ya está consumido
            code_in.first.fill(totp(secret))
            with p2.expect_navigation():
                p2.keyboard.press("Enter")
            p2.wait_for_load_state("networkidle")
            r = c2.request.get(f"{BASE}/api/dashboard", max_redirects=0)
            check("2fa: contraseña + código da acceso", r.status == 200, r.status)
        c2.close()
        time.sleep(31 - time.time() % 30)
        call("2fa: desactivar", "POST", "/api/auth/2fa/disable", {"code": totp(secret)}, ok_status=(200,))
        call("2fa: estado final desactivado", "GET", "/api/auth/2fa/status", pred=lambda d: not d.get("enabled", d.get("totp_enabled", False)))
    else:
        check("2fa: setup devuelve secreto", False, setup)

    check("ninguna respuesta 5xx en la API", not five, five)

    # ── Logout y rate limit (al final: bloquea la IP 15 min) ──────────────
    pg.goto(f"{BASE}/logout"); pg.wait_for_load_state("networkidle")
    r = ctx.request.get(f"{BASE}/api/dashboard", max_redirects=0)
    check("logout invalida la sesión", r.status in (302, 401), r.status)
    # localhost está en lista blanca: simulamos un proxy local que reenvía una IP externa
    c3 = b.new_context(ignore_https_errors=True, extra_http_headers={"X-Forwarded-For": "203.0.113.9"}); p3 = c3.new_page(); blocked = False
    for i in range(7):
        p3.goto(f"{BASE}/login"); p3.fill("input[name=username], #username", "admin"); p3.fill("input[type=password]", f"mala{i}")
        p3.keyboard.press("Enter"); p3.wait_for_load_state("networkidle")
        txt = p3.content().lower()
        if any(w in txt for w in ("bloque", "demasiados", "too many", "intentos")):
            blocked = True; break
    p3.goto(f"{BASE}/login"); p3.fill("input[name=username], #username", "admin"); p3.fill("input[type=password]", PASSWORD)
    p3.keyboard.press("Enter"); p3.wait_for_load_state("networkidle")
    r = c3.request.get(f"{BASE}/api/dashboard", max_redirects=0)
    check("rate limit: bloquea tras intentos fallidos (ni con la buena)", blocked and r.status in (302, 401), f"bloqueado={blocked} status={r.status}")
    b.close()

ok = sum(r["ok"] for r in results)
(OUT / "functional.json").write_text(json.dumps(results, indent=1, ensure_ascii=False))
print(f"\nfuncional: {ok}/{len(results)} pruebas OK")
sys.exit(0 if ok == len(results) else 1)
