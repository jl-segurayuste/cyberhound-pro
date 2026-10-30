"""
Bastionado con perfiles oficiales de SCAP Security Guide sobre hosts remotos.

Perfiles: CCN-STIC (guía CCN-STIC-610A22: básico, intermedio y avanzado; RHEL 9 y derivadas)
y DISA STIG (RHEL 8 y 9). No reimplementa las reglas: en el host se ejecuta oscap con el
contenido de la propia versión del sistema (paquete scap-security-guide), como pide Red Hat.

- Auditoría: oscap xccdf eval con el perfil elegido; vuelven solo las reglas que fallan (más
  un resumen con el porcentaje de cumplimiento).
- Corrección: regla a regla. oscap 1.3 ignora --rule al generar el script de corrección y
  devuelve el del perfil entero, así que del script se extrae el bloque de esa regla y solo
  ese; si no se puede aislar exactamente uno, no se ejecuta nada. Antes se guarda /etc;
  después se comprueba la regla y se guarda solo lo que cambió, para poder deshacerlo.
  Paquetes, servicios y valores en caliente (sysctl) no se deshacen.
- Las reglas que pueden dejar fuera al que administra el host (SSH, PAM, contraseñas,
  cortafuegos, sudo, cifrado del sistema, arranque) solo se corrigen con confirmación.

Todo lo que devuelve el host se valida aquí: es dato, nunca código.
"""
from __future__ import annotations

import inspect
import json
import re
import secrets
import time

from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding, HostResult

logger = get_logger("scap_baseline")

# Perfil (sufijo del id de SSG) → (nombre, categoría de los hallazgos)
PROFILES: dict[str, tuple[str, str]] = {
    "ccn_basic":        ("CCN-STIC básico", "ccn-stic"),
    "ccn_intermediate": ("CCN-STIC intermedio", "ccn-stic"),
    "ccn_advanced":     ("CCN-STIC avanzado", "ccn-stic"),
    "stig":             ("DISA STIG", "disa-stig"),
}
DEFAULT_PROFILE = "ccn_intermediate"   # ENS categoría MEDIA, la más habitual
CATEGORIES = frozenset(cat for _, cat in PROFILES.values())
PROFILE_PREFIX = "xccdf_org.ssgproject.content_profile_"
RULE_PREFIX = "xccdf_org.ssgproject.content_rule_"
# Categorías de DISA a partir de la gravedad de la regla
STIG_CAT = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}

_RULE_RE = re.compile(r"[a-z0-9_]{1,120}")
_DS_RE = re.compile(r"/usr/share/xml/scap/ssg/content/ssg-[a-z0-9]{1,20}-ds\.xml")
_ETC_RE = re.compile(r"/etc(/[\w.+@:,=~-]+)+")
_FID_RE = re.compile(r"scap\.(" + "|".join(PROFILES) + r")\.([a-z0-9_]{1,120})")
_SEVERITY = {"high": "high", "medium": "medium", "low": "low"}

# Reglas cuya corrección puede cortar el acceso de administración: piden confirmación expresa
RISKY_PREFIXES = (
    "sshd_", "disable_host_auth", "accounts_", "account_", "no_empty_passwords", "enable_authselect",
    "password", "faillock", "pam_", "set_password", "firewalld", "service_firewalld", "configure_firewalld",
    "sudo", "configure_crypto_policy", "enable_fips", "grub2_", "selinux",
    "package_firewalld", "service_sshd", "use_pam_wheel", "no_shelllogin",
)


def is_risky(rule: str) -> bool:
    return rule.startswith(RISKY_PREFIXES) or "ssh" in rule


def parse_finding_id(fid: str) -> tuple[str, str] | None:
    """(perfil, regla) de un hallazgo SCAP (con o sin el «host::» delante); None si no lo es."""
    m = _FID_RE.fullmatch(fid.split("::", 1)[-1])
    return (m.group(1), m.group(2)) if m else None


def is_scap_finding(finding: Finding) -> bool:
    return finding.category in CATEGORIES and parse_finding_id(finding.id) is not None


def needs_confirmation(finding: Finding) -> bool:
    """La corrección puede cortar el acceso de administración: hay que confirmarla."""
    return is_scap_finding(finding) and is_risky(parse_finding_id(finding.id)[1])


# ── Script remoto de auditoría ───────────────────────────────────────────────
# Python 3.6+ (RHEL 8 lleva 3.6). Recibe por la cabecera PERFIL; imprime una línea JSON.
REMOTE_AUDIT_SCRIPT = r'''
import json, os, shutil, subprocess, sys, tempfile
import xml.etree.ElementTree as ET
NS = "{http://checklists.nist.gov/xccdf/1.2}"
CONTENT = "/usr/share/xml/scap/ssg/content/"
PROFILE = "xccdf_org.ssgproject.content_profile_" + PERFIL

def out(d):
    print(json.dumps(d)); sys.exit(0)

def run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return -1, "", str(e)

osr = {}
try:
    for l in open("/etc/os-release"):
        if "=" in l:
            k, v = l.rstrip("\n").split("=", 1); osr[k] = v.strip('"')
except Exception:
    pass
os_name = osr.get("PRETTY_NAME", "")
major = osr.get("VERSION_ID", "").split(".")[0]
if os.geteuid() != 0:
    out({"error": "sin_root", "os": os_name})
if not shutil.which("oscap"):
    out({"error": "sin_oscap", "os": os_name})
ids = [osr.get("ID", "")] + osr.get("ID_LIKE", "").split()
names = []
for i in ids:
    # Primero el contenido propio de la distribución: el de RHEL en Rocky o Alma da todo «no aplica»
    names += {"rhel": ["rhel"], "centos": ["cs", "centos"], "almalinux": ["almalinux", "alma", "rhel"],
              "rocky": ["rl", "rocky", "rhel"], "ol": ["ol"], "fedora": ["fedora"]}.get(i, [])
ds = ""
for n in names:
    p = CONTENT + "ssg-" + n + major + "-ds.xml"
    if os.path.exists(p):
        rc, so, se = run(["oscap", "info", "--profiles", p])
        if PROFILE + ":" in so:
            ds = p; break
if not ds:
    out({"error": "sin_perfil", "os": os_name, "busca": names, "major": major})

tmp = tempfile.mkdtemp(prefix="ch-scap-")
try:
    res = os.path.join(tmp, "r.xml")
    rc, so, se = run(["oscap", "xccdf", "eval", "--profile", PROFILE, "--results", res, ds], timeout=1800)
    if rc not in (0, 2) or not os.path.exists(res):
        out({"error": "oscap", "os": os_name, "rc": rc, "msg": (se or so)[-300:]})
    rules, results = {}, []
    for ev, el in ET.iterparse(res, events=("end",)):
        if el.tag == NS + "Rule":
            t = el.find(NS + "title")
            fixes = [f.get("system", "") for f in el.findall(NS + "fix")]
            rules[el.get("id")] = (t.text if t is not None else "", el.get("severity", ""),
                                   "urn:xccdf:fix:script:sh" in fixes)
            el.clear()
        elif el.tag == NS + "rule-result":
            r = el.find(NS + "result")
            results.append((el.get("idref"), r.text if r is not None else ""))
            el.clear()
finally:
    shutil.rmtree(tmp, ignore_errors=True)
counts, fails = {}, []
for rid, r in results:
    counts[r] = counts.get(r, 0) + 1
    if r in ("fail", "error"):
        t, sev, fix = rules.get(rid, ("", "", False))
        fails.append({"rule": rid, "result": r, "title": t, "severity": sev, "fix": fix})
if not any(counts.get(k) for k in ("pass", "fail", "error")):
    out({"error": "no_aplica", "os": os_name, "ds": ds})
out({"os": os_name, "ds": ds, "profile": PROFILE, "counts": counts, "fails": fails})
'''

# ── Extracción del bloque de una regla ───────────────────────────────────────
# También se ejecuta en el host (va dentro de REMOTE_FIX_SCRIPT): Python 3.6, solo con `re`.
# Cada regla del script de SSG va entre
#   # BEGIN fix (i / N) for '<regla>'   …   ) # END fix for '<regla>'
def extract_rule_fix(script, rule):
    """Script bash con solo la corrección de `rule` (id completo); None si no hay exactamente una."""
    begin = re.compile(r"# BEGIN fix \(\d+ / \d+\) for '" + re.escape(rule) + r"'")
    end = ") # END fix for '" + rule + "'"
    lines = script.splitlines()
    starts = [i for i, line in enumerate(lines) if begin.fullmatch(line.strip())]
    if len(starts) != 1:
        return None
    i = starts[0]
    ends = [j for j in range(i + 1, len(lines)) if lines[j].strip() == end]
    if len(ends) != 1:
        return None
    block = lines[i:ends[0] + 1]
    # Dentro del bloque no puede empezar ni acabar otra regla
    if sum(1 for line in block if line.lstrip().startswith("# BEGIN fix")) != 1:
        return None
    if sum(1 for line in block if line.lstrip().startswith(") # END fix for")) != 1:
        return None
    return "#!/usr/bin/env bash\n" + "\n".join(block) + "\n"


# ── Script remoto de corrección y de deshacer ────────────────────────────────
# Recibe A (acción) por la cabecera. Copia de /etc antes; después, solo lo cambiado.
REMOTE_FIX_SCRIPT = "import re\n" + inspect.getsource(extract_rule_fix) + r'''
import fcntl, json, os, shutil, stat, subprocess, sys, tarfile
BASE = "/var/lib/cyberhound/scap"

def done(ok, msg="", before=None):
    print(json.dumps({"ok": ok, "msg": msg[:300], "before": before})); sys.exit(0)

def run(cmd, timeout=600, inp=None):
    try:
        r = subprocess.run(cmd, input=inp, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return -1, "", str(e)

def manifest():
    m = {}
    for root, dirs, files in os.walk("/etc"):
        for n in files + [d for d in dirs if os.path.islink(os.path.join(root, d))]:
            p = os.path.join(root, n)
            try:
                s = os.lstat(p)
            except OSError:
                continue
            link = os.readlink(p) if stat.S_ISLNK(s.st_mode) else ""
            m[p] = (s.st_mode, s.st_uid, s.st_gid, s.st_size, s.st_mtime_ns, link)
    return m

if os.geteuid() != 0:
    done(False, "hace falta root (sudo sin contraseña) para corregir")
os.makedirs(BASE, 0o700, exist_ok=True)
os.chmod(BASE, 0o700)
lock = open(os.path.join(BASE, ".lock"), "w")
fcntl.flock(lock, fcntl.LOCK_EX)
act = A["action"]
bid = A["bid"]
small = os.path.join(BASE, bid + ".tar")
# Filtro «tar» explícito donde exista (3.12+ y los backports de RHEL): nada fuera de la raíz
XKW = {"filter": "tar"} if hasattr(tarfile, "tar_filter") else {}

if act == "scap_rule":
    rule = "xccdf_org.ssgproject.content_rule_" + A["rule"]
    profile = "xccdf_org.ssgproject.content_profile_" + A["profile"]
    ds = A["ds"]
    if not os.path.isfile(ds):
        done(False, "no existe " + ds)
    rc, full_script, se = run(["oscap", "xccdf", "generate", "fix", "--fix-type", "bash",
                               "--profile", profile, "--rule", rule, ds], timeout=300)
    script = extract_rule_fix(full_script, rule) if rc == 0 else None
    if not script:
        done(False, "no se pudo aislar la corrección de esta regla en el script de SSG: no se ha tocado nada")
    full = os.path.join(BASE, bid + ".full.tar")
    m0 = manifest()
    with tarfile.open(full, "w") as t:
        t.add("/etc", recursive=True)
    rc, so, se = run(["bash", "-s"], timeout=900, inp=script)
    m1 = manifest()
    changed = sorted(p for p in m0 if p in m1 and m0[p] != m1[p])
    removed = sorted(p for p in m0 if p not in m1)
    added = sorted(p for p in m1 if p not in m0)

    def restore_from(tarpath, paths):
        with tarfile.open(tarpath) as t:
            for p in paths:
                try:
                    t.extract(p.lstrip("/"), "/", **XKW)
                except KeyError:
                    pass
    if rc != 0:
        restore_from(full, changed + removed)
        for p in added:
            if os.path.islink(p) or os.path.isfile(p):
                os.unlink(p)
        os.unlink(full)
        done(False, "la corrección falló y se ha restaurado /etc: " + (se or so).strip()[-200:])
    with tarfile.open(full) as src, tarfile.open(small, "w") as dst:
        for p in changed + removed:
            try:
                m = src.getmember(p.lstrip("/"))
            except KeyError:
                continue
            dst.addfile(m, src.extractfile(m) if m.isfile() else None)
    os.unlink(full)
    os.chmod(small, 0o600)
    rc, so, se = run(["oscap", "xccdf", "eval", "--profile", profile, "--rule", rule, ds], timeout=300)
    # oscap separa «Result» y el valor con \r\t: en modo texto el valor cae en la línea siguiente
    m = re.search(r"^Result\s+(\w+)", so, re.M)
    result = m.group(1) if m else ""
    msg = "" if result == "pass" else ("aplicada, pero la regla sigue en «%s» (puede requerir reiniciar)" % (result or "?"))
    done(True, msg, {"bid": bid, "changed": changed, "removed": removed, "added": added, "result": result})

if act == "scap_undo":
    if not os.path.isfile(small):
        done(False, "ya no está la copia de esta corrección en el host")
    with tarfile.open(small) as t:
        for m in t.getmembers():
            t.extract(m, "/", **XKW)
    for p in A.get("added", []):
        if p.startswith("/etc/") and (os.path.islink(p) or os.path.isfile(p)):
            os.unlink(p)
    os.unlink(small)
    done(True, "restaurados los ficheros de /etc; los paquetes, servicios y valores aplicados en caliente (sysctl) que tocara la corrección no se deshacen")

done(False, "acción desconocida")
'''


def _audit_payload(profile: str) -> str:
    return f"PERFIL = {profile!r}\n" + REMOTE_AUDIT_SCRIPT


def fix_payload(action: dict) -> str:
    # repr() de un str es un literal Python válido: la acción viaja como dato, no como código
    return f"A = __import__('json').loads({json.dumps(action)!r})\n" + REMOTE_FIX_SCRIPT


def findings_from(data: dict, host: str, profile: str) -> list[Finding]:
    """Hallazgos a partir de lo que devolvió el host, validando cada campo."""
    name, category = PROFILES[profile]
    ds = str(data.get("ds", ""))
    if not _DS_RE.fullmatch(ds):
        raise ValueError("el host devolvió una ruta de contenido SCAP no válida")
    counts = data.get("counts") if isinstance(data.get("counts"), dict) else {}
    n = {k: counts.get(k, 0) for k in ("pass", "fail", "error", "notapplicable", "notchecked")
         if isinstance(counts.get(k, 0), int) and not isinstance(counts.get(k, 0), bool)}
    fails = data.get("fails") if isinstance(data.get("fails"), list) else []
    stig = category == "disa-stig"
    out: list[Finding] = []
    for f in fails[:2000]:
        if not isinstance(f, dict):
            continue
        rid = str(f.get("rule", ""))
        if not rid.startswith(RULE_PREFIX) or not _RULE_RE.fullmatch(rid[len(RULE_PREFIX):]):
            continue
        rule = rid[len(RULE_PREFIX):]
        title = re.sub(r"\s+", " ", str(f.get("title") or rule))[:200]
        severity = _SEVERITY.get(str(f.get("severity")), "info")
        fixable = f.get("fix") is True
        risky = is_risky(rule)
        result = "error" if f.get("result") == "error" else "fail"
        label = f"{name} ({STIG_CAT[severity]})" if stig and severity in STIG_CAT else name
        out.append(Finding(
            id=f"{host}::scap.{profile}.{rule}", category=category, severity=severity,
            title=f"{label}: {title}",
            description=(f"Regla del perfil {name} que no se cumple"
                         + (" (oscap no pudo evaluarla)" if result == "error" else "") + "."),
            remediation=("Corrección oficial de SCAP Security Guide para esta regla"
                         + (" — puede afectar al acceso de administración: pide confirmación" if risky else "")
                         if fixable else "Sin corrección automática: revísala a mano con la guía del perfil"),
            evidence=f"oscap: {result} · regla {rule}",
            auto_fix=fixable, file_path=ds, source_host=host,
        ))
    evaluated = n.get("pass", 0) + n.get("fail", 0) + n.get("error", 0)
    pct = round(100 * n.get("pass", 0) / evaluated) if evaluated else 0
    out.append(Finding(
        id=f"{host}::scap.{profile}._resumen", category=category, severity="info",
        title=f"{name}: {pct} % de cumplimiento",
        description=(f"{n.get('pass', 0)} reglas cumplen, {n.get('fail', 0)} no y {n.get('error', 0)} con error; "
                     f"{n.get('notapplicable', 0)} no aplican a este sistema."),
        remediation="Corrige las reglas que fallan; las que pueden cortar el acceso piden confirmación.",
        evidence=re.sub(r"[^\w .,()/:+-]", "", str(data.get("os", "")))[:120], passed=True,
        file_path=ds, source_host=host,
    ))
    return out


AUDIT_ERRORS = {
    "sin_root": "hace falta sudo sin contraseña (sudo -n) para ejecutar oscap",
    "sin_oscap": "falta OpenSCAP en el host: dnf install openscap-scanner scap-security-guide",
    "no_aplica": "ninguna regla del perfil aplica a este sistema: el contenido SCAP no es el de esta distribución",
    "sin_perfil": "el contenido SCAP de este sistema no trae ese perfil (CCN-STIC: RHEL 9 o derivada con "
                  "scap-security-guide 0.1.69 o posterior; DISA STIG: RHEL 8 o 9 o derivada)",
}


def remote_fix_action(finding: Finding) -> dict | None:
    """Acción de corrección para un hallazgo SCAP; None si no se puede corregir sola."""
    parsed = parse_finding_id(finding.id)
    if not parsed or finding.category not in CATEGORIES or not finding.auto_fix or parsed[1].startswith("_"):
        return None
    profile, rule = parsed
    if not _DS_RE.fullmatch(finding.file_path or ""):
        return None
    return {"action": "scap_rule", "profile": profile, "rule": rule, "ds": finding.file_path,
            "bid": secrets.token_hex(8)}


def undo_action(action: dict, before) -> dict | None:
    """Acción para deshacer: la copia del host y los ficheros nuevos, validados."""
    if action.get("action") != "scap_rule" or not isinstance(before, dict):
        return None
    if before.get("bid") != action.get("bid"):
        return None
    lists = {}
    for k in ("changed", "removed", "added"):
        v = before.get(k)
        if not isinstance(v, list) or len(v) > 2000:
            return None
        if not all(isinstance(p, str) and len(p) < 400 and _ETC_RE.fullmatch(p) and "/.." not in p for p in v):
            return None
        lists[k] = v
    return {"action": "scap_undo", "bid": action["bid"], "added": lists["added"],
            "files": len(lists["changed"]) + len(lists["removed"])}


async def audit_host(auditor, host: str, profile: str = DEFAULT_PROFILE) -> HostResult:
    """Auditoría de un host con un perfil SCAP, con la conexión (y la verificación de clave) de RemoteAuditor."""
    import asyncssh

    from cyberhound.scanners.ssh_audit import HOSTKEY_CHANGED
    if profile not in PROFILES:
        raise ValueError(f"Perfil SCAP no válido: {profile}")
    start = time.monotonic()
    result = HostResult(host=host, port=auditor.creds.port, user=auditor.creds.username, status="error")
    try:
        async with await auditor._connect(host) as conn:
            cmd = await auditor._python_cmd(conn)
            if not cmd.startswith("sudo"):
                result.error = AUDIT_ERRORS["sin_root"]
                return result
            r = await conn.run(cmd, input=_audit_payload(profile), timeout=1900)
            lines = (r.stdout or "").strip().splitlines()
            data = json.loads(lines[-1]) if lines else {"error": "oscap", "msg": (r.stderr or "")[:200]}
            result.os_info = re.sub(r"[^\w .,()/:+-]", "", str(data.get("os", "")))[:120]
            if err := data.get("error"):
                result.error = AUDIT_ERRORS.get(err, f"oscap falló: {str(data.get('msg', err))[:200]}")
                return result
            result.findings = findings_from(data, host, profile)
            result.status = "ok"
    except asyncssh.PermissionDenied:
        result.status, result.error = "auth_failed", "Autenticación SSH fallida (clave o contraseña incorrecta)"
    except asyncssh.HostKeyNotVerifiable:
        result.status, result.error = "hostkey_changed", HOSTKEY_CHANGED.format(host=host)
    except (asyncssh.DisconnectError, ConnectionRefusedError, OSError) as e:
        result.status, result.error = "unreachable", str(e)
    except (ValueError, json.JSONDecodeError) as e:
        result.error = f"Respuesta del host no válida: {e}"
    except Exception as e:
        logger.error("%s: error en la auditoría SCAP: %s", host, e, exc_info=True)
        result.error = str(e)
    result.scan_time = time.monotonic() - start
    return result
