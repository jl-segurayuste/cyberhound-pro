"""Threat intelligence de extremo a extremo (sin red: se simulan las respuestas de cada API).

Bugs reales corregidos 2026-10-20: IntelScanner devolvía el JSON en bruto de cada
fuente pero la ruta, la BD, el resumen y la UI lo trataban como Finding (500 en
cuanto había una respuesta); con modules=[] (lo que envía la UI) no se consultaba
ninguna fuente; OTX no estaba implementado; VirusTotal solo sabía de IPs; los
targets no se validaban antes de meterlos en las URLs de las APIs.
"""
import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer

from cyberhound.api.server import CyberHoundServer
from cyberhound.core import passwords
from cyberhound.core.config import CyberHoundConfig
from cyberhound.core.models import ExternalIntel
from cyberhound.scanners import intel
from cyberhound.scanners.intel import IntelScanner, indicator_kind, to_findings

# Respuestas reales (recortadas) del formato documentado de cada API
RESPONSES = {
    "api.shodan.io": {"ip_str": "203.0.113.7", "ports": [22, 80, 443], "vulns": ["CVE-2023-38408", "CVE-2024-6387"]},
    "virustotal.com": {"data": {"attributes": {"last_analysis_stats": {"malicious": 7, "suspicious": 1,
                                                                        "harmless": 60}, "reputation": -30}}},
    "abuseipdb.com": {"data": {"ipAddress": "203.0.113.7", "abuseConfidenceScore": 88, "totalReports": 41,
                               "isp": "Ejemplo ISP"}},
    "greynoise.io": {"ip": "203.0.113.7", "noise": True, "riot": False, "classification": "malicious",
                     "name": "unknown"},
    "otx.alienvault.com": {"pulse_info": {"count": 4, "pulses": []}},
    "haveibeenpwned.com": [{"Name": "Adobe"}, {"Name": "LinkedIn"}],
}


class _Keys:
    shodan = virustotal = abuseipdb = greynoise = otx = hibp = "k"


@pytest.fixture
def fake_apis(monkeypatch):
    calls = []

    async def fake_get(s, url, **kw):
        calls.append(url)
        return next((v for host, v in RESPONSES.items() if host in url), None)
    monkeypatch.setattr(IntelScanner, "_get", staticmethod(fake_get))
    return calls


def test_tipo_de_indicador():
    assert indicator_kind("203.0.113.7") == "ip"
    assert indicator_kind("2001:db8::1") == "ip"
    assert indicator_kind("ejemplo-demo.es") == "domain"
    assert indicator_kind("d41d8cd98f00b204e9800998ecf8427e") == "hash"
    assert indicator_kind("alguien@ejemplo-demo.es") == "email"
    for bad in ("", "1.2.3.4/../../x", "a b", "evil.com/path?x", "x" * 300, "../etc/passwd"):
        assert indicator_kind(bad) is None


async def test_ip_consulta_todas_las_fuentes_configuradas_y_da_hallazgos(fake_apis):
    findings = await IntelScanner(_Keys()).scan_findings("203.0.113.7")   # modules vacío = todas
    cats = {f.category for f in findings}
    assert cats == {"intel/shodan", "intel/virustotal", "intel/abuseipdb", "intel/greynoise", "intel/otx"}
    sev = {f.id: f.severity for f in findings}
    assert sev["intel_abuseipdb_abuse_203_0_113_7"] == "critical"
    assert sev["intel_virustotal_detections_203_0_113_7"] == "critical"
    assert all(f.evidence.startswith("ip=203.0.113.7") for f in findings)
    assert not any("haveibeenpwned" in u for u in fake_apis)    # hibp solo para emails


async def test_dominio_hash_y_email_van_a_su_endpoint(fake_apis):
    sc = IntelScanner(_Keys())
    await sc.scan("ejemplo-demo.es")
    await sc.scan("d41d8cd98f00b204e9800998ecf8427e")
    out = await sc.scan_findings("alguien@ejemplo-demo.es")
    assert any("/api/v3/domains/ejemplo-demo.es" in u for u in fake_apis)
    assert any("/api/v3/files/d41d8cd98f00b204e9800998ecf8427e" in u for u in fake_apis)
    assert any("/indicators/domain/ejemplo-demo.es/general" in u for u in fake_apis)
    assert [f.category for f in out] == ["intel/hibp"] and "Adobe" in out[0].evidence
    assert not any("shodan" in u for u in fake_apis)


async def test_sin_api_keys_no_consulta_nada(fake_apis):
    assert await IntelScanner(None).scan("203.0.113.7") == []
    assert fake_apis == []


def test_respuestas_limpias_no_dan_hallazgos():
    clean = {"shodan": {"ports": []}, "virustotal": {"data": {"attributes": {"last_analysis_stats": {}}}},
             "abuseipdb": {"data": {"abuseConfidenceScore": 0}}, "greynoise": {"classification": "benign"},
             "otx": {"pulse_info": {"count": 0}}, "hibp": {"breaches": []}}
    for src, data in clean.items():
        assert to_findings(ExternalIntel(source=src, indicator="203.0.113.7", data=data)) == []
    assert to_findings(ExternalIntel(source="shodan", indicator="203.0.113.7", data={})) == []   # 404


@pytest_asyncio.fixture
async def client(tmp_path, monkeypatch):
    monkeypatch.setattr(CyberHoundConfig, "save", lambda self, *a, **k: None)
    cfg = CyberHoundConfig()
    cfg.db_path = tmp_path / "intel.db"
    cfg.auth.username = "admin"
    cfg.auth.password_hash = passwords.hash_password("clave-de-prueba")
    cfg.auth.secret = "s" * 64
    cfg.api_keys = _Keys()
    srv = CyberHoundServer(cfg)
    await srv.db.init()
    c = TestClient(TestServer(srv.build_app()))
    await c.start_server()
    await c.get("/login")
    csrf = c.session.cookie_jar.filter_cookies(c.make_url("/")).get("ch_csrf").value
    await c.post("/login", data={"username": "admin", "password": "clave-de-prueba", "_csrf": csrf},
                 allow_redirects=False)
    c.srv = srv
    yield c
    await c.close()


async def test_api_scan_guarda_y_resume_los_hallazgos(client, fake_apis):
    r = await client.post("/api/intel/scan", json={"targets": ["203.0.113.7"], "modules": []})
    assert r.status == 200
    d = await r.json()
    assert d["count"] == 6 and d["summary"]["risk_level"] == "critical"
    assert d["summary"]["by_module"]["shodan"] == 2
    hist = await (await client.get("/api/intel/history")).json()
    assert hist and hist[0]["total_findings"] == 6


async def test_api_lookup(client, fake_apis):
    d = await (await client.get("/api/intel/lookup?target=ejemplo-demo.es&modules=virustotal")).json()
    assert d["count"] == 1 and d["findings"][0]["category"] == "intel/virustotal"


async def test_api_valida_indicadores_y_modulos(client, fake_apis):
    assert (await client.post("/api/intel/scan", json={"targets": ["1.2.3.4/../x"]})).status == 400
    assert (await client.post("/api/intel/scan", json={"targets": ["1.2.3.4"], "modules": ["nmap"]})).status == 400
    assert (await client.post("/api/intel/scan", json={"targets": "1.2.3.4"})).status == 400
    assert (await client.get("/api/intel/lookup?target=a%20b")).status == 400
    assert (await client.get("/api/intel/history?limit=x")).status == 400
    assert fake_apis == []


async def test_api_sin_keys_lo_dice_claro(client, fake_apis):
    client.srv.cfg.api_keys = intel_keys_none = type("K", (), {})()
    assert intel_keys_none is client.srv.cfg.api_keys
    r = await client.post("/api/intel/scan", json={"targets": ["203.0.113.7"]})
    assert r.status == 400 and "API key" in (await r.json())["error"]
    cfg = await (await client.get("/api/intel/config")).json()
    assert cfg["configured_count"] == 0 and set(intel.ALL_MODULES) <= set(cfg)
