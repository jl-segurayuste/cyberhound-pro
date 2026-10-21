"""
Tests de los módulos nuevos:
- OpenAPI spec generation
- Multi-tenant TenantStore
- Ansible playbook generation
- Runtime container scan patterns
"""
import json
import re
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyberhound.core.models import Finding
from cyberhound.core.multitenancy import Tenant, TenantStore, tenant_from_host
from cyberhound.core.openapi import ENDPOINT_DOCS, SWAGGER_UI_HTML, build_openapi_spec
from cyberhound.scanners.runtime_scan import (
    SUSPICIOUS_PROCS,
    check_container_diff,
    check_resource_limits,
    check_running_processes,
)

# ── OpenAPI ───────────────────────────────────────────────────────────────────

class TestOpenAPI:

    def test_spec_is_valid_openapi_30(self):
        spec = build_openapi_spec()
        assert spec["openapi"] == "3.0.3"
        assert "info" in spec
        assert "paths" in spec
        assert "components" in spec

    def test_spec_has_security_schemes(self):
        spec = build_openapi_spec()
        schemes = spec["components"]["securitySchemes"]
        assert "BearerAuth" in schemes
        assert "AgentKey" in schemes

    def test_spec_has_finding_schema(self):
        spec = build_openapi_spec()
        schemas = spec["components"]["schemas"]
        assert "Finding" in schemas
        assert "severity" in schemas["Finding"]["properties"]

    def test_spec_has_all_tags(self):
        spec = build_openapi_spec()
        tag_names = {t["name"] for t in spec["tags"]}
        assert "Scans" in tag_names
        assert "Auth" in tag_names
        assert "Compliance" in tag_names
        assert "Ansible" in tag_names
        assert "MultiTenant" in tag_names

    def test_all_endpoints_have_tags(self):
        spec = build_openapi_spec()
        for path, methods in spec["paths"].items():
            for method, op in methods.items():
                assert "tags" in op, f"Falta tag en {method.upper()} {path}"
                assert len(op["tags"]) > 0

    def test_endpoints_count(self):
        spec = build_openapi_spec()
        total = sum(len(methods) for methods in spec["paths"].values())
        assert total >= 30, f"Solo {total} endpoints documentados"

    def test_spec_contains_websocket_docs(self):
        spec = build_openapi_spec()
        assert "/ws" in spec["paths"]
        assert "/ws/push" in spec["paths"]

    def test_server_url_in_spec(self):
        spec = build_openapi_spec("https://cyberhound.empresa.com:8443")
        assert "https://cyberhound.empresa.com:8443" in spec["servers"][0]["url"]

    def test_swagger_ui_html_valid(self):
        assert "<!DOCTYPE html>" in SWAGGER_UI_HTML
        assert "swagger-ui" in SWAGGER_UI_HTML
        assert "/api/openapi.json" in SWAGGER_UI_HTML
        assert "SwaggerUIBundle" in SWAGGER_UI_HTML

    def test_request_interceptor_adds_auth(self):
        """El Swagger UI debe inyectar el token JWT automáticamente."""
        assert "ch_token" in SWAGGER_UI_HTML
        assert "Authorization" in SWAGGER_UI_HTML


# ── Multi-tenant ──────────────────────────────────────────────────────────────

class TestTenant:

    def test_valid_slug(self):
        t = Tenant(slug="acme", name="ACME Corp")
        assert t.slug == "acme"
        assert t.pg_schema == "tenant_acme"

    def test_invalid_slug_raises(self):
        with pytest.raises(ValueError):
            Tenant(slug="ACME", name="Test")   # mayúsculas no permitidas
        with pytest.raises(ValueError):
            Tenant(slug="a", name="Test")       # demasiado corto
        with pytest.raises(ValueError):
            Tenant(slug="acme corp", name="T")  # espacio no permitido

    def test_slug_with_hyphens(self):
        t = Tenant(slug="my-company", name="My Company")
        assert t.slug == "my-company"

    def test_to_dict_excludes_key_by_default(self):
        t = Tenant(slug="acme", name="ACME")
        d = t.to_dict()
        assert "api_key" not in d
        assert "slug" in d
        assert "name" in d

    def test_to_dict_includes_key_when_requested(self):
        t = Tenant(slug="acme", name="ACME")
        d = t.to_dict(include_key=True)
        assert "api_key" in d
        assert len(d["api_key"]) > 20

    def test_api_key_is_random(self):
        t1 = Tenant(slug="acme1", name="T1")
        t2 = Tenant(slug="acme2", name="T2")
        assert t1.api_key != t2.api_key


class TestTenantStore:

    @pytest.fixture
    def store(self, tmp_path):
        return TenantStore(path=tmp_path / "tenants.json")

    def test_create_tenant(self, store):
        t = store.create("acme", "ACME Corp")
        assert t.slug == "acme"
        assert store.get("acme") is not None

    def test_duplicate_slug_raises(self, store):
        store.create("acme", "ACME Corp")
        with pytest.raises(ValueError):
            store.create("acme", "Another ACME")

    def test_list_active_tenants(self, store):
        store.create("acme", "ACME")
        store.create("contoso", "Contoso")
        assert len(store.list()) == 2

    def test_soft_delete(self, store):
        store.create("acme", "ACME")
        store.delete("acme")
        assert len(store.list()) == 0
        # get sigue funcionando
        assert store.get("acme") is not None

    def test_deleted_slug_can_be_recreated_with_new_key(self, store):
        old = store.create("acme", "ACME")
        old_key = old.api_key
        store.delete("acme")
        new = store.create("acme", "ACME 2")
        assert new.active and new.api_key != old_key
        assert [t.slug for t in store.list()] == ["acme"]

    def test_deleted_tenant_key_no_longer_valid(self, store):
        t = store.create("acme", "ACME")
        store.delete("acme")
        assert store.get_by_api_key(t.api_key) is None

    def test_get_by_api_key(self, store):
        t = store.create("acme", "ACME")
        found = store.get_by_api_key(t.api_key)
        assert found is not None
        assert found.slug == "acme"

    def test_get_by_wrong_key(self, store):
        store.create("acme", "ACME")
        assert store.get_by_api_key("wrong-key-xxx") is None

    def test_update_tenant(self, store):
        store.create("acme", "ACME", plan="community")
        updated = store.update("acme", plan="professional", name="ACME Corp 2")
        assert updated.plan == "professional"
        assert updated.name == "ACME Corp 2"

    def test_rotate_api_key(self, store):
        t = store.create("acme", "ACME")
        old_key = t.api_key
        new_key = store.rotate_api_key("acme")
        assert new_key != old_key
        assert store.get_by_api_key(new_key) is not None
        assert store.get_by_api_key(old_key) is None

    def test_persistence(self, tmp_path):
        store1 = TenantStore(path=tmp_path / "t.json")
        store1.create("acme", "ACME")
        # Nuevo store carga desde disco
        store2 = TenantStore(path=tmp_path / "t.json")
        assert store2.get("acme") is not None
        assert store2.get("acme").name == "ACME"


class TestTenantDetection:

    def test_subdominio(self):
        assert tenant_from_host("acme.cyberhound.empresa.com") == "acme"
        assert tenant_from_host("acme.cyberhound.empresa.com:8443") == "acme"

    def test_sin_subdominio_o_reservado(self):
        assert tenant_from_host("localhost:8443") == ""
        assert tenant_from_host("www.empresa.com") == ""
        assert tenant_from_host("192.168.1.10") == ""

    def test_slugs_reservados_no_se_crean(self, tmp_path):
        store = TenantStore(path=tmp_path / "t.json")
        for slug in ("default", "admin", "static"):
            with pytest.raises(ValueError):
                store.create(slug, "X")
        with pytest.raises(ValueError):
            store.create("acme", "   ")


# ── Runtime scan patterns ─────────────────────────────────────────────────────

class TestRuntimeScanPatterns:

    def test_suspicious_proc_patterns_compile(self):
        for pattern in SUSPICIOUS_PROCS:
            compiled = re.compile(pattern, re.IGNORECASE)
            assert compiled is not None

    def test_detects_netcat_listener(self):
        procs = SUSPICIOUS_PROCS
        line = "root 1234 nc -e /bin/bash -l 4444"
        matches = [p for p in procs if re.search(p, line, re.IGNORECASE)]
        assert len(matches) >= 1

    def test_detects_base64_exec(self):
        line = "www-data 5678 bash -c 'echo YmFzaQ== | base64 -d | bash'"
        matches = [p for p in SUSPICIOUS_PROCS if re.search(p, line, re.IGNORECASE)]
        assert len(matches) >= 1

    def test_normal_process_not_flagged(self):
        normal_lines = [
            "root 1 /sbin/init",
            "www-data 100 nginx: master process",
            "mysql 200 /usr/sbin/mysqld",
            "root 300 python3 /app/manage.py runserver",
        ]
        for line in normal_lines:
            matches = [p for p in SUSPICIOUS_PROCS if re.search(p, line, re.IGNORECASE)]
            assert len(matches) == 0, f"Falso positivo en: {line}"

    @pytest.mark.asyncio
    async def test_resource_limits_high_cpu(self):
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = "95.2%\t40.1%\t400MiB / 1GiB"

        container = {"name": "myapp", "image": "myapp:1.0"}
        with patch("cyberhound.scanners.runtime_scan.run_command",
                   new_callable=AsyncMock, return_value=proc):
            findings = await check_resource_limits(container)
        assert any(f.severity == "high" and "CPU" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_resource_limits_normal(self):
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = "15.0%\t30.0%\t300MiB / 1GiB"

        container = {"name": "myapp", "image": "myapp:1.0"}
        with patch("cyberhound.scanners.runtime_scan.run_command",
                   new_callable=AsyncMock, return_value=proc):
            findings = await check_resource_limits(container)
        assert findings == []

    @pytest.mark.asyncio
    async def test_container_diff_critical_file(self):
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = "C /etc/passwd\nC /etc/shadow\nA /tmp/newfile.sh"

        container = {"name": "myapp", "image": "myapp:1.0"}
        with patch("cyberhound.scanners.runtime_scan.run_command",
                   new_callable=AsyncMock, return_value=proc):
            findings = await check_container_diff(container)
        assert len(findings) >= 1
        assert any("passwd" in f.evidence or "passwd" in f.title for f in findings)
        assert any(f.severity == "critical" for f in findings)

    @pytest.mark.asyncio
    async def test_container_diff_no_critical_files(self):
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = "A /tmp/upload.txt\nC /var/www/html/index.html"

        container = {"name": "myapp", "image": "myapp:1.0"}
        with patch("cyberhound.scanners.runtime_scan.run_command",
                   new_callable=AsyncMock, return_value=proc):
            findings = await check_container_diff(container)
        assert findings == []
