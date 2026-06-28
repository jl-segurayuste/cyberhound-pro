"""Tests de compliance normativo y generación de informes PDF."""
import pytest

from cyberhound.core.models import Finding
from cyberhound.scanners.compliance import (
    CATEGORY_TO_CONTROLS, FRAMEWORK_NAMES,
    analyze_compliance, compliance_to_dict,
)
from cyberhound.scanners.pdf_report import generate_pdf, _generate_html_fallback


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_finding(category, severity="high", fid=None):
    return Finding(
        id=fid or f"test_{category.replace('/','_')}",
        category=category, severity=severity,
        title=f"Test finding {category}", description="", remediation="fix it",
    )


# ── Compliance ────────────────────────────────────────────────────────────────

class TestCompliance:

    def test_empty_findings_full_compliance(self):
        results = analyze_compliance([])
        for fw, res in results.items():
            assert res.score_pct == 100.0
            assert res.failed == 0

    def test_ssh_finding_fails_ssh_controls(self):
        findings = [make_finding("ssh", "high")]
        results = analyze_compliance(findings, frameworks=["ens"])
        ens = results.get("ens")
        assert ens is not None
        assert ens.failed > 0
        # El control ENS-MP.SI.1 debe estar en los fallidos
        failed_ids = {c["id"] for c in ens.failed_controls}
        assert "ENS-MP.SI.1" in failed_ids

    def test_firewall_finding_fails_firewall_controls(self):
        findings = [make_finding("firewall", "critical")]
        results = analyze_compliance(findings, frameworks=["pci-dss"])
        pci = results.get("pci-dss")
        assert pci is not None
        assert pci.failed > 0
        failed_ids = {c["id"] for c in pci.failed_controls}
        assert "PCI-1.2" in failed_ids

    def test_malware_finding_fails_malware_controls(self):
        findings = [make_finding("malware/yara", "critical")]
        results = analyze_compliance(findings, frameworks=["iso27001"])
        iso = results.get("iso27001")
        assert iso is not None
        assert iso.failed > 0

    def test_framework_filter(self):
        findings = [make_finding("ssh")]
        results = analyze_compliance(findings, frameworks=["ens"])
        assert "ens" in results
        assert "iso27001" not in results
        assert "pci-dss" not in results

    def test_all_frameworks_analyzed_by_default(self):
        results = analyze_compliance([])
        assert "ens" in results
        assert "iso27001" in results
        assert "cis" in results

    def test_score_decreases_with_more_findings(self):
        one_finding   = analyze_compliance([make_finding("ssh")], ["ens"])
        multi_findings = analyze_compliance([
            make_finding("ssh"),
            make_finding("firewall"),
            make_finding("authentication"),
        ], ["ens"])
        assert multi_findings["ens"].score_pct <= one_finding["ens"].score_pct

    def test_compliance_to_dict_format(self):
        findings = [make_finding("ssh")]
        results  = analyze_compliance(findings, ["ens"])
        d = compliance_to_dict(results)
        assert "ens" in d
        ens = d["ens"]
        assert "score_pct" in ens
        assert "status" in ens
        assert "failed_controls" in ens
        assert "total_controls" in ens

    def test_status_conforme_when_no_failures(self):
        results = analyze_compliance([], ["ens"])
        assert results["ens"].status == "CONFORME"

    def test_status_no_conforme_with_many_failures(self):
        findings = [
            make_finding(cat) for cat in
            ["ssh", "firewall", "authentication", "malware/yara",
             "audit", "updates", "kernel"]
        ]
        results = analyze_compliance(findings, ["ens"])
        # Con muchos fallos debería ser no conforme o parcialmente conforme
        assert results["ens"].status in ("NO_CONFORME", "PARCIALMENTE_CONFORME")

    def test_failed_controls_have_required_fields(self):
        findings = [make_finding("ssh")]
        results  = analyze_compliance(findings, ["ens"])
        for ctrl in results["ens"].failed_controls:
            assert "id" in ctrl
            assert "title" in ctrl
            assert "priority" in ctrl
            assert "findings" in ctrl

    def test_category_mapping_coverage(self):
        """Verificar que al menos los 5 más comunes tienen controles mapeados."""
        important_categories = ["ssh", "firewall", "authentication", "malware/yara", "audit"]
        for cat in important_categories:
            assert cat in CATEGORY_TO_CONTROLS, f"Categoría '{cat}' sin mapeo de controles"

    def test_framework_names_complete(self):
        assert "ens"      in FRAMEWORK_NAMES
        assert "iso27001" in FRAMEWORK_NAMES
        assert "pci-dss"  in FRAMEWORK_NAMES
        assert "cis"      in FRAMEWORK_NAMES


# ── PDF Report ────────────────────────────────────────────────────────────────

class TestPDFReport:

    def test_html_fallback_generates_valid_html(self):
        findings = [
            Finding(id="f1", category="ssh", severity="critical",
                    title="SSH root login", description="", remediation="fix"),
            Finding(id="f2", category="firewall", severity="high",
                    title="UFW inactivo", description="", remediation="enable"),
        ]
        html = _generate_html_fallback(findings, "localhost", "audit", 65, "Test Corp")
        assert isinstance(html, bytes)
        decoded = html.decode("utf-8")
        assert "<!DOCTYPE html>" in decoded
        assert "CyberHound Pro" in decoded
        assert "SSH root login" in decoded
        assert "Test Corp" in decoded

    def test_html_includes_score(self):
        findings = []
        html = _generate_html_fallback(findings, "server1", "audit", 92, "ACME")
        decoded = html.decode()
        assert "92" in decoded

    def test_html_includes_all_severity_counts(self):
        findings = [
            Finding(id="c1", category="ssh", severity="critical", title="", description="", remediation=""),
            Finding(id="h1", category="fw", severity="high",     title="", description="", remediation=""),
            Finding(id="m1", category="fs", severity="medium",   title="", description="", remediation=""),
        ]
        html = _generate_html_fallback(findings, "host", "audit", 40, "Test")
        decoded = html.decode()
        assert "CRITICAL" in decoded or "critical" in decoded.lower()

    def test_generate_pdf_falls_back_to_html_if_fpdf_missing(self):
        import sys
        findings = [
            Finding(id="f1", category="ssh", severity="high",
                    title="Test", description="desc", remediation="fix"),
        ]
        # Forzar ImportError de fpdf
        orig = sys.modules.get('fpdf')
        sys.modules['fpdf'] = None
        try:
            result = generate_pdf(findings, "test-host", "audit", 70, "Test")
            assert isinstance(result, bytes)
            assert len(result) > 100
        finally:
            if orig is None:
                del sys.modules['fpdf']
            else:
                sys.modules['fpdf'] = orig

    def test_html_print_button_present(self):
        findings = []
        html = _generate_html_fallback(findings, "host", "audit", 100, "Corp")
        assert b"window.print()" in html

    def test_empty_findings_no_error(self):
        html = _generate_html_fallback([], "host", "audit", None, "Corp")
        assert isinstance(html, bytes)
        assert b"<!DOCTYPE html>" in html

    def test_remediation_truncated_at_100_chars(self):
        long_rem = "A" * 200
        findings = [
            Finding(id="f1", category="test", severity="low",
                    title="Long rem", description="", remediation=long_rem),
        ]
        html = _generate_html_fallback(findings, "host", "audit", 90, "Corp")
        decoded = html.decode()
        # No debe incluir los 200 chars completos
        assert "A" * 150 not in decoded
