"""
Tests del importador de auditorías externas.
Cubre: Nessus XML, XCCDF/OpenSCAP, CSV genérico, JSON, detección de formato.
"""
import pytest
from cyberhound.scanners.audit_import import (
    import_audit_file, detect_format,
    parse_nessus, parse_xccdf, parse_csv,
    cvss_to_severity, _xccdf_category, _nessus_category,
)


# ── Fixtures de contenido de ejemplo ─────────────────────────────────────────

NESSUS_SAMPLE = '''<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="Scan Result">
    <ReportHost name="192.168.1.100">
      <ReportItem port="22" svc_name="ssh" protocol="tcp"
                  severity="3" pluginID="10267" pluginName="SSH Server Type and Version Information">
        <synopsis>An SSH server is listening on this port.</synopsis>
        <description>It is possible to obtain information about the remote SSH server.</description>
        <solution>Upgrade to the latest version of OpenSSH.</solution>
        <cvss_base_score>5.0</cvss_base_score>
      </ReportItem>
      <ReportItem port="443" svc_name="https" protocol="tcp"
                  severity="4" pluginID="51192" pluginName="SSL Certificate Cannot Be Trusted">
        <cve>CVE-2021-3449</cve>
        <cvss3_base_score>9.1</cvss3_base_score>
        <synopsis>SSL certificate validation failed.</synopsis>
        <solution>Purchase or generate a proper SSL certificate.</solution>
      </ReportItem>
      <ReportItem port="0" svc_name="" protocol="tcp"
                  severity="0" pluginID="19506" pluginName="Nessus Scan Information">
        <description>Informational finding.</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>'''

XCCDF_SAMPLE = '''<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_rhel9_benchmark">
  <title>Red Hat Enterprise Linux 9 CIS Benchmark</title>
  <version>1.0</version>
  <Rule id="xccdf_rule_ssh_permitrootlogin" severity="high">
    <title>Ensure SSH PermitRootLogin is disabled</title>
    <description>The PermitRootLogin parameter specifies whether root can log in using ssh.</description>
    <fixtext>Edit /etc/ssh/sshd_config and set: PermitRootLogin no</fixtext>
  </Rule>
  <Rule id="xccdf_rule_auditd_enabled" severity="medium">
    <title>Ensure auditd is installed and enabled</title>
    <description>The auditd daemon is the userspace component to the Linux Auditing System.</description>
    <fix>yum install audit; systemctl enable auditd</fix>
  </Rule>
  <TestResult id="xccdf_result_1">
    <target>rhel9-server.company.com</target>
    <score>65.0</score>
    <rule-result idref="xccdf_rule_ssh_permitrootlogin" severity="high">
      <result>fail</result>
    </rule-result>
    <rule-result idref="xccdf_rule_auditd_enabled" severity="medium">
      <result>pass</result>
    </rule-result>
  </TestResult>
</Benchmark>'''

CSV_SAMPLE = """Vulnerability,Severity,Host,Description,Solution,CVE
SQL Injection in login form,High,192.168.1.5,User input is not sanitized.,Use parameterized queries.,CVE-2021-1234
Weak SSL cipher,Medium,192.168.1.10,RC4 cipher is enabled.,Disable weak ciphers.,
Open RDP port,Low,192.168.1.20,RDP is exposed to internet.,Restrict access with firewall.,"""

JSON_SAMPLE = '''[
  {"id": "j1", "category": "vulnerability/web", "severity": "critical",
   "title": "Remote Code Execution", "description": "RCE via deserialization",
   "remediation": "Update the framework", "source_host": "10.0.0.1"},
  {"id": "j2", "category": "compliance/ssh", "severity": "high",
   "title": "SSH root login enabled", "description": "PermitRootLogin yes",
   "remediation": "Set PermitRootLogin no"}
]'''


# ── detect_format ─────────────────────────────────────────────────────────────

class TestDetectFormat:

    def test_nessus_by_extension(self):
        assert detect_format(b"", "scan.nessus") == "nessus"

    def test_nessus_by_content(self):
        assert detect_format(b"<NessusClientData_v2>", "scan.xml") == "nessus"

    def test_csv_by_extension(self):
        assert detect_format(b"a,b,c\n1,2,3", "results.csv") == "csv"

    def test_json_by_content(self):
        assert detect_format(b'[{"a":1}]', "data.json") == "json"

    def test_xccdf_by_content(self):
        content = b'<?xml?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">'
        assert detect_format(content, "rhel9.xml") == "xccdf"

    def test_unknown_format(self):
        result = detect_format(b"random binary data \x00\x01", "file.bin")
        assert result == "unknown"


# ── parse_nessus ──────────────────────────────────────────────────────────────

class TestNessusParser:

    def test_parses_basic_nessus(self):
        result = parse_nessus(NESSUS_SAMPLE)
        assert result.source == "nessus"
        assert result.imported >= 1

    def test_skips_informational(self):
        result = parse_nessus(NESSUS_SAMPLE)
        # severity=0 (informational) debe saltarse
        assert result.skipped >= 1

    def test_cvss3_overrides_severity(self):
        """CVSS 9.1 debe mapear a critical."""
        result = parse_nessus(NESSUS_SAMPLE)
        crits = [f for f in result.findings if f.severity == "critical"]
        assert len(crits) >= 1

    def test_cve_in_evidence(self):
        """CVEs deben aparecer en la evidencia."""
        result = parse_nessus(NESSUS_SAMPLE)
        cve_findings = [f for f in result.findings if "CVE" in (f.evidence or "")]
        assert len(cve_findings) >= 1

    def test_source_host_set(self):
        """El host de cada finding es la IP del ReportHost."""
        result = parse_nessus(NESSUS_SAMPLE)
        assert all(f.source_host == "192.168.1.100" for f in result.findings)

    def test_category_is_vulnerability(self):
        """Todos los findings Nessus son vulnerability/*."""
        result = parse_nessus(NESSUS_SAMPLE)
        assert all(f.category.startswith("vulnerability/") for f in result.findings)

    def test_invalid_xml_returns_error(self):
        result = parse_nessus("<not valid xml")
        assert len(result.errors) >= 1
        assert result.imported == 0

    def test_empty_content(self):
        result = parse_nessus("")
        assert isinstance(result.findings, list)


# ── parse_xccdf ───────────────────────────────────────────────────────────────

class TestXCCDFParser:

    def test_parses_basic_xccdf(self):
        result = parse_xccdf(XCCDF_SAMPLE)
        assert result.source == "xccdf"
        assert result.imported >= 1

    def test_pass_rules_skipped(self):
        """Las reglas con resultado 'pass' no generan findings."""
        result = parse_xccdf(XCCDF_SAMPLE)
        # auditd_enabled tiene pass — no debe generar finding
        auditd_findings = [f for f in result.findings if "auditd" in f.id]
        assert len(auditd_findings) == 0
        assert result.skipped >= 1

    def test_fail_rules_generate_findings(self):
        """Las reglas con resultado 'fail' generan findings."""
        result = parse_xccdf(XCCDF_SAMPLE)
        ssh_findings = [f for f in result.findings if "ssh" in f.id.lower()]
        assert len(ssh_findings) >= 1

    def test_category_is_compliance(self):
        """Todos los findings XCCDF son compliance/*."""
        result = parse_xccdf(XCCDF_SAMPLE)
        assert all(f.category.startswith("compliance/") for f in result.findings)

    def test_title_extracted_from_rule(self):
        """El título se extrae de la definición de la regla."""
        result = parse_xccdf(XCCDF_SAMPLE)
        assert any("PermitRootLogin" in (f.title or "") for f in result.findings)

    def test_host_extracted_from_test_result(self):
        """El host se extrae del elemento <target> del TestResult."""
        result = parse_xccdf(XCCDF_SAMPLE)
        assert all("rhel9-server" in (f.source_host or "") for f in result.findings)

    def test_metadata_benchmark(self):
        """Los metadatos incluyen el nombre del benchmark."""
        result = parse_xccdf(XCCDF_SAMPLE)
        assert "benchmark" in result.metadata
        assert "CIS" in result.metadata["benchmark"] or "Red Hat" in result.metadata["benchmark"]

    def test_metadata_score(self):
        """Los metadatos incluyen el score si está presente."""
        result = parse_xccdf(XCCDF_SAMPLE)
        assert "score" in result.metadata
        assert result.metadata["score"] == 65.0


# ── parse_csv ─────────────────────────────────────────────────────────────────

class TestCSVParser:

    def test_parses_basic_csv(self):
        result = parse_csv(CSV_SAMPLE)
        assert result.source == "csv"
        assert result.imported == 3

    def test_severity_mapping(self):
        result = parse_csv(CSV_SAMPLE)
        highs = [f for f in result.findings if f.severity == "high"]
        assert len(highs) >= 1

    def test_cve_in_evidence(self):
        result = parse_csv(CSV_SAMPLE)
        cve_findings = [f for f in result.findings if "CVE" in (f.evidence or "")]
        assert len(cve_findings) >= 1

    def test_host_in_source_host(self):
        result = parse_csv(CSV_SAMPLE)
        assert all(f.source_host for f in result.findings)

    def test_empty_csv(self):
        result = parse_csv("Title,Severity\n")
        assert isinstance(result.findings, list)

    def test_csv_with_bom(self):
        """CSV con BOM UTF-8 se parsea correctamente."""
        bom_csv = b"\xef\xbb\xbfVulnerability,Severity,Host\nSQL Injection,High,10.0.0.1\n"
        result = parse_csv(bom_csv)
        assert result.imported >= 1


# ── import_audit_file (dispatcher) ───────────────────────────────────────────

class TestImportDispatcher:

    def test_auto_detect_nessus(self):
        result = import_audit_file(NESSUS_SAMPLE.encode(), "scan.nessus")
        assert result.source == "nessus"
        assert result.imported >= 1

    def test_auto_detect_xccdf(self):
        result = import_audit_file(XCCDF_SAMPLE.encode(), "rhel9.xml")
        assert result.source == "xccdf"

    def test_auto_detect_csv(self):
        result = import_audit_file(CSV_SAMPLE.encode(), "results.csv")
        assert result.source == "csv"

    def test_auto_detect_json(self):
        result = import_audit_file(JSON_SAMPLE.encode(), "findings.json")
        assert result.source == "json"
        assert result.imported == 2

    def test_force_format(self):
        """Se puede forzar el formato explícitamente."""
        result = import_audit_file(NESSUS_SAMPLE.encode(), "unknown_file", fmt="nessus")
        assert result.source == "nessus"

    def test_unknown_format_returns_error(self):
        result = import_audit_file(b"random content", "file.xyz", fmt="binary")
        assert len(result.errors) >= 1
        assert result.imported == 0

    def test_json_compliance_category(self):
        """JSON con compliance/* mantiene la categoría."""
        result = import_audit_file(JSON_SAMPLE.encode(), "f.json")
        compliance = [f for f in result.findings if f.category.startswith("compliance/")]
        assert len(compliance) >= 1

    def test_json_vulnerability_category(self):
        """JSON con vulnerability/* mantiene la categoría."""
        result = import_audit_file(JSON_SAMPLE.encode(), "f.json")
        vulns = [f for f in result.findings if f.category.startswith("vulnerability/")]
        assert len(vulns) >= 1


# ── Utilidades ────────────────────────────────────────────────────────────────

class TestUtilities:

    def test_cvss_to_severity(self):
        assert cvss_to_severity(9.5) == "critical"
        assert cvss_to_severity(9.0) == "critical"
        assert cvss_to_severity(8.9) == "high"
        assert cvss_to_severity(7.0) == "high"
        assert cvss_to_severity(6.9) == "medium"
        assert cvss_to_severity(4.0) == "medium"
        assert cvss_to_severity(3.9) == "low"
        assert cvss_to_severity(0.0) == "info"

    def test_xccdf_category_ssh(self):
        assert _xccdf_category("xccdf_rule_ssh_config", "SSH PermitRootLogin") == "compliance/ssh"

    def test_xccdf_category_firewall(self):
        assert _xccdf_category("xccdf_rule_firewall", "Enable firewalld") == "compliance/firewall"

    def test_xccdf_category_kernel(self):
        assert _xccdf_category("xccdf_rule_sysctl", "kernel.randomize_va_space") == "compliance/kernel"

    def test_xccdf_category_default(self):
        assert _xccdf_category("xccdf_rule_unknown_check", "Some other check") == "compliance/system"

    def test_nessus_category_cve(self):
        assert _nessus_category("OpenSSL Vulnerability", "https", ["CVE-2021-1234"]) == "vulnerability/cve"

    def test_nessus_category_ssh(self):
        assert _nessus_category("SSH Version Detection", "ssh", []) == "vulnerability/ssh"

    def test_nessus_category_tls(self):
        assert _nessus_category("SSL Certificate Problem", "https", []) == "vulnerability/tls"
