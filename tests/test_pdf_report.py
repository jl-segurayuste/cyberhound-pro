"""El informe PDF sale como PDF real aunque los hallazgos traigan caracteres fuera de latin-1.

Bug real 2026-10-20: fpdf2 no estaba en las dependencias (el botón "Informe PDF"
descargaba HTML) y, ya instalado, cualquier "→", "…" o emoji en un hallazgo
lanzaba FPDFUnicodeEncodingException -- el propio código añade "→ " delante de
cada remediación, así que en la práctica el PDF nunca salía.
"""
from cyberhound.core.models import Finding
from cyberhound.scanners.pdf_report import generate_pdf


def test_pdf_real_con_caracteres_unicode():
    findings = [
        Finding(id="ssh_root_login", category="ssh", severity="critical",
                title="Login SSH como root — permitido “siempre”",
                description="PermitRootLogin yes… 🔥 en /etc/ssh/sshd_config",
                remediation="Establecer PermitRootLogin no → reiniciar sshd", auto_fix=True),
        Finding(id="x", category="kernel", severity="low", title="Ñandú ✓", description="", remediation="✔ ok"),
    ]
    pdf = generate_pdf(findings, target="demo-web-01", scan_type="audit", score=54, licensee="Community")
    assert pdf[:5] == b"%PDF-"
