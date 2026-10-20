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
    pdf = generate_pdf(findings, target="demo-web-01", scan_type="audit", score=54, organization="Demo S.L.")
    assert pdf[:5] == b"%PDF-"


def test_informe_html_escapa_lo_que_viene_de_fuera():
    """Títulos/categorías pueden venir de cabeceras web, CT logs o agentes: nunca HTML crudo."""
    from cyberhound.scanners.pdf_report import _generate_html_fallback
    evil = Finding(id="x", category="<img src=x onerror=alert(1)>", severity="high",
                   title="<script>alert(1)</script>", description="<b>d</b>", remediation="r")
    html = _generate_html_fallback([evil], "<svg onload=1>", "audit", 10, "<i>Org</i>").decode()
    assert "<script>alert" not in html and "<img src=x" not in html and "<svg onload" not in html
    assert "&lt;script&gt;" in html and "onclick=" not in html
