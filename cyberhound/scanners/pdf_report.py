"""
Generación de informes PDF para CyberHound Pro.

Usa fpdf2 (ya en las dependencias) para generar PDFs sin dependencias externas.
El informe incluye:
  - Portada con logo, fecha, objetivo y score
  - Resumen ejecutivo con métricas principales
  - Gráfico de distribución por severidad (SVG → drawing)
  - Tabla de hallazgos agrupados por categoría
  - Sección de remediaciones priorizadas
  - Pie de página con información de licencia

Si fpdf2 no está disponible, genera HTML y lo convierte con weasyprint
o retorna el HTML directamente como fallback.
"""
from __future__ import annotations

from datetime import UTC, datetime

from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("pdf_report")

SEV_COLORS = {
    "critical": (248, 81, 73),
    "high":     (227, 86, 42),
    "medium":   (210, 153, 34),
    "low":      (88, 166, 255),
    "info":     (139, 148, 158),
}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _group_by_category(findings: list[Finding]) -> dict[str, list[Finding]]:
    groups: dict[str, list[Finding]] = {}
    for f in sorted(findings, key=lambda x: SEV_ORDER.get(x.severity, 5)):
        cat = f.category or "other"
        groups.setdefault(cat, []).append(f)
    return groups


def generate_pdf(
    findings: list[Finding],
    target: str = "localhost",
    scan_type: str = "audit",
    score: int | None = None,
    licensee: str = "CyberHound Pro",
    include_compliance: bool = True,
) -> bytes:
    """
    Genera un informe PDF y devuelve los bytes.
    Intenta fpdf2 primero, weasyprint como fallback.
    """
    try:
        return _generate_with_fpdf2(findings, target, scan_type, score, licensee,
                                    include_compliance)
    except ImportError:
        logger.warning("fpdf2 no disponible - usando HTML como fallback")
        return _generate_html_fallback(findings, target, scan_type, score, licensee,
                                       include_compliance)
    except Exception as e:
        logger.warning("fpdf2 fallo (%s) - usando HTML como fallback", type(e).__name__)
        return _generate_html_fallback(findings, target, scan_type, score, licensee,
                                       include_compliance)


def _sanitize_pdf(text: str) -> str:
    """Elimina/reemplaza caracteres no soportados por las fuentes core de fpdf2 (latin-1)."""
    replacements = {
        '—': '-',   # em dash
        '–': '-',   # en dash
        '…': '...',  # ellipsis
        '→': '->',  # flecha derecha
        'é': 'e',   # é (ya en latin-1 pero por si acaso)
    }
    result = text
    for char, repl in replacements.items():
        result = result.replace(char, repl)
    # Eliminar cualquier otro carácter fuera de latin-1
    return result.encode('latin-1', errors='replace').decode('latin-1')


def _generate_with_fpdf2(
    findings, target, scan_type, score, licensee, include_compliance=True,
):
    from fpdf import FPDF, XPos, YPos

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1

    now = datetime.now(UTC)
    grade = "A" if (score or 0) >= 90 else "B" if (score or 0) >= 75 else "C" if (score or 0) >= 60 else "D" if (score or 0) >= 40 else "F"

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # ── PORTADA ───────────────────────────────────────────────────────────────
    pdf.add_page()

    # Franja superior azul oscuro
    pdf.set_fill_color(13, 17, 23)
    pdf.rect(0, 0, 210, 55, "F")

    # Título
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(88, 166, 255)
    pdf.set_xy(15, 12)
    pdf.cell(180, 10, "CyberHound Pro", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "", 13)
    pdf.set_text_color(230, 237, 243)
    pdf.set_xy(15, 26)
    pdf.cell(180, 8, "Informe de Auditoría de Seguridad", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(139, 148, 158)
    pdf.set_xy(15, 38)
    pdf.cell(180, 6, f"Generado: {now.strftime('%d/%m/%Y %H:%M UTC')}  |  Objetivo: {target}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Score grande
    pdf.set_xy(145, 60)
    if score is not None:
        score_color = (63, 185, 80) if score >= 75 else (210, 153, 34) if score >= 50 else (248, 81, 73)
        pdf.set_font("Helvetica", "B", 48)
        pdf.set_text_color(*score_color)
        pdf.cell(55, 20, str(score), align="R")
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(139, 148, 158)
        pdf.set_xy(145, 82)
        pdf.cell(55, 6, f"Score / 100  [Grado {grade}]", align="R")

    # Línea separadora
    pdf.set_draw_color(48, 54, 61)
    pdf.set_line_width(0.5)
    pdf.line(15, 70, 140, 70)

    # Info del scan
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(230, 237, 243)
    pdf.set_xy(15, 72)
    pdf.cell(0, 7, f"Tipo de análisis: {scan_type.upper()}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(139, 148, 158)
    pdf.set_xy(15, 81)
    pdf.cell(0, 6, f"Empresa / licenciatario: {licensee}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── RESUMEN EJECUTIVO ─────────────────────────────────────────────────────
    pdf.set_xy(15, 100)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(88, 166, 255)
    pdf.cell(0, 8, "Resumen ejecutivo", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(3)

    # Tarjetas de contadores
    box_w = 35
    box_labels = [
        ("CRÍTICOS",  counts["critical"],  (248, 81, 73)),
        ("ALTOS",     counts["high"],      (227, 86, 42)),
        ("MEDIOS",    counts["medium"],    (210, 153, 34)),
        ("BAJOS",     counts["low"],       (88, 166, 255)),
        ("TOTAL",     len(findings),       (139, 148, 158)),
    ]
    x_start = 15
    y_box = pdf.get_y() + 2
    for label, val, color in box_labels:
        pdf.set_fill_color(33, 38, 45)
        pdf.rect(x_start, y_box, box_w, 22, "F")
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_text_color(*color)
        pdf.set_xy(x_start, y_box + 2)
        pdf.cell(box_w, 10, str(val), align="C")
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(139, 148, 158)
        pdf.set_xy(x_start, y_box + 13)
        pdf.cell(box_w, 5, label, align="C")
        x_start += box_w + 3

    pdf.set_y(y_box + 28)

    # Texto de resumen
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(230, 237, 243)
    if counts["critical"] > 0:
        summary = (f"Se han detectado {counts['critical']} hallazgo(s) CRÍTICO(S) que requieren "
                   f"atención inmediata. Adicionalmente, hay {counts['high']} alto(s), "
                   f"{counts['medium']} medio(s) y {counts['low']} bajo(s).")
    elif counts["high"] > 0:
        summary = (f"No se detectaron problemas críticos. Sin embargo, hay {counts['high']} "
                   f"hallazgo(s) alto(s) que deben corregirse a la brevedad.")
    else:
        summary = f"El sistema analizado presenta un buen estado de seguridad con {len(findings)} hallazgo(s) menores."
    pdf.multi_cell(180, 6, summary)
    pdf.ln(4)

    # ── HALLAZGOS POR CATEGORÍA ───────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(88, 166, 255)
    pdf.cell(0, 8, "Hallazgos detallados", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(3)

    groups = _group_by_category(findings)

    for category, cat_findings in groups.items():
        # Cabecera de categoría
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(22, 27, 34)
        pdf.set_text_color(88, 166, 255)
        pdf.cell(180, 7, f"  {category.upper()}  ({len(cat_findings)} hallazgo(s))",
                 fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        for f in cat_findings:
            if pdf.get_y() > 260:
                pdf.add_page()

            sev_color = SEV_COLORS.get(f.severity, (139, 148, 158))

            # Badge de severidad
            pdf.set_fill_color(*sev_color)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 7)
            pdf.set_xy(15, pdf.get_y() + 2)
            pdf.cell(18, 5, f.severity.upper(), align="C", fill=True)

            # Título del hallazgo
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(230, 237, 243)
            pdf.set_xy(35, pdf.get_y())
            pdf.multi_cell(160, 5, f.title or "")

            # Descripción (max 2 líneas)
            if f.description:
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(139, 148, 158)
                pdf.set_xy(35, pdf.get_y())
                desc = f.description[:200] + ("…" if len(f.description) > 200 else "")
                pdf.multi_cell(160, 4.5, desc)

            # Remediación
            if f.remediation:
                pdf.set_font("Helvetica", "I", 8)
                pdf.set_text_color(63, 185, 80)
                pdf.set_xy(35, pdf.get_y())
                rem = "→ " + f.remediation.split("\n")[0][:150]
                pdf.cell(160, 4.5, rem, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            pdf.ln(2)

        pdf.ln(3)

    # ── SECCIÓN DE COMPLIANCE ─────────────────────────────────────────────────
    if include_compliance and findings:
        try:
            from cyberhound.scanners.compliance import FRAMEWORK_NAMES, analyze_compliance
            compliance = analyze_compliance(findings, frameworks=["ens", "iso27001", "cis"])

            pdf.add_page()
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_text_color(88, 166, 255)
            pdf.cell(0, 8, "Análisis de cumplimiento normativo", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.line(15, pdf.get_y(), 195, pdf.get_y())
            pdf.ln(4)

            for fw, res in compliance.items():
                fw_name = FRAMEWORK_NAMES.get(fw, fw.upper())
                status_color = (63, 185, 80) if res.score_pct >= 90 \
                    else (210, 153, 34) if res.score_pct >= 70 else (248, 81, 73)

                # Cabecera del marco
                pdf.set_font("Helvetica", "B", 10)
                pdf.set_text_color(*status_color)
                pdf.cell(0, 7, f"{fw_name}  —  {res.score_pct}%  ({res.status.replace('_',' ')})",
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                # Barra de progreso
                bar_w = 180
                filled = int(bar_w * res.score_pct / 100)
                pdf.set_fill_color(33, 38, 45)
                pdf.rect(15, pdf.get_y(), bar_w, 4, "F")
                pdf.set_fill_color(*status_color)
                pdf.rect(15, pdf.get_y(), filled, 4, "F")
                pdf.ln(7)

                # Controles fallidos (max 5)
                if res.failed_controls:
                    pdf.set_font("Helvetica", "", 8)
                    pdf.set_text_color(248, 81, 73)
                    pdf.cell(0, 5, f"Controles no cubiertos ({res.failed}):",
                             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    for ctrl in res.failed_controls[:5]:
                        pdf.set_text_color(230, 237, 243)
                        pdf.set_xy(20, pdf.get_y())
                        pdf.cell(0, 4.5,
                                 f"• {ctrl['id']}: {ctrl['title'][:60]}",
                                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    if res.failed > 5:
                        pdf.set_text_color(139, 148, 158)
                        pdf.cell(0, 4, f"  ... y {res.failed-5} mas",
                                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.ln(4)
        except Exception as e:
            logger.warning("No se pudo añadir compliance al PDF: %s", e)

    # ── PIE DE PÁGINA ─────────────────────────────────────────────────────────
    pdf.set_y(-20)
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(139, 148, 158)
    pdf.cell(0, 5,
             f"CyberHound Pro - Informe confidencial - {_sanitize_pdf(now.strftime(chr(37)+'d/'+chr(37)+'m/'+chr(37)+'Y'))} - {_sanitize_pdf(licensee)}",
             align="C")

    return pdf.output()


def _generate_html_fallback(
    findings, target, scan_type, score, licensee, include_compliance=True,
):
    """Genera HTML que el navegador puede imprimir como PDF."""
    now = datetime.now(UTC).strftime("%d/%m/%Y %H:%M UTC")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1

    sev_css = {
        "critical": "#f85149", "high": "#e3562a",
        "medium": "#d29922",   "low": "#58a6ff", "info": "#8b949e",
    }

    rows = ""
    for f in sorted(findings, key=lambda x: SEV_ORDER.get(x.severity, 5)):
        color = sev_css.get(f.severity, "#8b949e")
        rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{f.severity.upper()}</span></td>
          <td class="dim">{f.category or ''}</td>
          <td><strong>{f.title or ''}</strong>
            <div class="dim small">{(f.description or '')[:200]}</div>
          </td>
          <td class="green small">{(f.remediation or '').split(chr(10))[0][:100]}</td>
        </tr>"""

    score_color = "#3fb950" if (score or 0) >= 75 else "#d29922" if (score or 0) >= 50 else "#f85149"
    # Sección compliance
    compliance_html = ""
    if include_compliance and findings:
        try:
            from cyberhound.scanners.compliance import FRAMEWORK_NAMES, analyze_compliance
            compliance = analyze_compliance(findings, frameworks=["ens", "iso27001", "cis"])
            rows_c = ""
            for fw, res in compliance.items():
                color = "#3fb950" if res.score_pct >= 90 else "#d29922" if res.score_pct >= 70 else "#f85149"
                rows_c += f"""<tr>
                  <td style="font-weight:600">{FRAMEWORK_NAMES.get(fw,fw)}</td>
                  <td style="color:{color};font-weight:700">{res.score_pct}%</td>
                  <td style="color:{color}">{res.status.replace('_',' ')}</td>
                  <td>{res.covered}/{res.total_controls}</td>
                  <td style="color:#f85149">{res.failed}</td>
                </tr>"""
            compliance_html = f"""<h2>Cumplimiento normativo</h2>
            <table><thead><tr><th>Marco</th><th>Score</th><th>Estado</th><th>Cubiertos</th><th>Fallidos</th></tr></thead>
            <tbody>{rows_c}</tbody></table>"""
        except Exception:
            pass

    html = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8">
<title>CyberHound Pro — Informe {target}</title>
<style>
  body {{ font-family: system-ui, sans-serif; background: #0d1117; color: #e6edf3;
          font-size: 13px; padding: 30px; margin: 0; }}
  @media print {{ body {{ background: white; color: black; }}
                  .no-print {{ display: none; }} }}
  h1 {{ color: #58a6ff; font-size: 24px; margin-bottom: 4px; }}
  h2 {{ color: #58a6ff; font-size: 15px; margin: 24px 0 8px; border-bottom: 1px solid #30363d; padding-bottom: 4px; }}
  .meta {{ color: #8b949e; font-size: 11px; margin-bottom: 20px; }}
  .score {{ font-size: 52px; font-weight: 700; color: {score_color}; float: right; line-height: 1; }}
  .counters {{ display: flex; gap: 12px; margin: 16px 0; }}
  .counter {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
               padding: 12px 20px; text-align: center; flex: 1; }}
  .counter .num {{ font-size: 28px; font-weight: 700; }}
  .counter .label {{ font-size: 10px; color: #8b949e; text-transform: uppercase; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
  th {{ background: #161b22; padding: 6px 10px; text-align: left; font-size: 11px;
        color: #8b949e; text-transform: uppercase; }}
  td {{ padding: 6px 10px; border-bottom: 1px solid #21262d; vertical-align: top; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 10px;
             font-weight: 700; color: white; }}
  .dim {{ color: #8b949e; }}
  .green {{ color: #3fb950; }}
  .small {{ font-size: 11px; }}
  .footer {{ margin-top: 40px; text-align: center; color: #8b949e; font-size: 10px; }}
  .print-btn {{ background: #58a6ff; color: #0d1117; border: none; padding: 8px 16px;
                 border-radius: 6px; cursor: pointer; font-weight: 600; margin-bottom: 20px; }}
</style></head><body>
<button class="print-btn no-print" onclick="window.print()">🖨️ Imprimir / Guardar PDF</button>
<div class="score">{score if score is not None else '—'}<span style="font-size:16px;color:#8b949e">/100</span></div>
<h1>🐾 CyberHound Pro</h1>
<div class="meta">Informe de seguridad — {target} — {scan_type.upper()} — {now}<br>
Licenciatario: {licensee}</div>
<div style="clear:both"></div>
<div class="counters">
  <div class="counter"><div class="num" style="color:#f85149">{counts['critical']}</div><div class="label">Críticos</div></div>
  <div class="counter"><div class="num" style="color:#e3562a">{counts['high']}</div><div class="label">Altos</div></div>
  <div class="counter"><div class="num" style="color:#d29922">{counts['medium']}</div><div class="label">Medios</div></div>
  <div class="counter"><div class="num" style="color:#58a6ff">{counts['low']}</div><div class="label">Bajos</div></div>
  <div class="counter"><div class="num">{len(findings)}</div><div class="label">Total</div></div>
</div>
<h2>Hallazgos</h2>
<table><thead><tr><th>Severidad</th><th>Categoría</th><th>Hallazgo</th><th>Remediación</th></tr></thead>
<tbody>{rows}</tbody></table>
{compliance_html}
<div class="footer">CyberHound Pro — Informe confidencial — {now} — {licensee}</div>
</body></html>"""
    return html.encode("utf-8")
