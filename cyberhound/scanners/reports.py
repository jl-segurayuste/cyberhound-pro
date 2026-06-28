"""Generación de informes HTML y playbooks Ansible."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding, ScanReport

if TYPE_CHECKING:
    pass

logger = get_logger("reports")

_SEV_COLOR = {
    "critical": "#c0392b", "high": "#e3562a",
    "medium": "#d29922",   "low": "#3498db", "info": "#95a5a6",
}


class ReportGenerator:

    @staticmethod
    async def html_report(report: ScanReport) -> str:
        report.compute_stats()
        failed = [f for f in report.local_findings if not f.passed]
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        failed.sort(key=lambda x: sev_order.get(x.severity, 5))

        stats_html = "".join(
            f'<span style="background:{_SEV_COLOR.get(s,"#666")};color:white;'
            f'padding:6px 14px;border-radius:8px;font-weight:700;margin:4px">'
            f'{s.upper()}: {c}</span>'
            for s, c in sorted(
                report.statistics.items(),
                key=lambda x: sev_order.get(x[0], 5),
            )
        )

        rows = ""
        for f in failed:
            color = _SEV_COLOR.get(f.severity, "#666")
            rows += (
                f"<tr>"
                f"<td><span style='color:{color};font-weight:700'>{f.severity.upper()}</span></td>"
                f"<td style='color:#888'>{f.category}</td>"
                f"<td>{_h(f.title)}</td>"
                f"<td style='font-family:monospace;font-size:.8em'>{_h(f.remediation[:200])}</td>"
                f"<td>{'⚡' if f.auto_fix else ''}</td>"
                f"</tr>\n"
            )

        return f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8">
<title>CyberHound — {_h(report.target)}</title>
<style>
body{{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;margin:2rem}}
h1{{color:#58a6ff}}h2{{color:#8b949e;font-size:1rem;margin-top:1.5rem}}
table{{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden}}
th{{background:#21262d;padding:10px;text-align:left;font-size:.8rem;color:#8b949e}}
td{{padding:9px 10px;border-bottom:1px solid #21262d;font-size:.85rem;vertical-align:top}}
tr:hover{{background:#21262d}}.meta{{color:#8b949e;font-size:.85rem;margin-bottom:1rem}}
</style></head>
<body>
<h1>🐾 CyberHound Pro — Informe de Seguridad</h1>
<div class="meta">
  <b>Objetivo:</b> {_h(report.target)} &nbsp;|&nbsp;
  <b>Fecha:</b> {report.timestamp}
</div>
<h2>RESUMEN</h2>
<div style="margin-bottom:1.5rem">{stats_html}</div>
<h2>HALLAZGOS ({len(failed)})</h2>
<table>
<thead><tr><th>Severidad</th><th>Categoría</th><th>Hallazgo</th><th>Remediación</th><th>Fix</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</body></html>"""

    @staticmethod
    def ansible_playbook(findings: list[Finding]) -> str:
        tasks = [
            {
                "name": f"[CyberHound] {f.title}",
                "ansible.builtin.shell": f.remediation.split("\n")[0],
                "become": True,
                "tags": [f.category, f.severity],
            }
            for f in findings
            if f.auto_fix and f.remediation
        ]
        playbook = [{
            "name": "CyberHound Pro — Remediación automática",
            "hosts": "all",
            "become": True,
            "gather_facts": True,
            "tasks": tasks,
        }]
        return yaml.dump(playbook, default_flow_style=False, allow_unicode=True)


def _h(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
