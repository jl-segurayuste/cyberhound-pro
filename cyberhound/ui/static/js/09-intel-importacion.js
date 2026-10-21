// Inteligencia de amenazas e importación de auditorías externas.
// Se cargan en orden (ver index.html); comparten el ámbito global como si fueran un solo fichero.
'use strict';

// ══════════════════════════════════════════════════════════════════════════════
// PANEL DE INTELIGENCIA DE AMENAZAS
// ══════════════════════════════════════════════════════════════════════════════

// ── Cargar config de API keys de Intel ───────────────────────────────────────
async function loadIntelConfig() {
  try {
    const r = await fetch('/api/intel/config');
    if (!r.ok) return;
    const cfg = await r.json();
    const el = document.getElementById('intel-api-status');
    if (!el) return;

    const modules = [
      { key: 'shodan',     label: 'Shodan',     color: '#e67e22' },
      { key: 'virustotal', label: 'VirusTotal', color: '#3498db' },
      { key: 'abuseipdb',  label: 'AbuseIPDB',  color: '#e74c3c' },
      { key: 'greynoise',  label: 'GreyNoise',  color: '#2ecc71' },
      { key: 'hibp',       label: 'HIBP',       color: '#9b59b6' },
    ];

    el.innerHTML = modules.map(m => `
      <div style="display:flex;align-items:center;gap:6px;padding:5px 10px;
                  background:var(--bg2);border:1px solid var(--border);border-radius:6px;font-size:.78rem">
        <span style="width:8px;height:8px;border-radius:50%;flex-shrink:0;
                     background:${cfg[m.key] ? m.color : 'var(--text2)'}"></span>
        <span style="color:${cfg[m.key] ? 'var(--text)' : 'var(--text2)'}">${m.label}</span>
        <span style="color:${cfg[m.key] ? 'var(--green)' : 'var(--text2)'};font-size:.7rem">
          ${cfg[m.key] ? '✓ activo' : '✗ sin key'}
        </span>
      </div>`).join('');

    if (cfg.configured_count === 0) {
      el.innerHTML += `<div style="padding:5px 10px;color:var(--yellow);font-size:.78rem">
        ⚠ Sin API keys configuradas — ir a Config API Keys
      </div>`;
    }
  } catch(e) {}
}

// ── Búsqueda manual de IP/dominio ─────────────────────────────────────────────
async function runIntelLookup() {
  const target  = document.getElementById('intel-target')?.value.trim();
  const modules = [...document.querySelectorAll('.intel-mod:checked')].map(c => c.value);
  const btnEl   = document.getElementById('btn-intel-lookup');

  if (!target) { toast('Introduce una IP, dominio, hash o email', 'warning'); return; }

  if (btnEl) { btnEl.disabled = true; btnEl.textContent = 'Consultando…'; }
  _showIntelLoading();

  try {
    const params = new URLSearchParams({ target });
    if (modules.length) params.set('modules', modules.join(','));
    const r = await fetch(`/api/intel/lookup?${params}`);
    const d = await r.json();

    if (d.error) {
      _showIntelEmpty(`✗ Error: ${d.error}`);
      return;
    }

    _renderIntelResults(d);
    addActivityItem('intel', '', `Intel: ${target}`, `${d.count} hallazgos`, d.summary?.risk_level || 'info');

  } catch(e) {
    _showIntelEmpty(`✗ Error: ${e.message}`);
  } finally {
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'Consultar'; }
  }
}

// ── Scan masivo desde network scan ────────────────────────────────────────────
async function runIntelScan() {
  const btnEl = document.getElementById('btn-intel-scan');
  if (btnEl) { btnEl.disabled = true; btnEl.textContent = 'Analizando…'; }
  _showIntelLoading();

  try {
    const r = await fetch('/api/intel/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ targets: [], modules: [] }),
    });
    const d = await r.json();

    if (d.error) {
      _showIntelEmpty(`✗ ${d.error}`);
      return;
    }

    _renderIntelResults(d);
    toast(`✓ Intel scan: ${d.count} hallazgos en ${d.targets?.length || 0} targets`);

  } catch(e) {
    _showIntelEmpty(`✗ Error: ${e.message}`);
  } finally {
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'Analizar IPs del último scan de red'; }
  }
}

// ── Renderizar resultados de Intel ────────────────────────────────────────────
function _renderIntelResults(data) {
  const resultsEl = document.getElementById('intel-results');
  const emptyEl   = document.getElementById('intel-empty');
  const tbody     = document.getElementById('intel-tbody');
  const banner    = document.getElementById('intel-risk-banner');
  const cardsEl   = document.getElementById('intel-summary-cards');

  if (emptyEl) emptyEl.textContent = '';
  if (!data.findings?.length) {
    _showIntelEmpty('Sin hallazgos de threat intelligence para estos targets.');
    return;
  }

  if (resultsEl) resultsEl.style.display = '';

  // Banner de riesgo
  const riskColors = {
    critical: '#f85149', high: '#e3562a',
    medium: '#d29922',   low: '#58a6ff', none: 'var(--green)',
  };
  const risk = data.summary?.risk_level || 'none';
  const riskColor = riskColors[risk] || 'var(--text2)';
  if (banner) {
    banner.style.background = `${riskColor}22`;
    banner.style.borderLeft = `4px solid ${riskColor}`;
    banner.style.color = riskColor;
    banner.textContent = `Nivel de riesgo: ${risk.toUpperCase()} — ${data.count} hallazgo(s) en ${data.targets?.length || 1} target(s)`;
  }

  // Tarjetas de módulos
  if (cardsEl && data.summary?.by_module) {
    cardsEl.innerHTML = Object.entries(data.summary.by_module).map(([mod, count]) =>
      `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;
                   padding:8px 14px;font-size:.8rem;text-align:center">
        <div style="font-size:1.1rem;font-weight:700">${count}</div>
        <div style="color:var(--text2)">${mod}</div>
      </div>`
    ).join('');
  }

  // Tabla de hallazgos
  if (tbody) {
    const sevColors = { critical:'var(--critical)', high:'var(--high)', medium:'var(--medium)', low:'var(--text2)' };
    tbody.innerHTML = data.findings.map(f => {
      const cat = (f.category || '').split('/').pop();
      const target = f.evidence?.match(/(?:ip|domain|hash|email)=([^\s]+)/)?.[1] || '—';
      return `<tr ${on('click', 'openDrawer', f)}>
        <td>${sevBadge(f.severity)}</td>
        <td style="font-size:.78rem;color:var(--text2)">${esc(cat)}</td>
        <td style="font-family:monospace;font-size:.78rem">${esc(target)}</td>
        <td><b>${esc(f.title)}</b>
            <div style="font-size:.75rem;color:var(--text2)">${esc((f.description||'').substring(0,80))}</div>
        </td>
        <td style="font-size:.75rem;color:var(--text2);max-width:200px;overflow:hidden;text-overflow:ellipsis">
          ${esc((f.evidence||'').substring(0,100))}
        </td>
      </tr>`;
    }).join('');
  }
}

function _showIntelLoading() {
  const resultsEl = document.getElementById('intel-results');
  const emptyEl   = document.getElementById('intel-empty');
  if (resultsEl) resultsEl.style.display = 'none';
  if (emptyEl) emptyEl.innerHTML = '<div style="color:var(--text2);font-size:.85rem">Consultando fuentes de inteligencia…</div>';
}

function _showIntelEmpty(msg) {
  const resultsEl = document.getElementById('intel-results');
  const emptyEl   = document.getElementById('intel-empty');
  if (resultsEl) resultsEl.style.display = 'none';
  if (emptyEl) emptyEl.textContent = msg;
}

// ── Historial de Intel ────────────────────────────────────────────────────────
async function loadIntelHistory() {
  const histEl = document.getElementById('intel-history');
  const listEl = document.getElementById('intel-history-list');
  if (!histEl || !listEl) return;

  histEl.style.display = '';
  listEl.innerHTML = '<div style="color:var(--text2);font-size:.82rem">Cargando…</div>';

  try {
    const r = await fetch('/api/intel/history?limit=10');
    const history = await r.json();

    if (!history.length) {
      listEl.innerHTML = '<div style="color:var(--text2);font-size:.82rem">Sin scans de intel anteriores.</div>';
      return;
    }

    listEl.innerHTML = history.map(scan => `
      <div style="display:flex;gap:12px;padding:8px 0;border-bottom:1px solid var(--border);
                  font-size:.8rem;align-items:center;cursor:pointer"
           ${on('click', 'loadIntelScanDetail', scan.id)}>
        <span style="color:var(--text2)">${new Date(scan.started_at).toLocaleString('es')}</span>
        <span>${_scorePill(scan.score)}</span>
        <span style="color:var(--text2)">${scan.total_findings || 0} hallazgos</span>
        <span style="color:var(--red)">${scan.critical || 0} críticos</span>
      </div>`).join('');
  } catch(e) {
    listEl.innerHTML = `<div style="color:var(--red);font-size:.82rem">Error: ${esc(e.message)}</div>`;
  }
}

async function loadIntelScanDetail(scanId) {
  try {
    const r = await fetch(`/api/history/${scanId}`);
    const findings = await r.json();
    _renderIntelResults({ findings, count: findings.length, targets: [], summary: null });
  } catch(e) {}
}

// ══════════════════════════════════════════════════════════════════════════════
// IMPORTACIÓN DE AUDITORÍAS EXTERNAS (Nessus, XCCDF/OpenSCAP, CSV, JSON)
// ══════════════════════════════════════════════════════════════════════════════

function onImportFileChange(input) {
  const btnEl = document.getElementById('btn-import');
  const file  = input.files?.[0];
  if (!file) { if (btnEl) btnEl.disabled = true; return; }
  if (btnEl) btnEl.disabled = false;

  // Auto-seleccionar formato según extensión
  const fmt    = document.getElementById('import-format');
  const ext    = file.name.split('.').pop().toLowerCase();
  if (fmt) {
    if (ext === 'nessus')                           fmt.value = 'nessus';
    else if (ext === 'csv')                         fmt.value = 'csv';
    else if (ext === 'json')                        fmt.value = 'json';
    else if (ext === 'xml')                         fmt.value = '';  // auto-detectar entre nessus y xccdf
  }
}

async function importAuditFile() {
  const fileInput  = document.getElementById('import-file');
  const formatSel  = document.getElementById('import-format');
  const targetIn   = document.getElementById('import-target');
  const btnEl      = document.getElementById('btn-import');
  const resultEl   = document.getElementById('import-result');
  const summaryEl  = document.getElementById('import-summary');
  const tbodyEl    = document.getElementById('import-preview-tbody');
  const errorEl    = document.getElementById('import-error');

  const file = fileInput?.files?.[0];
  if (!file) { toast('Selecciona un fichero de auditoría', 'warning'); return; }

  if (btnEl) { btnEl.disabled = true; btnEl.textContent = 'Importando…'; }
  if (resultEl) resultEl.style.display = 'none';
  if (errorEl)  errorEl.textContent = '';

  const formData = new FormData();
  formData.append('file',   file);
  formData.append('target', targetIn?.value || file.name);
  if (formatSel?.value) formData.append('format', formatSel.value);

  try {
    const r = await fetch('/api/import/audit', { method: 'POST', body: formData });
    const d = await r.json();

    if (!r.ok || d.error) {
      if (errorEl) errorEl.textContent = `✗ ${d.error || 'Error desconocido'}`;
      return;
    }

    // Mostrar resumen
    if (resultEl) resultEl.style.display = '';
    if (summaryEl) {
      const typeLabel = d.source === 'xccdf' ? 'Cumplimiento/bastionado' : 'Vulnerabilidades';
      summaryEl.innerHTML = `
        <div style="display:flex;gap:16px;flex-wrap:wrap">
          <span><strong>Formato:</strong> ${esc(d.source)}</span>
          <span><strong>Tipo:</strong> ${typeLabel}</span>
          <span style="color:var(--green)"><strong>Importados:</strong> ${d.imported}</span>
          <span style="color:var(--text2)"><strong>Omitidos:</strong> ${d.skipped}</span>
          <span><strong>Scan ID:</strong> #${d.scan_id}</span>
        </div>
        ${d.metadata?.benchmark ? `<div style="margin-top:4px;color:var(--text2)">Benchmark: ${esc(d.metadata.benchmark)}</div>` : ''}
        ${d.errors?.length ? `<div style="color:var(--yellow);margin-top:4px">⚠ Avisos: ${d.errors.slice(0,2).map(esc).join('; ')}</div>` : ''}
        <div style="margin-top:6px;font-size:.78rem;color:var(--text2)">${esc(d.note||'')}</div>`;
    }

    // Preview de hallazgos
    if (tbodyEl) {
      tbodyEl.innerHTML = (d.findings || []).slice(0, 10).map(f => {
        const isCompliance = (f.category||'').startsWith('compliance');
        const typeIcon = isCompliance ? '' : '';
        return `<tr>
          <td style="font-size:.75rem;color:var(--text2)">${typeIcon} ${esc((f.category||'').split('/').pop())}</td>
          <td>${sevBadge(f.severity)}</td>
          <td style="font-size:.8rem"><b>${esc((f.title||'').substring(0,60))}</b></td>
          <td style="font-size:.75rem;color:var(--text2);font-family:monospace">${esc(f.source_host||'—')}</td>
        </tr>`;
      }).join('') || '<tr><td colspan="4" style="color:var(--text2)">Sin hallazgos en el preview</td></tr>';
    }

    toast(`✓ ${d.imported} hallazgos importados (scan #${d.scan_id})`, 'ok');
    addActivityItem('import', '', `Import: ${file.name}`, `${d.imported} hallazgos`, d.imported > 0 ? 'ok' : 'info');

    // Limpiar el input
    if (fileInput) fileInput.value = '';
    if (btnEl)     btnEl.disabled = true;

  } catch(e) {
    if (errorEl) errorEl.textContent = `✗ Error: ${e.message}`;
  } finally {
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'Importar'; }
  }
}
