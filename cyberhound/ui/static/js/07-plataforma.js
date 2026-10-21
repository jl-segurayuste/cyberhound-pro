// Cuarentena, SBOM, PDF, compliance, monitor, imágenes Docker, Ansible y runtime.
// Se cargan en orden (ver index.html); comparten el ámbito global como si fueran un solo fichero.
'use strict';

// ══════════════════════════════════════════════════════════════════════════════
// CUARENTENA + SBOM
// ══════════════════════════════════════════════════════════════════════════════

// ── Cuarentena ────────────────────────────────────────────────────────────────
async function loadQuarantine() {
  if (!hostAccess()) return;   // de la plataforma: un tenant recibiría 403
  const [items, stats] = await Promise.all([
    fetch('/api/quarantine').then(r=>r.json()).catch(()=>[]),
    fetch('/api/quarantine/stats').then(r=>r.json()).catch(()=>({})),
  ]);

  const statsEl = document.getElementById('quarantine-stats');
  if (statsEl && stats.total !== undefined) {
    statsEl.textContent = `${stats.total} fichero(s) — ${stats.size_mb} MB`;
  }

  const table = document.getElementById('quarantine-table');
  const empty = document.getElementById('quarantine-empty');
  const tbody = document.getElementById('quarantine-tbody');
  if (!tbody) return;

  if (!items.length) {
    if (table) table.style.display = 'none';
    if (empty) empty.style.display = '';
    return;
  }

  if (table) table.style.display = '';
  if (empty) empty.style.display = 'none';

  tbody.innerHTML = items.map(item => `
    <tr>
      <td style="font-family:monospace;font-size:.75rem">${esc(item.original_path?.split('/').pop()||'')}</td>
      <td style="font-size:.78rem;color:var(--text2)">${esc((item.finding_title||'').substring(0,40))}</td>
      <td style="font-size:.75rem;color:var(--text2)">${new Date(item.quarantined_at).toLocaleString('es')}</td>
      <td style="font-size:.75rem;color:var(--text2)">${(item.size_bytes/1024).toFixed(1)} KB</td>
      <td><span style="font-size:.72rem;padding:2px 6px;border-radius:3px;background:var(--bg3)">${item.restored?'Restaurado':'Cuarentena'}</span></td>
      <td>
        <button class="btn-secondary small" ${on('click', 'restoreQuarantine', item.quarantine_name)}>Restaurar</button>
        <button class="btn-danger small" ${on('click', 'deleteQuarantine', item.quarantine_name)}>Eliminar</button>
      </td>
    </tr>`).join('');
}

async function quarantineFile(filepath, findingId, title) {
  if (!confirm(`¿Enviar a cuarentena?\n${filepath}\n\nEl fichero se cifrará y no podrá ejecutarse.`)) return;
  const r = await fetch('/api/quarantine', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ filepath, finding_id: findingId, title }),
  });
  const d = await r.json();
  toast(d.ok ? `✓ ${d.message}` : `✗ ${d.error||d.message}`);
  if (d.ok && document.getElementById('cfg-quarantine')?.classList.contains('active')) {
    await loadQuarantine();
  }
}

async function restoreQuarantine(name) {
  if (!confirm('¿Restaurar el fichero a su ubicación original?')) return;
  const r = await fetch(`/api/quarantine/${encodeURIComponent(name)}/restore`, {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: '{}',
  });
  const d = await r.json();
  toast(d.ok ? `✓ ${d.message}` : `✗ ${d.message}`);
  if (d.ok) await loadQuarantine();
}

async function deleteQuarantine(name) {
  if (!confirm('¿Eliminar PERMANENTEMENTE el fichero de cuarentena?\nEsta acción no se puede deshacer.')) return;
  const r = await fetch(`/api/quarantine/${encodeURIComponent(name)}`, { method: 'DELETE' });
  const d = await r.json();
  toast(d.ok ? '✓ Eliminado permanentemente' : `✗ ${d.message}`);
  if (d.ok) await loadQuarantine();
}

// Añadir botón de cuarentena en el drawer de findings de malware
function openDrawerWithQuarantine(f) {
  openDrawer(f);
  // Si el finding tiene file_path, añadir botón de cuarentena
  if (f.file_path && (f.category||'').includes('malware')) {
    const body = document.getElementById('drawer-body');
    if (body) {
      const btn = document.createElement('button');
      btn.className = 'btn-danger small';
      btn.style.marginTop = '12px';
      btn.textContent = 'Enviar a cuarentena';
      btn.onclick = () => quarantineFile(f.file_path, f.id || f.finding_id, f.title);
      body.appendChild(btn);
    }
  }
}

// ── SBOM ──────────────────────────────────────────────────────────────────────
let _sbomData = null;

async function generateSBOM() {
  const managers = [...document.querySelectorAll('.sbom-check:checked')].map(c => c.value);
  const format   = document.getElementById('sbom-format')?.value || 'json';

  const summaryEl = document.getElementById('sbom-summary');
  const result    = document.getElementById('sbom-result');
  if (summaryEl) summaryEl.textContent = 'Generando SBOM… (puede tardar 10-30s)';
  if (result)    result.style.display = '';

  try {
    const r = await fetch('/api/sbom/generate', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ include: managers, format }),
    });

    if (format === 'spdx') {
      const text = await r.text();
      const blob = new Blob([text], { type: 'text/plain' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href = url; a.download = 'sbom.spdx'; a.click();
      if (summaryEl) summaryEl.textContent = '✓ SBOM SPDX descargado';
      return;
    }

    const d = await r.json();
    _sbomData = d;

    if (summaryEl) {
      const summary = d.summary || {};
      const parts = Object.entries(summary).map(([k,v]) => `${k}: ${v}`).join(' · ');
      summaryEl.innerHTML = `<b>✓ ${d.total} componentes</b> — ${parts} — Generado: ${new Date(d.generated_at).toLocaleString('es')}`;
    }

    renderSBOMTable(d.components || []);
  } catch(e) {
    if (summaryEl) { summaryEl.textContent = '✗ Error: ' + e.message; }
  }
}

function renderSBOMTable(components) {
  const tbody = document.getElementById('sbom-tbody');
  if (!tbody) return;
  tbody.innerHTML = components.slice(0, 500).map(c => `
    <tr>
      <td style="font-size:.8rem;font-weight:500">${esc(c.name||'')}</td>
      <td style="font-size:.78rem;color:var(--text2);font-family:monospace">${esc(c.version||'')}</td>
      <td style="font-size:.75rem"><span style="background:var(--bg3);padding:2px 5px;border-radius:3px">${esc(c.type||'')}</span></td>
      <td style="font-size:.75rem;color:var(--text2)">${esc(c.manager||'')}</td>
    </tr>`).join('');
  if (components.length > 500) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td colspan="4" style="text-align:center;color:var(--text2);font-size:.78rem">… y ${components.length-500} más</td>`;
    tbody.appendChild(tr);
  }
}

async function downloadSBOM() {
  const format = document.getElementById('sbom-format')?.value || 'json';
  if (format === 'spdx') { await generateSBOM(); return; }

  if (!_sbomData && format === 'json') { await generateSBOM(); return; }

  const data     = format === 'cyclonedx'
    ? await fetch('/api/sbom/generate', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({format:'cyclonedx'}) }).then(r=>r.json())
    : _sbomData;

  if (!data) { toast('Genera el SBOM primero'); return; }

  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url;
  a.download = format === 'cyclonedx' ? 'sbom-cyclonedx.json' : 'sbom.json';
  a.click();
}

async function loadSBOM() {
  if (!hostAccess()) return;   // de la plataforma: un tenant recibiría 403
  const r = await fetch('/api/sbom/latest');
  if (!r.ok) { toast('Sin SBOM generado todavía — genera uno primero'); return; }
  const d = await r.json();
  _sbomData = d;
  const result = document.getElementById('sbom-result');
  if (result) result.style.display = '';
  const summaryEl = document.getElementById('sbom-summary');
  if (summaryEl) {
    const summary = d.summary || {};
    const parts = Object.entries(summary).map(([k,v]) => `${k}: ${v}`).join(' · ');
    summaryEl.innerHTML = `<b>${d.total} componentes</b> — ${parts}`;
  }
  renderSBOMTable(d.components || []);
}


// ══════════════════════════════════════════════════════════════════════════════
// PDF + COMPLIANCE
// ══════════════════════════════════════════════════════════════════════════════

// ── Descarga de informe PDF ───────────────────────────────────────────────────
async function downloadPDF(scanType) {
  // Obtener el último scan de ese tipo
  try {
    const histResp = await fetch(`/api/history?type=${scanType}&limit=1`);
    const history  = await histResp.json();
    const lastScan = history[0];

    if (!lastScan) {
      toast(`Sin escaneos de tipo '${scanType}' — ejecuta uno primero`);
      return;
    }

    toast('Generando PDF…');
    const r = await fetch('/api/report/pdf', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        scan_id:   lastScan.id,
        scan_type: scanType,
        target:    lastScan.target || 'localhost',
        score:     lastScan.score,
      }),
    });

    if (!r.ok) {
      const err = await r.json().catch(() => ({error: 'Error desconocido'}));
      toast('✗ Error generando PDF: ' + (err.error || r.status));
      return;
    }

    const blob     = await r.blob();
    const url      = URL.createObjectURL(blob);
    const a        = document.createElement('a');
    const filename = r.headers.get('content-disposition')?.match(/filename=([^;]+)/)?.[1]
                     || `cyberhound-${scanType}.pdf`;
    a.href = url;
    a.download = filename.replace(/"/g, '');
    a.click();
    URL.revokeObjectURL(url);
    toast(`✓ PDF descargado: ${a.download}`);
  } catch(e) {
    toast('✗ Error: ' + e.message);
  }
}

// ── Compliance ────────────────────────────────────────────────────────────────
async function loadCompliance() {
  const frameworks = [...document.querySelectorAll('.fw-check:checked')].map(c => c.value);
  if (!frameworks.length) { toast('Selecciona al menos un marco normativo'); return; }

  const result  = document.getElementById('compliance-result');
  const cards   = document.getElementById('compliance-cards');
  if (result) result.style.display = '';
  if (cards)  cards.innerHTML = '<div style="color:var(--text2);font-size:.82rem">Analizando cumplimiento…</div>';

  try {
    const r = await fetch('/api/compliance', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ frameworks }),
    });
    const d = await r.json();

    if (!cards) return;

    const fwNames = {
      ens:      'ENS',
      iso27001: 'ISO 27001',
      'pci-dss':'PCI-DSS',
      cis:      'CIS v8',
    };

    const statusColors = {
      CONFORME:               'var(--green)',
      PARCIALMENTE_CONFORME:  'var(--yellow)',
      NO_CONFORME:            'var(--red)',
    };

    cards.innerHTML = Object.entries(d).map(([fw, res]) => {
      const color = statusColors[res.status] || 'var(--text2)';
      const pct   = res.score_pct;
      return `
        <div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px;min-width:180px;flex:1">
          <div style="font-weight:700;margin-bottom:4px;font-size:.9rem">${fwNames[fw]||fw}</div>
          <div style="font-size:1.8rem;font-weight:700;color:${color};line-height:1">${pct}%</div>
          <div style="font-size:.72rem;color:${color};margin-bottom:8px">${res.status.replace(/_/g,' ')}</div>
          <div style="display:flex;gap:4px;font-size:.72rem;color:var(--text2)">
            <span style="color:var(--green)">✓ ${res.covered}</span>
            <span>·</span>
            <span style="color:var(--red)">✗ ${res.failed}</span>
            <span>·</span>
            <span>${res.total_controls} controles</span>
          </div>
          ${res.failed_controls?.length > 0 ? `
            <div style="margin-top:8px;font-size:.72rem">
              <div style="color:var(--text2);margin-bottom:4px">Controles fallidos:</div>
              ${res.failed_controls.slice(0,3).map(c =>
                `<div style="padding:2px 0;border-bottom:1px solid var(--border)">
                  <span style="color:var(--red);font-weight:600">${esc(c.id)}</span>
                  <span style="color:var(--text2)"> — ${esc(c.title)}</span>
                </div>`).join('')}
              ${res.failed > 3 ? `<div style="color:var(--text2);margin-top:2px">… y ${res.failed-3} más</div>` : ''}
            </div>` : ''}
        </div>`;
    }).join('');

  } catch(e) {
    if (cards) cards.innerHTML = `<div style="color:var(--red);font-size:.82rem">Error: ${esc(e.message)}</div>`;
  }
}

// ── Auto-cargar compliance en el dashboard ────────────────────────────────────
async function loadComplianceSummary() {
  try {
    const r = await fetch('/api/compliance?frameworks=ens,iso27001,cis');
    if (!r.ok) return;
    const d = await r.json();
    // Mostrar en la sección de informes si está visible
    const cards = document.getElementById('compliance-cards');
    // Solo actualizar si el panel de reports está activo
    if (cards && document.getElementById('panel-reports')?.classList.contains('active')) {
      // Ya cargado por loadCompliance()
    }
  } catch(e) {}
}

// ══════════════════════════════════════════════════════════════════════════════
// MONITOR EN TIEMPO REAL + DOCKER IMAGE SCAN
// ══════════════════════════════════════════════════════════════════════════════

// ── Monitor status ────────────────────────────────────────────────────────────
async function loadMonitorStatus() {
  if (!hostAccess()) return;   // de la plataforma: un tenant recibiría 403
  try {
    const r = await fetch('/api/monitor/status');
    if (!r.ok) return;
    const d = await r.json();

    const dot    = document.getElementById('monitor-status-dot');
    const text   = document.getElementById('monitor-status-text');
    const detail = document.getElementById('monitor-status-detail');

    if (d.active) {
      if (dot)    dot.style.background    = 'var(--green)';
      if (text)   text.textContent        = `✓ Monitor activo (modo: ${d.mode})`;
      if (detail) detail.textContent      = d.message;
    } else {
      if (dot)    dot.style.background    = 'var(--yellow)';
      if (text)   text.textContent        = '⚠ Monitor inactivo';
      if (detail) detail.textContent      = 'Instala auditd o bpftrace para activar: sudo apt install auditd';
    }
  } catch(e) {}
}

// ── Historial de eventos del monitor ─────────────────────────────────────────
async function loadMonitorHistory() {
  if (!hostAccess()) return;   // de la plataforma: un tenant recibiría 403
  try {
    const r = await fetch('/api/history?type=monitor&limit=50');
    if (!r.ok) return;
    const history = await r.json();
    const feed    = document.getElementById('monitor-events');
    if (!feed) return;

    if (!history.length) {
      feed.innerHTML = '<div style="color:var(--text2);padding:8px">Sin eventos registrados todavía.</div>';
      return;
    }

    // Cargar findings del último scan de monitor
    const events = [];
    for (const scan of history.slice(0, 5)) {
      const fr = await fetch(`/api/history/${scan.id}`);
      const findings = fr.ok ? await fr.json() : [];
      events.push(...findings.map(f => ({ ...f, scan_time: scan.started_at })));
    }

    const sevColors = {
      critical: 'var(--critical)', high: 'var(--high)',
      medium: 'var(--medium)', low: 'var(--text2)',
    };

    feed.innerHTML = events.slice(0, 50).map(f => {
      const dt    = new Date(f.scan_time || '').toLocaleTimeString('es');
      const color = sevColors[f.severity] || 'var(--text2)';
      const icon  = f.severity === 'critical' ? '' : f.severity === 'high' ? '' : '';
      return `<div style="padding:4px 0;border-bottom:1px solid var(--bg3)">
        <span style="color:var(--text2)">[${dt}]</span>
        <span style="color:${color};margin:0 4px">${icon}</span>
        <span style="color:var(--text)">${esc(f.title || f.finding_id || '')}</span>
      </div>`;
    }).join('') || '<div style="color:var(--text2);padding:8px">Sin eventos.</div>';
  } catch(e) {}
}

// ── Docker image deep scan ─────────────────────────────────────────────────────
async function runDockerImageScan() {
  const imagesInput = document.getElementById('img-scan-images')?.value.trim();
  const deep        = document.getElementById('img-scan-deep')?.checked ?? true;
  const images      = imagesInput ? imagesInput.split(',').map(s=>s.trim()).filter(Boolean) : null;

  const btnEl   = document.getElementById('btn-img-scan');
  const results = document.getElementById('img-scan-results');
  const empty   = document.getElementById('img-scan-empty');
  const tbody   = document.getElementById('img-scan-tbody');

  if (btnEl) { btnEl.disabled = true; btnEl.textContent = 'Analizando imágenes…'; }
  if (results) results.style.display = 'none';
  if (empty)   empty.textContent = '';

  try {
    const r = await fetch('/api/scan/docker-image', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ images, deep, max_images: 5, max_size_mb: 200 }),
    });
    const d = await r.json();

    if (d.error) {
      if (empty) empty.textContent = '✗ Error: ' + d.error;
      return;
    }

    if (!d.findings?.length) {
      if (empty) empty.textContent = 'Sin hallazgos en las imágenes analizadas.';
      return;
    }

    if (results) results.style.display = '';
    _renderSummary('img-scan-summary-bar', d.findings);

    if (tbody) {
      tbody.innerHTML = d.findings.map(f => `
        <tr ${on('click', 'openDrawer', f)}>
          <td>${sevBadge(f.severity)}</td>
          <td style="font-size:.78rem;color:var(--text2)">${esc((f.category||'').replace('docker/image/',''))}</td>
          <td><b>${esc(f.title)}</b><div style="font-size:.75rem;color:var(--text2)">${esc((f.description||'').substring(0,80))}</div></td>
          <td style="font-size:.75rem;color:var(--text2)">${esc((f.remediation||'').split('\\n')[0].substring(0,70))}</td>
        </tr>`).join('');
    }

    appendLog('ok', `✓ Docker image scan: ${d.findings.length} hallazgos`);
    addActivityItem('docker', '', `Image scan: ${d.findings.length} hallazgos`,
      `${images?.join(', ') || 'imágenes locales'}`, d.findings[0]?.severity || 'info');

  } catch(e) {
    if (empty) empty.textContent = '✗ Error: ' + e.message;
  } finally {
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'Analizar imágenes'; }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// ANSIBLE AWX/TOWER + RUNTIME SCAN + MULTI-TENANT
// ══════════════════════════════════════════════════════════════════════════════

// ── Ansible ────────────────────────────────────────────────────────────────────
document.querySelectorAll('[name="ansible-mode"]')?.forEach(radio => {
  radio.addEventListener('change', () => {
    const awxFields = document.getElementById('awx-fields');
    if (awxFields) awxFields.style.display = radio.value === 'awx' ? '' : 'none';
  });
});

async function runAnsiblePlaybook() {
  const mode     = document.querySelector('[name="ansible-mode"]:checked')?.value || 'local';
  const scanId   = document.getElementById('ansible-scan-id')?.value || '';
  const target   = document.getElementById('ansible-target')?.value || 'localhost';
  const result   = document.getElementById('ansible-result');
  const statusEl = document.getElementById('ansible-status');
  const outputEl = document.getElementById('ansible-output');
  const pbEl     = document.getElementById('ansible-playbook');

  if (result)   result.style.display = '';
  if (statusEl) statusEl.textContent = 'Lanzando playbook…';
  if (outputEl) outputEl.textContent = '';

  const body = { mode, target };
  if (scanId) body.scan_id = parseInt(scanId);
  if (mode === 'awx') {
    body.awx_url     = document.getElementById('awx-url')?.value;
    body.awx_token   = document.getElementById('awx-token')?.value;
    body.template_id = parseInt(document.getElementById('awx-template-id')?.value || '1');
  }

  try {
    const r = await fetch('/api/ansible/run', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify(body),
    });
    const d = await r.json();

    if (d.error) {
      if (statusEl) { statusEl.textContent = `✗ Error: ${d.error}`; statusEl.style.color='var(--red)'; }
      return;
    }

    const statusColor = d.status === 'successful' ? 'var(--green)' : d.status === 'failed' ? 'var(--red)' : 'var(--yellow)';
    if (statusEl) {
      statusEl.innerHTML = `<span style="color:${statusColor};font-weight:600">Job #${d.job_id}: ${d.status}</span>`;
    }
    if (outputEl) outputEl.textContent = d.output || '(sin output)';
    if (pbEl)     pbEl.textContent     = d.playbook || '';

    // Actualizar lista de jobs
    await loadAnsibleJobs();
    toast(d.status === 'successful' ? '✓ Playbook completado' : '⚠ Playbook con errores');
    addActivityItem('ansible', d.status === 'successful' ? '' : '',
      `Playbook Ansible: ${d.status}`, `target=${target}`, d.status === 'successful' ? 'ok' : 'high');
  } catch(e) {
    if (statusEl) { statusEl.textContent = `✗ Error: ${e.message}`; statusEl.style.color='var(--red)'; }
  }
}

async function loadAnsibleJobs() {
  if (!hostAccess()) return;   // de la plataforma: un tenant recibiría 403
  try {
    const r = await fetch('/api/ansible/jobs');
    const jobs = await r.json();
    const el = document.getElementById('ansible-jobs-list');
    if (!el) return;
    if (!jobs.length) { el.textContent = 'Sin jobs ejecutados.'; return; }
    el.innerHTML = jobs.slice(0,5).map(j => {
      const color = j.status==='successful'?'var(--green)':j.status==='failed'?'var(--red)':'var(--yellow)';
      return `<div style="padding:4px 0;border-bottom:1px solid var(--border);font-size:.78rem;display:flex;gap:8px">
        <span style="color:${color};font-weight:600">#${j.job_id}</span>
        <span style="color:${color}">${j.status}</span>
        <span style="color:var(--text2)">${j.mode} ${j.target}</span>
        <span style="color:var(--text2);margin-left:auto">${new Date(j.started_at).toLocaleTimeString('es')}</span>
      </div>`;
    }).join('');
  } catch(e) {}
}

// ── Runtime container scan ────────────────────────────────────────────────────
async function runRuntimeScan() {
  const cInput  = document.getElementById('rt-containers')?.value.trim();
  const containers = cInput ? cInput.split(',').map(s=>s.trim()).filter(Boolean) : null;
  const btnEl   = document.getElementById('btn-rt-scan');
  const results = document.getElementById('rt-results');
  const empty   = document.getElementById('rt-empty');
  const tbody   = document.getElementById('rt-tbody');

  if (btnEl) { btnEl.disabled=true; btnEl.textContent='Analizando…'; }
  if (results) results.style.display = 'none';
  if (empty)   empty.textContent = '';

  try {
    const r = await fetch('/api/scan/runtime', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ containers }),
    });
    const d = await r.json();

    if (d.error) { if (empty) empty.textContent = '✗ ' + d.error; return; }
    if (!d.findings?.length) {
      if (empty) empty.textContent = 'Sin comportamiento anómalo detectado en los contenedores activos.';
      return;
    }

    if (results) results.style.display = '';
    _renderSummary('rt-summary-bar', d.findings);
    if (tbody) {
      tbody.innerHTML = d.findings.map(f => `
        <tr ${on('click', 'openDrawer', f)}>
          <td>${sevBadge(f.severity)}</td>
          <td style="font-size:.78rem;color:var(--text2)">${esc((f.category||'').replace('runtime/',''))}</td>
          <td><b>${esc(f.title)}</b></td>
          <td style="font-size:.75rem;color:var(--text2)">${esc((f.evidence||'').substring(0,60))}</td>
        </tr>`).join('');
    }
    addActivityItem('runtime', '', `Runtime scan: ${d.findings.length} hallazgos`, '', d.findings[0]?.severity||'info');
    toast(`✓ Runtime scan: ${d.findings.length} hallazgos`);
  } catch(e) {
    if (empty) empty.textContent = '✗ Error: ' + e.message;
  } finally {
    if (btnEl) { btnEl.disabled=false; btnEl.textContent='Analizar runtime'; }
  }
}
