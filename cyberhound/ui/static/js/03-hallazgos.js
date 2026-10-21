// Historial, corrección de hallazgos (local y remota), drawer, explicación y filtros.
// Se cargan en orden (ver index.html); comparten el ámbito global como si fueran un solo fichero.
'use strict';

// ── Historial ─────────────────────────────────────────────────────────────
async function loadHistory() {
  const type = document.getElementById('hist-type')?.value || '';
  const url = '/api/history' + (type ? '?type=' + type : '');
  try {
    const data = await fetch(url).then(r => r.json());
    const tbody = document.getElementById('history-tbody');
    const table = document.getElementById('history-table');
    const empty = document.getElementById('history-empty');
    if (!data.length) {
      table.style.display = 'none'; empty.style.display = ''; return;
    }
    table.style.display = 'table'; empty.style.display = 'none';
    const typeLabels = {audit:'Seguridad', malware:'Malware', network:'Red', code:'Código', ssh:'SSH'};
    tbody.innerHTML = data.map(s => `
      <tr ${on('click', 'loadHistoryDetail', s.id, '$this')} style="cursor:pointer">
        <td style="white-space:nowrap">${fmt(s.started_at)}</td>
        <td>${typeLabels[s.scan_type]||s.scan_type}</td>
        <td style="font-size:.82rem;color:var(--text2)">${esc(s.target||'localhost')}</td>
        <td>${_scorePill(s.score)}</td>
        <td>${_findingBar(s)}</td>
        <td style="color:var(--text2);font-size:.82rem">${dur(s.duration_s)}</td>
        <td><span style="font-size:.75rem;color:var(--text2)">${s.triggered_by==='scheduler'?'Auto':'Manual'}</span></td>
        <td>
          ${s.status==='completed'?`<button class="fix-btn" ${on('click', 'loadHistoryDetail', s.id)} data-stop>Ver</button>`:''}
          <span style="font-size:.75rem;color:${s.status==='completed'?'var(--green)':s.status==='failed'?'var(--red)':'var(--yellow)'}">${s.status}</span>
        </td>
      </tr>`).join('');
  } catch (e) { toast('Error cargando historial: ' + e, 'error'); }
}

function _findingBar(s) {
  const total = (s.critical||0)+(s.high||0)+(s.medium||0)+(s.low||0);
  if (!total) return '<span style="color:var(--green);font-size:.78rem">✓ Sin problemas</span>';
  const w = v => total ? Math.round(v/total*100) : 0;
  return `<div class="finding-bar">
    ${s.critical?`<span style="width:${w(s.critical)}%;background:var(--critical)" title="Crítico: ${s.critical}"></span>`:''}
    ${s.high?`<span style="width:${w(s.high)}%;background:var(--high)" title="Alto: ${s.high}"></span>`:''}
    ${s.medium?`<span style="width:${w(s.medium)}%;background:var(--medium)" title="Medio: ${s.medium}"></span>`:''}
    ${s.low?`<span style="width:${w(s.low)}%;background:var(--low)" title="Bajo: ${s.low}"></span>`:''}
  </div><span style="font-size:.75rem;color:var(--text2);margin-left:6px">${total}</span>`;
}

async function loadHistoryDetail(scanId) {
  const [findings, comparison] = await Promise.all([
    fetch(`/api/history/${scanId}`).then(r => r.json()),
    fetch(`/api/history/${scanId}/compare`).then(r => r.json()).catch(() => ({})),
  ]);
  document.getElementById('history-detail').style.display = '';
  document.getElementById('history-detail-title').textContent = `Scan #${scanId} — ${findings.length} hallazgos`;
  // Comparación
  const compEl = document.getElementById('history-comparison');
  if (comparison.first_scan) {
    compEl.innerHTML = '<span style="color:var(--text2)">Primer análisis</span>';
  } else if (comparison.new !== undefined) {
    compEl.innerHTML = `
      <span class="comp-new">${comparison.new.length} nuevos</span>
      <span class="comp-resolved">${comparison.resolved.length} resueltos</span>
      <span class="comp-same">= ${comparison.unchanged} sin cambio</span>`;
  }
  // Tabla de findings
  const tbody = document.getElementById('hist-detail-tbody');
  tbody.innerHTML = findings.map(f => `
    <tr data-sev="${esc(f.severity)}" ${on('click', 'openDrawerFromData', f)}>
      <td>${_sevBadge(f.severity)}</td>
      <td style="font-size:.78rem;color:var(--text2)">${esc(f.category)}</td>
      <td>${esc(f.title)}</td>
      <td>${f.fixed_at ? `<span class="fixed-badge">✓ Corregido</span>` : ''}</td>
    </tr>`).join('');
  document.getElementById('history-detail').scrollIntoView({behavior:'smooth'});
}

function closeHistoryDetail() {
  const el = document.getElementById('history-detail');
  if (el) el.style.display = 'none';
}

// ── Fix local / remoto ────────────────────────────────────────────────────
async function applyFix(findingId, btnEl) {
  if (btnEl) { btnEl.disabled = true; btnEl.textContent = '…'; }
  try {
    const r = await fetch('/api/fix/local', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({finding_id: findingId}),
    });
    const d = await r.json();
    if (d.ok) {
      appendLog('ok', `✓ Corregido: ${findingId}`);
      toast('✓ Corrección aplicada');
      if (btnEl) {
        if (d.reversible) {
          // El fix se registró en el journal: ofrecer deshacer.
          btnEl.disabled = false;
          btnEl.textContent = '↶ Deshacer';
          btnEl.style.background = 'var(--amber, #b45309)';
          btnEl.onclick = (ev) => { ev.stopPropagation(); rollbackFix(findingId, btnEl); };
        } else {
          btnEl.textContent = '✓ Listo';
          btnEl.style.background = 'var(--green)';
        }
      }
    } else {
      toast('Error: ' + d.error, 'error');
      if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'Corregir'; }
    }
  } catch(e) {
    toast('Error: ' + e, 'error');
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'Corregir'; }
  }
}

// Revierte el último fix aplicado a un finding (usa el journal de rollback).
async function rollbackFix(findingId, btnEl) {
  if (btnEl) { btnEl.disabled = true; btnEl.textContent = '…'; }
  try {
    const r = await fetch('/api/rollback/local', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({finding_id: findingId}),
    });
    const d = await r.json();
    if (d.ok) {
      appendLog('ok', `↶ Revertido: ${findingId}`);
      toast('↶ Corrección revertida');
      if (btnEl) {
        btnEl.disabled = false;
        btnEl.textContent = 'Corregir';
        btnEl.style.background = '';
        btnEl.onclick = (ev) => { ev.stopPropagation(); applyFix(findingId, btnEl); };
      }
    } else {
      toast('Error al revertir: ' + (d.message || d.error || ''), 'error');
      if (btnEl) { btnEl.disabled = false; btnEl.textContent = '↶ Deshacer'; }
    }
  } catch(e) {
    toast('Error: ' + e, 'error');
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = '↶ Deshacer'; }
  }
}

async function fixAll(scope) {
  const fixable = (S.findings[scope]||[]).filter(f => f.auto_fix);
  if (!fixable.length) { toast('Sin correcciones automáticas'); return; }
  appendLog('section', `Aplicando ${fixable.length} correcciones…`);
  for (const f of fixable) {
    await applyFix(f.id, document.getElementById('fix-'+f.id));
    await new Promise(r => setTimeout(r, 150));
  }
  toast(`✓ ${fixable.length} correcciones aplicadas`);
}

async function applyFixRemote(findingId, host, btnEl) {
  if (btnEl) { btnEl.disabled = true; btnEl.textContent = '…'; }
  try {
    const r = await fetch('/api/fix/remote', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        finding_id: findingId, host,
        ssh_user: document.getElementById('net-user')?.value || 'root',
        ssh_key:  document.getElementById('net-key')?.value || '',
        ssh_password: document.getElementById('net-pass')?.value || '',
      }),
    });
    const d = await r.json();
    if (d.ok) {
      toast(`✓ Fix aplicado en ${host}`);
      if (btnEl && d.reversible) {
        btnEl.disabled = false;
        btnEl.textContent = '↶ Deshacer';
        btnEl.style.background = 'var(--amber, #b45309)';
        btnEl.onclick = (ev) => { ev.stopPropagation(); undoFixRemote(d.fix_id, host, btnEl); };
      } else if (btnEl) { btnEl.textContent = '✓'; btnEl.style.background = 'var(--green)'; }
    } else {
      toast('Error: ' + d.error, 'error');
      if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'Fix'; }
    }
  } catch(e) {
    toast('Error: ' + e, 'error');
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'Fix'; }
  }
}

// Deshace un fix remoto: el servidor guardó el estado previo del host al aplicarlo
async function undoFixRemote(fixId, host, btnEl) {
  if (btnEl) { btnEl.disabled = true; btnEl.textContent = '…'; }
  try {
    const r = await fetch('/api/fix/remote/undo', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        fix_id: fixId,
        ssh_user: document.getElementById('net-user')?.value || 'root',
        ssh_key:  document.getElementById('net-key')?.value || '',
        ssh_password: document.getElementById('net-pass')?.value || '',
      }),
    });
    const d = await r.json();
    if (d.ok) {
      toast(`↶ Fix deshecho en ${host}`);
      if (btnEl) { btnEl.textContent = '↶ Deshecho'; btnEl.style.background = ''; }
      if (document.getElementById('remote-fixes-tbody')) loadRemoteFixes();
    } else {
      toast('Error al deshacer: ' + (d.error || ''), 'error');
      if (btnEl) { btnEl.disabled = false; btnEl.textContent = '↶ Deshacer'; }
    }
  } catch(e) {
    toast('Error: ' + e, 'error');
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = '↶ Deshacer'; }
  }
}

// ── Drawer ────────────────────────────────────────────────────────────────
function openDrawer(f, host) {
  _renderDrawer(f, host || f.source_host);
}

function openDrawerFromData(f) {
  // f puede ser un dict con finding_id en lugar de id (de BD)
  if (f.finding_id && !f.id) f.id = f.finding_id;
  _renderDrawer(f, f.source_host);
}

function _renderDrawer(f, host) {
  const hostLabel = host || (f.id?.includes('::') ? f.id.split('::')[0] : null);
  document.getElementById('drawer-sev-badge').outerHTML =
    `<span id="drawer-sev-badge">${_sevBadge(f.severity)}</span>`;
  document.getElementById('drawer-title').textContent = f.title;
  document.getElementById('drawer-body').innerHTML = `
    ${hostLabel ? `<div class="d-field"><div class="d-label">Equipo</div><div class="d-value" style="color:var(--blue);font-family:monospace">${esc(hostLabel)}</div></div>` : ''}
    <div class="d-field"><div class="d-label">ID</div><div class="d-value" style="color:var(--text2);font-size:.75rem">${esc(f.id||f.finding_id||'')}</div></div>
    <div class="d-field"><div class="d-label">Categoría</div><div class="d-value">${esc(f.category)}</div></div>
    ${f.description ? `<div class="d-field"><div class="d-label">¿Qué ocurre?</div><div class="d-value">${esc(f.description)}</div></div>` : ''}
    ${f.evidence ? `<div class="d-field"><div class="d-label">Evidencia</div><div class="d-code">${esc(f.evidence)}</div></div>` : ''}
    ${f.file_path ? `<div class="d-field"><div class="d-label">Fichero</div><div class="d-value" style="font-family:monospace;font-size:.82rem">${esc(f.file_path)}${f.line_number?':'+f.line_number:''}</div></div>` : ''}
    <div class="d-field"><div class="d-label">Cómo solucionarlo</div><div class="d-code">${esc(f.remediation)}</div></div>
    ${f.fixed_at ? `<div style="background:rgba(63,185,80,.12);border-radius:6px;padding:8px;font-size:.82rem;color:var(--green)">✓ Corregido el ${fmt(f.fixed_at)} por ${esc(f.fixed_by||'')}</div>` : ''}
    ${f.auto_fix && !hostLabel && !f.fixed_at ? `<button class="d-fix-btn" ${on('click', 'applyFix', f.id || f.finding_id || '', '$this')}>Aplicar corrección</button>` : ''}
    ${f.auto_fix && hostLabel && !f.fixed_at ? `<button class="d-fix-btn remote" ${on('click', 'applyFixRemote', f.id || '', hostLabel, '$this')}>Corregir en ${esc(hostLabel)}</button>` : ''}
    ${!f.auto_fix ? `<div style="margin-top:10px;padding:10px;background:var(--bg3);border-radius:6px;font-size:.82rem;color:var(--text2)">ℹ️ Esta corrección requiere revisión manual.</div>` : ''}
    <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn-secondary small" ${on('click', 'explainFinding', f.id || f.finding_id || '')}>Explicar con IA</button>
      <button class="btn-secondary small" ${on('click', 'suppressFinding', f.id || f.finding_id || '')}>Suprimir (falso positivo)</button>
    </div>
    <div id="ai-explanation" style="margin-top:10px"></div>`;
  document.getElementById('drawer').classList.add('open');
  document.getElementById('drawer-backdrop').classList.add('show');
}

function closeDrawer() {
  document.getElementById('drawer').classList.remove('open');
  document.getElementById('drawer-backdrop').classList.remove('show');
}

// ── Supresión rápida desde el drawer ─────────────────────────────────────
async function suppressFinding(findingId) {
  const reason = prompt(`Motivo para suprimir "${findingId}":`);
  if (!reason) return;
  const r = await fetch('/api/suppressions', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({pattern: findingId, reason}),
  });
  const d = await r.json();
  if (d.ok) { toast('✓ Finding suprimido'); closeDrawer(); }
  else toast('Error: ' + d.error, 'error');
}

// ── Explicación en lenguaje llano con IA (LLM local) ──────────────────────
async function explainFinding(findingId) {
  const box = document.getElementById('ai-explanation');
  if (box) box.innerHTML = '<div style="padding:10px;color:var(--text2);font-size:.85rem">Generando explicación…</div>';
  try {
    const r = await fetch('/api/findings/explain', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({finding_id: findingId}),
    });
    const d = await r.json();
    if (!box) return;
    if (d.explanation) {
      box.innerHTML = `<div style="padding:12px;background:rgba(88,166,255,.08);border-radius:8px;font-size:.9rem;line-height:1.5"><strong>En lenguaje llano</strong><br>${esc(d.explanation)}</div>`;
    } else {
      box.innerHTML = `<div style="padding:10px;color:var(--text2);font-size:.85rem">${esc(d.detail || d.error || 'No disponible')}</div>`;
    }
  } catch (e) {
    if (box) box.innerHTML = `<div style="padding:10px;color:var(--red);font-size:.85rem">Error: ${esc(String(e))}</div>`;
  }
}

// ── Filtros y búsqueda ────────────────────────────────────────────────────
function filterTable(scope, sev, btnEl) {
  const ids = {audit:'audit-tbody', malware:'malware-tbody', code:'code-tbody',
               network:'network-findings-tbody', 'hist-detail':'hist-detail-tbody'};
  const tbody = document.getElementById(ids[scope] || scope+'-tbody');
  tbody?.querySelectorAll('tr').forEach(tr => {
    tr.style.display = (sev === 'all' || tr.dataset.sev === sev) ? '' : 'none';
  });
  if (btnEl) {
    btnEl.closest('.toolbar')?.querySelectorAll('.filter').forEach(b => b.classList.remove('active'));
    btnEl.classList.add('active');
  }
}

function searchTable(tbodyId, q) {
  const lower = q.toLowerCase();
  document.getElementById(tbodyId)?.querySelectorAll('tr').forEach(tr => {
    tr.style.display = tr.textContent.toLowerCase().includes(lower) ? '' : 'none';
  });
}
