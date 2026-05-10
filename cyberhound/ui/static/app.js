/* CyberHound Pro — app.js */
'use strict';

// ── Estado global ─────────────────────────────────────────────────────────────
const S = {
  findings: { audit: [], malware: [], code: [], network: [], ssh: [] },
  devices:  [],
  ws:       null,
  running:  false,
  logLines: [],
  currentTask: null,
};

// ── WebSocket ─────────────────────────────────────────────────────────────────
function wsRun(task, params, handlers = {}) {
  if (S.ws) S.ws.close();
  S.running = true;
  S.currentTask = task;
  setStatus('running', 'Analizando…');

  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  S.ws = new WebSocket(`${proto}://${location.host}/ws`);

  S.ws.onopen = () => S.ws.send(JSON.stringify({ task, ...params }));

  S.ws.onmessage = ev => {
    const msg = JSON.parse(ev.data);
    switch (msg.type) {
      case 'log':
        appendLog(msg.level, msg.text);
        break;
      case 'finding':
        if (handlers.onFinding) handlers.onFinding(msg.data);
        break;
      case 'devices':
        if (handlers.onDevices) handlers.onDevices(msg.data);
        break;
      case 'host_result':
        if (handlers.onHostResult) handlers.onHostResult(msg.data);
        break;
      case 'done':
        S.running = false;
        setStatus('done', `Completado — ${msg.count} hallazgos`);
        appendLog('ok', `✓ Análisis completado. ${msg.count} hallazgos.`);
        if (handlers.onDone) handlers.onDone(msg);
        break;
      case 'error':
        S.running = false;
        setStatus('error', msg.text);
        appendLog('error', '✗ Error: ' + msg.text);
        toast('Error: ' + msg.text);
        if (handlers.onError) handlers.onError(msg);
        break;
    }
  };
  S.ws.onerror = () => { S.running = false; setStatus('error', 'Error de conexión'); };
  S.ws.onclose = () => { S.running = false; };
}

// ── Navegación ────────────────────────────────────────────────────────────────
function showPanel(name) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
  document.getElementById('panel-' + name)?.classList.add('active');
  document.querySelector(`[data-panel="${name}"]`)?.classList.add('active');
  closeDrawer();
}

// ── Status ────────────────────────────────────────────────────────────────────
function setStatus(state, label) {
  const dot = document.getElementById('status-dot');
  dot.className = 'dot ' + state;
  document.getElementById('status-label').textContent = label;
}

// ── Log ───────────────────────────────────────────────────────────────────────
function appendLog(level, text) {
  const body = document.getElementById('log-body');
  const ts = new Date().toLocaleTimeString('es', { hour12: false });
  const div = document.createElement('div');
  div.className = 'log-' + (level || 'info');
  div.innerHTML = `<span class="log-ts">${ts}</span>${esc(text)}`;
  body.appendChild(div);
  body.scrollTop = body.scrollHeight;
  S.logLines.push(`[${ts}] [${level}] ${text}`);
}

function toggleLog() {
  document.getElementById('log-overlay').classList.toggle('show');
}

// ── Utilidades ────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s || '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function sevBadge(sev) {
  return `<span class="sev sev-${esc(sev)}">${esc((sev||'').toUpperCase())}</span>`;
}

function sevLabel(sev) {
  return { critical:'Crítico', high:'Alto', medium:'Medio', low:'Bajo', info:'Info' }[sev] || sev;
}

function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2800);
}

function btn(id, disabled, label) {
  const b = document.getElementById(id);
  if (!b) return;
  b.disabled = disabled;
  if (label) b.textContent = label;
}

// ── Summary bar ───────────────────────────────────────────────────────────────
function renderSummary(containerId, findings) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const counts = {};
  findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
  const order = ['critical','high','medium','low','info'];
  const labels = { critical:'Críticos', high:'Altos', medium:'Medios', low:'Bajos', info:'Info' };
  let html = '<div class="summary-bar">';
  order.forEach(s => {
    if (counts[s]) {
      html += `<span class="sum-chip ${s}">${counts[s]} ${labels[s]}</span>`;
    }
  });
  if (!findings.length) html += '<span class="sum-chip ok">✓ Sin problemas detectados</span>';
  html += '</div>';
  el.innerHTML = html;
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
function updateDashboard() {
  const all = [
    ...S.findings.audit,
    ...S.findings.malware,
    ...S.findings.network,
  ];
  if (!all.length) return;

  // Contadores
  const counts = {};
  all.forEach(f => { counts[f.severity] = (counts[f.severity]||0)+1; });
  ['critical','high','medium','low'].forEach(s => {
    const el = document.getElementById(`cnt-${s}`);
    if (el) el.textContent = counts[s] || 0;
  });

  // Puntuación (0-100, penaliza críticos más)
  const pen = { critical: 20, high: 10, medium: 4, low: 1 };
  let score = 100;
  all.forEach(f => { score -= (pen[f.severity] || 0); });
  score = Math.max(0, score);
  const scoreEl = document.getElementById('score-num');
  const scoreCircle = document.getElementById('score-circle');
  const scoreLabel = document.getElementById('score-label');
  if (scoreEl) scoreEl.textContent = score;
  const color = score >= 80 ? '#3fb950' : score >= 50 ? '#d29922' : '#f85149';
  if (scoreCircle) scoreCircle.style.borderColor = color;
  if (scoreLabel) {
    scoreLabel.style.color = color;
    scoreLabel.textContent = score >= 80 ? 'Bueno' : score >= 50 ? 'Mejorable' : 'Crítico';
  }

  // Dispositivos
  const devEl = document.getElementById('dash-devices-count');
  if (devEl && S.devices.length) devEl.textContent = S.devices.length;

  // Lista críticos
  const critList = document.getElementById('dash-critical-list');
  if (critList) {
    const criticals = all.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0, 6);
    if (criticals.length) {
      critList.innerHTML = criticals.map(f => `
        <div class="critical-item" onclick="openDrawer(${JSON.stringify(f).replace(/"/g,'&quot;')})">
          <span>${sevBadge(f.severity)}</span>
          <div>
            <div class="item-title">${esc(f.title)}</div>
            <div class="item-fix">${esc(f.remediation.split('\n')[0].substring(0,80))}</div>
          </div>
          ${f.auto_fix ? '<span class="fix-btn" style="pointer-events:none">⚡ Fix</span>' : ''}
        </div>`).join('');
    }
  }
}

// ── Audit ─────────────────────────────────────────────────────────────────────
function quickAudit() { showPanel('audit'); runAudit(); }

function runAudit() {
  S.findings.audit = [];
  document.getElementById('audit-results').style.display = 'none';
  document.getElementById('audit-empty').style.display = '';
  document.getElementById('audit-tbody').innerHTML = '';
  btn('btn-audit', true, '⏳ Analizando…');
  appendLog('section', '═══ ANÁLISIS DE SEGURIDAD ═══');

  wsRun('audit', {}, {
    onFinding(f) {
      S.findings.audit.push(f);
      appendAuditRow(f);
    },
    onDone() {
      btn('btn-audit', false, '▶ Iniciar análisis completo');
      document.getElementById('audit-results').style.display = '';
      document.getElementById('audit-empty').style.display = 'none';
      renderSummary('audit-summary-bar', S.findings.audit);
      // Mostrar botón "corregir todo" si hay fixes disponibles
      const fixable = S.findings.audit.filter(f => f.auto_fix);
      if (fixable.length) {
        btn('btn-fix-all', false, `⚡ Corregir ${fixable.length} problemas automáticamente`);
        document.getElementById('btn-fix-all').style.display = '';
      }
      updateDashboard();
      // Auto-fix si está marcado
      if (document.getElementById('audit-fix-all')?.checked) {
        fixAll('audit');
      }
    },
  });
}

function appendAuditRow(f) {
  const tbody = document.getElementById('audit-tbody');
  const tr = document.createElement('tr');
  tr.dataset.sev = f.severity;
  tr.onclick = () => openDrawer(f);
  tr.innerHTML = `
    <td>${sevBadge(f.severity)}</td>
    <td><b>${esc(f.title)}</b></td>
    <td style="color:var(--text2);font-size:.82rem">${esc((f.description||'').substring(0,100))}</td>
    <td>${f.auto_fix
      ? `<button class="fix-btn" id="fix-${esc(f.id)}" onclick="event.stopPropagation();applyFix('${esc(f.id)}',this)">⚡ Corregir</button>`
      : `<span style="font-size:.75rem;color:var(--text2)">${esc(f.remediation.substring(0,50))}</span>`
    }</td>`;
  tbody.appendChild(tr);
}

// ── Malware ───────────────────────────────────────────────────────────────────
function quickMalware() { showPanel('malware'); runMalware(); }

function runMalware() {
  S.findings.malware = [];
  document.getElementById('malware-results').style.display = 'none';
  document.getElementById('malware-empty').style.display = '';
  document.getElementById('malware-tbody').innerHTML = '';
  btn('btn-malware', true, '⏳ Escaneando…');
  appendLog('section', '═══ ESCANEO DE MALWARE ═══');

  const skip = [];
  if (!document.getElementById('m-yara')?.checked)    skip.push('yara');
  if (!document.getElementById('m-hash')?.checked)    skip.push('hash');
  if (!document.getElementById('m-auditd')?.checked)  skip.push('auditd');
  if (!document.getElementById('m-cron')?.checked)    skip.push('cron');
  if (!document.getElementById('m-webshell')?.checked)skip.push('webshell');

  wsRun('malware', {
    skip,
    yara_rules: document.getElementById('yara-rules')?.value || null,
    web_roots: document.getElementById('web-roots')?.value.split(/\s+/).filter(Boolean) || null,
  }, {
    onFinding(f) {
      S.findings.malware.push(f);
      appendMalwareRow(f);
    },
    onDone() {
      btn('btn-malware', false, '▶ Iniciar escaneo');
      document.getElementById('malware-results').style.display = '';
      document.getElementById('malware-empty').style.display = 'none';
      renderSummary('malware-summary-bar', S.findings.malware);
      updateDashboard();
    },
  });
}

function appendMalwareRow(f) {
  const tbody = document.getElementById('malware-tbody');
  const tr = document.createElement('tr');
  tr.dataset.sev = f.severity;
  tr.onclick = () => openDrawer(f);
  tr.innerHTML = `
    <td>${sevBadge(f.severity)}</td>
    <td style="font-size:.78rem;color:var(--text2)">${esc(f.category.replace('malware/',''))}</td>
    <td>${esc(f.title)}</td>
    <td style="font-size:.75rem;color:var(--text2);font-family:monospace">${esc((f.file_path||'').substring(0,50))}</td>
    <td><button class="fix-btn" onclick="event.stopPropagation();openDrawer(${JSON.stringify(f).replace(/"/g,'&quot;')})">Ver detalle</button></td>`;
  tbody.appendChild(tr);
}

// ── Code ──────────────────────────────────────────────────────────────────────
function runCode() {
  const path = document.getElementById('code-path')?.value.trim();
  if (!path) { toast('Introduce la ruta del proyecto'); return; }
  S.findings.code = [];
  document.getElementById('code-results').style.display = 'none';
  document.getElementById('code-empty').style.display = '';
  document.getElementById('code-tbody').innerHTML = '';
  btn('btn-code', true, '⏳ Analizando código…');
  appendLog('section', `═══ ANÁLISIS DE CÓDIGO: ${path} ═══`);

  wsRun('code', { path }, {
    onFinding(f) {
      S.findings.code.push(f);
      const tbody = document.getElementById('code-tbody');
      const tr = document.createElement('tr');
      tr.dataset.sev = f.severity;
      tr.onclick = () => openDrawer(f);
      tr.innerHTML = `
        <td>${sevBadge(f.severity)}</td>
        <td style="font-family:monospace;font-size:.75rem">${esc(f.file_path || '')}${f.line_number ? ':'+f.line_number : ''}</td>
        <td>${esc(f.title)}</td>
        <td style="font-size:.78rem;color:var(--text2)">${esc((f.remediation||'').substring(0,80))}</td>`;
      tbody.appendChild(tr);
    },
    onDone() {
      btn('btn-code', false, '▶ Analizar código');
      document.getElementById('code-results').style.display = '';
      document.getElementById('code-empty').style.display = 'none';
    },
  });
}

// ── Network ───────────────────────────────────────────────────────────────────
function quickNetwork() { showPanel('network'); runNetworkScan(); }

function _netParams() {
  return {
    networks: document.getElementById('net-networks')?.value || '',
    ssh_user: document.getElementById('net-user')?.value || 'root',
    ssh_port: document.getElementById('net-port')?.value || '22',
    ssh_key:  document.getElementById('net-key')?.value || '',
    ssh_password: document.getElementById('net-pass')?.value || '',
    ssh_audit: true,
    vuln_scan: document.getElementById('vuln-scan')?.checked || false,
  };
}

function discoverOnly() {
  const networks = document.getElementById('net-networks')?.value || '';
  appendLog('info', 'Descubriendo dispositivos…');
  fetch('/api/network/discover' + (networks ? '?networks=' + encodeURIComponent(networks) : ''))
    .then(r => r.json())
    .then(d => {
      if (d.hosts?.length) {
        renderDiscoveredChips(d.hosts.map(ip => ({ ip, scan_status: 'discovered' })));
        toast(`✓ ${d.hosts.length} dispositivos encontrados`);
        appendLog('ok', `Descubiertos: ${d.hosts.join(', ')}`);
      } else {
        toast('Sin dispositivos detectados');
      }
    })
    .catch(e => toast('Error: ' + e));
}

function runNetworkScan() {
  S.findings.network = [];
  S.devices = [];
  document.getElementById('network-table').style.display = 'none';
  document.getElementById('network-empty').style.display = '';
  document.getElementById('network-findings-tbody').innerHTML = '';
  document.getElementById('ssh-findings-area').style.display = 'none';
  document.getElementById('host-chips').innerHTML = '';
  btn('btn-network', true, '⏳ Escaneando red…');
  appendLog('section', '═══ ESCANEO DE RED ═══');

  wsRun('network', _netParams(), {
    onDevices(devices) {
      S.devices = devices;
      document.getElementById('network-empty').style.display = 'none';
      document.getElementById('network-table').style.display = 'table';
      const tbody = document.getElementById('network-tbody');
      tbody.innerHTML = '';
      renderDiscoveredChips(devices);
      devices.forEach(d => {
        const tr = document.createElement('tr');
        const ports = (d.open_ports || []).slice(0, 5)
          .map(p => `<span style="background:var(--bg3);padding:1px 5px;border-radius:3px;font-size:.72rem">${p.port}/${p.service||'?'}</span>`)
          .join(' ');
        const riskClass = `risk-${d.risk_level || 'low'}`;
        const cveCount = (d.cves || []).length;
        tr.innerHTML = `
          <td>
            <b>${esc(d.ip)}</b><br>
            <span style="font-size:.75rem;color:var(--text2)">${esc(d.hostname || d.mac || '')}</span>
          </td>
          <td style="font-size:.82rem">${esc(d.os_name || 'Desconocido')}${d.os_accuracy ? ` <span style="color:var(--text2)">(${d.os_accuracy}%)</span>` : ''}</td>
          <td>${ports || '<span style="color:var(--text2)">—</span>'}</td>
          <td class="${riskClass}">${(d.risk_level||'low').toUpperCase()}</td>
          <td>${cveCount ? `<span style="color:var(--red);font-weight:600">${cveCount} CVEs</span>` : '—'}</td>
          <td>
            ${d.has_ssh ? `<button class="fix-btn remote" onclick="sshAuditOne('${esc(d.ip)}',${d.ssh_port||22})">🔍 Auditar</button>` : ''}
          </td>`;
        document.getElementById('network-tbody').appendChild(tr);
      });
      updateDashboard();
    },
    onHostResult(hr) {
      updateHostChip(hr);
      if (hr.status === 'ok') {
        appendLog('ok', `✓ ${hr.host}: ${hr.count} problemas encontrados`);
      } else {
        appendLog('warn', `✗ ${hr.host}: ${hr.status} — ${hr.error || ''}`);
      }
    },
    onFinding(f) {
      S.findings.network.push(f);
      const tbody = document.getElementById('network-findings-tbody');
      document.getElementById('ssh-findings-area').style.display = '';
      const tr = document.createElement('tr');
      tr.dataset.sev = f.severity;
      const host = f.source_host || (f.id.includes('::') ? f.id.split('::')[0] : '');
      tr.onclick = () => openDrawer(f, host);
      tr.innerHTML = `
        <td style="font-family:monospace;font-size:.78rem;color:var(--blue)">${esc(host)}</td>
        <td>${sevBadge(f.severity)}</td>
        <td>${esc(f.title)}</td>
        <td style="font-size:.78rem;color:var(--text2)">${esc((f.remediation||'').substring(0,60))}</td>
        <td>${f.auto_fix ? `<button class="fix-btn remote" onclick="event.stopPropagation();applyFixRemote('${esc(f.id)}','${esc(host)}',this)">⚡ Fix</button>` : ''}</td>`;
      tbody.appendChild(tr);
    },
    onDone() {
      btn('btn-network', false, '▶ Descubrir y analizar todo');
      updateDashboard();
    },
  });
}

function renderDiscoveredChips(devices) {
  const container = document.getElementById('host-chips');
  container.innerHTML = '';
  devices.forEach(d => {
    const chip = document.createElement('span');
    chip.className = 'host-chip scanning';
    chip.id = `chip-${d.ip.replace(/\./g,'_')}`;
    chip.textContent = `⏳ ${d.ip}`;
    container.appendChild(chip);
  });
}

function updateHostChip(hr) {
  const chip = document.getElementById(`chip-${hr.host.replace(/\./g,'_')}`);
  if (!chip) return;
  chip.className = `host-chip ${hr.status}`;
  const icons = { ok: '✓', unreachable: '✗', auth_failed: '🔑', error: '⚠' };
  const icon = icons[hr.status] || '?';
  chip.textContent = `${icon} ${hr.host}${hr.status === 'ok' ? ` (${hr.count})` : hr.error ? ` — ${hr.error.substring(0,25)}` : ''}`;
}

function sshAuditOne(ip, port) {
  const creds = {
    hosts: ip,
    ssh_user: document.getElementById('net-user')?.value || 'root',
    ssh_port: port,
    ssh_key: document.getElementById('net-key')?.value || '',
    ssh_password: document.getElementById('net-pass')?.value || '',
  };
  appendLog('section', `═══ SSH AUDIT: ${ip} ═══`);
  wsRun('ssh', creds, {
    onFinding(f) {
      S.findings.network.push(f);
      document.getElementById('ssh-findings-area').style.display = '';
      const tbody = document.getElementById('network-findings-tbody');
      const tr = document.createElement('tr');
      tr.dataset.sev = f.severity;
      tr.onclick = () => openDrawer(f, ip);
      tr.innerHTML = `
        <td style="font-family:monospace;font-size:.78rem;color:var(--blue)">${esc(ip)}</td>
        <td>${sevBadge(f.severity)}</td>
        <td>${esc(f.title)}</td>
        <td style="font-size:.78rem;color:var(--text2)">${esc((f.remediation||'').substring(0,60))}</td>
        <td>${f.auto_fix ? `<button class="fix-btn remote" onclick="event.stopPropagation();applyFixRemote('${esc(f.id)}','${esc(ip)}',this)">⚡ Fix</button>` : ''}</td>`;
      tbody.appendChild(tr);
    },
    onDone() { updateDashboard(); },
  });
}

// ── Fix local ─────────────────────────────────────────────────────────────────
async function applyFix(findingId, btn_el) {
  if (btn_el) { btn_el.disabled = true; btn_el.textContent = '⏳'; }
  try {
    const r = await fetch('/api/fix/local', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finding_id: findingId }),
    });
    const d = await r.json();
    if (d.ok) {
      appendLog('ok', `✓ Corregido: ${findingId}`);
      toast('✓ Corrección aplicada');
      if (btn_el) { btn_el.textContent = '✓ Listo'; btn_el.style.background = 'var(--green)'; }
    } else {
      appendLog('error', `✗ Error: ${d.error}`);
      toast('Error: ' + d.error);
      if (btn_el) { btn_el.disabled = false; btn_el.textContent = '⚡ Corregir'; }
    }
  } catch (e) {
    appendLog('error', '✗ ' + e);
    if (btn_el) { btn_el.disabled = false; btn_el.textContent = '⚡ Corregir'; }
  }
}

async function fixAll(scope) {
  const fixable = (S.findings[scope] || []).filter(f => f.auto_fix);
  if (!fixable.length) { toast('Sin correcciones automáticas disponibles'); return; }
  appendLog('section', `═══ APLICANDO ${fixable.length} CORRECCIONES ═══`);
  for (const f of fixable) {
    const btnEl = document.getElementById(`fix-${f.id}`);
    await applyFix(f.id, btnEl);
    await new Promise(r => setTimeout(r, 200));
  }
}

// ── Fix remoto ────────────────────────────────────────────────────────────────
async function applyFixRemote(findingId, host, btn_el) {
  if (btn_el) { btn_el.disabled = true; btn_el.textContent = '⏳'; }
  const sshKey  = document.getElementById('net-key')?.value || '';
  const sshPass = document.getElementById('net-pass')?.value || '';
  const sshUser = document.getElementById('net-user')?.value || 'root';
  try {
    const r = await fetch('/api/fix/remote', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finding_id: findingId, host, ssh_user: sshUser, ssh_key: sshKey, ssh_password: sshPass }),
    });
    const d = await r.json();
    if (d.ok) {
      appendLog('ok', `✓ Fix remoto en ${host}: ${findingId}`);
      toast(`✓ Corrección aplicada en ${host}`);
      if (btn_el) { btn_el.textContent = '✓'; btn_el.style.background = 'var(--green)'; }
    } else {
      appendLog('error', `✗ Error remoto: ${d.error}`);
      toast('Error: ' + d.error);
      if (btn_el) { btn_el.disabled = false; btn_el.textContent = '⚡ Fix'; }
    }
  } catch (e) {
    appendLog('error', '✗ ' + e);
    if (btn_el) { btn_el.disabled = false; btn_el.textContent = '⚡ Fix'; }
  }
}

// ── Drawer ────────────────────────────────────────────────────────────────────
function openDrawer(f, host) {
  const hostLabel = host || f.source_host || (f.id?.includes('::') ? f.id.split('::')[0] : null);
  const isRemote = !!hostLabel;

  document.getElementById('drawer-sev-badge').outerHTML =
    `<span id="drawer-sev-badge">${sevBadge(f.severity)}</span>`;
  document.getElementById('drawer-title').textContent = f.title;

  document.getElementById('drawer-body').innerHTML = `
    ${hostLabel ? `<div class="d-field"><div class="d-label">Equipo</div><div class="d-value" style="color:var(--blue);font-family:monospace">${esc(hostLabel)}</div></div>` : ''}
    <div class="d-field">
      <div class="d-label">¿Qué ocurre?</div>
      <div class="d-value">${esc(f.description || f.title)}</div>
    </div>
    ${f.evidence ? `<div class="d-field"><div class="d-label">Evidencia técnica</div><div class="d-code">${esc(f.evidence)}</div></div>` : ''}
    ${f.file_path ? `<div class="d-field"><div class="d-label">Fichero afectado</div><div class="d-value" style="font-family:monospace;font-size:.82rem">${esc(f.file_path)}${f.line_number?':'+f.line_number:''}</div></div>` : ''}
    <div class="d-field">
      <div class="d-label">Cómo solucionarlo</div>
      <div class="d-code">${esc(f.remediation)}</div>
    </div>
    <div class="d-field">
      <div class="d-label">Categoría técnica</div>
      <div class="d-value" style="color:var(--text2);font-size:.8rem">${esc(f.category)} / ${esc(f.id)}</div>
    </div>
    ${f.auto_fix && !isRemote
      ? `<button class="d-fix-btn" onclick="applyFix('${esc(f.id)}',this)">⚡ Aplicar corrección automática</button>`
      : ''}
    ${f.auto_fix && isRemote
      ? `<button class="d-fix-btn remote" onclick="applyFixRemote('${esc(f.id)}','${esc(hostLabel||'')}',this)">⚡ Corregir en ${esc(hostLabel||'')}</button>`
      : ''}
    ${!f.auto_fix
      ? `<div style="margin-top:10px;padding:10px;background:var(--bg3);border-radius:6px;font-size:.82rem;color:var(--text2)">
           ℹ️ Esta corrección requiere revisión manual. Consulta la remediación arriba.
         </div>`
      : ''}
  `;

  document.getElementById('drawer').classList.add('open');
  document.getElementById('drawer-backdrop').classList.add('show');
}

function closeDrawer() {
  document.getElementById('drawer').classList.remove('open');
  document.getElementById('drawer-backdrop').classList.remove('show');
}

// ── Filtrado y búsqueda ───────────────────────────────────────────────────────
function filterTable(scope, sev, btnEl) {
  const tbodyMap = {
    audit: 'audit-tbody', malware: 'malware-tbody',
    code: 'code-tbody', network: 'network-findings-tbody',
  };
  const tbody = document.getElementById(tbodyMap[scope] || (scope + '-tbody'));
  if (!tbody) return;
  tbody.querySelectorAll('tr').forEach(tr => {
    tr.style.display = (sev === 'all' || tr.dataset.sev === sev) ? '' : 'none';
  });
  if (btnEl) {
    btnEl.closest('.toolbar')?.querySelectorAll('.filter')
      .forEach(b => b.classList.remove('active'));
    btnEl.classList.add('active');
  }
}

function searchTable(tbodyId, q) {
  const lower = q.toLowerCase();
  document.getElementById(tbodyId)?.querySelectorAll('tr').forEach(tr => {
    tr.style.display = tr.textContent.toLowerCase().includes(lower) ? '' : 'none';
  });
}

// ── Exportar / Informes ───────────────────────────────────────────────────────
function exportJSON(scope) {
  const data = S.findings[scope];
  if (!data?.length) { toast('Sin datos para exportar'); return; }
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  _download(blob, `cyberhound_${scope}_${_date()}.json`);
}

function downloadReport(fmt, scope) {
  const findings = S.findings[scope];
  if (!findings?.length) { toast(`Ejecuta primero el análisis de ${scope}`); return; }
  fetch(`/api/report/${fmt}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ findings, source: scope }),
  })
  .then(r => r.blob())
  .then(blob => _download(blob, `cyberhound_${scope}_${_date()}.${fmt === 'ansible' ? 'yml' : fmt}`))
  .catch(e => toast('Error: ' + e));
}

function downloadLog() {
  if (!S.logLines.length) { toast('Sin log disponible'); return; }
  const blob = new Blob([S.logLines.join('\n')], { type: 'text/plain' });
  _download(blob, `cyberhound_log_${_date()}.txt`);
}

function _download(blob, filename) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

function _date() {
  return new Date().toISOString().slice(0, 16).replace(':', '-');
}

// ── Config / API Keys ─────────────────────────────────────────────────────────
function saveKeys() {
  const keys = {
    shodan:     document.getElementById('key-shodan')?.value,
    virustotal: document.getElementById('key-vt')?.value,
    abuseipdb:  document.getElementById('key-abuse')?.value,
    greynoise:  document.getElementById('key-grey')?.value,
    hibp:       document.getElementById('key-hibp')?.value,
  };
  fetch('/api/config/keys', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(keys),
  })
  .then(r => r.json())
  .then(d => {
    const el = document.getElementById('keys-msg');
    if (el) el.textContent = d.ok ? '✓ Guardado correctamente' : '✗ Error: ' + d.error;
    if (el) el.style.color = d.ok ? 'var(--green)' : 'var(--red)';
    toast(d.ok ? '✓ API keys guardadas' : '✗ Error guardando');
  });
}

function loadKeys() {
  fetch('/api/config/keys')
    .then(r => r.json())
    .then(d => {
      ['shodan','virustotal','abuseipdb','greynoise','hibp'].forEach(k => {
        const el = document.getElementById('key-' + (k === 'virustotal' ? 'vt' : k === 'abuseipdb' ? 'abuse' : k === 'greynoise' ? 'grey' : k));
        if (el && d[k]) el.value = d[k];
      });
      const msg = document.getElementById('keys-msg');
      if (msg) { msg.textContent = '✓ Claves cargadas'; msg.style.color = 'var(--green)'; }
    });
}

function saveSshConfig() {
  toast('Configuración SSH guardada en sesión');
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  setStatus('idle', 'Listo');
  appendLog('info', 'CyberHound Pro v6.0.0 iniciado. Bienvenido.');
  loadKeys();
});
