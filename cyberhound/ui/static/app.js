/* CyberHound Pro v6.1 — app.js */
'use strict';

// ── Estado global ──────────────────────────────────────────────────────────
const S = {
  findings: { audit: [], malware: [], code: [], network: [] },
  devices:  [],
  ws:       null,
  wsRetries: 0,
  running:  false,
  logLines: [],
  lastScanId: null,
};

// ── Utilidades ────────────────────────────────────────────────────────────
const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const fmt = dt => dt ? new Date(dt).toLocaleString('es-ES',{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'}) : '—';
const dur = s => s==null?'—':s<60?`${Math.round(s)}s`:`${Math.round(s/60)}m ${Math.round(s%60)}s`;

function toast(msg, type='info') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'show ' + (type === 'error' ? 'toast-err' : '');
  clearTimeout(t._tid);
  t._tid = setTimeout(() => t.classList.remove('show'), 3000);
}

function btn(id, disabled, label) {
  const b = document.getElementById(id);
  if (b) { b.disabled = disabled; if (label) b.textContent = label; }
}

// ── Navegación ────────────────────────────────────────────────────────────
function showPanel(name) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
  document.getElementById('panel-' + name)?.classList.add('active');
  document.querySelector(`[data-panel="${name}"]`)?.classList.add('active');
  closeDrawer();
  // Cargar datos al entrar a ciertas secciones
  if (name === 'history')     loadHistory();
  if (name === 'settings')    { loadKeys(); loadNotifications(); loadScheduler(); loadSuppresions(); loadUsers(); }
  if (name === 'dashboard')   loadDashboard();
}

function showCfgTab(name) {
  document.querySelectorAll('.cfg-tab').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.cfg-panel').forEach(p => p.classList.remove('active'));
  document.querySelector(`[data-cfg="${name}"]`)?.classList.add('active');
  document.getElementById('cfg-' + name)?.classList.add('active');
  // Cargar datos al activar tabs que los necesitan
  if (name === 'siem')         loadSIEM();
  if (name === 'users')        loadUsers();
  if (name === 'suppressions') loadSuppressions();
  if (name === 'scheduler')    loadScheduler();
}

// ── Status ────────────────────────────────────────────────────────────────
function setStatus(state, label) {
  document.getElementById('status-dot').className = 'dot ' + state;
  document.getElementById('status-label').textContent = label;
}

// ── Log ───────────────────────────────────────────────────────────────────
function appendLog(level, text) {
  const body = document.getElementById('log-body');
  const ts = new Date().toLocaleTimeString('es', {hour12:false});
  const div = document.createElement('div');
  div.className = 'log-' + (level||'info');
  div.innerHTML = `<span class="log-ts">${ts}</span>${esc(text)}`;
  body.appendChild(div);
  body.scrollTop = body.scrollHeight;
  S.logLines.push(`[${ts}] [${level}] ${text}`);
}
function toggleLog() { document.getElementById('log-overlay').classList.toggle('show'); }

// ── WebSocket con reconexión automática ───────────────────────────────────
function wsRun(task, params, handlers = {}) {
  if (S.ws) { S.ws.close(); S.ws = null; }
  S.running = true; S.wsRetries = 0;
  setStatus('running', 'Analizando…');
  _wsConnect(task, params, handlers);
}

function _wsConnect(task, params, handlers) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  S.ws = ws;

  ws.onopen = () => {
    S.wsRetries = 0;
    ws.send(JSON.stringify({task, ...params}));
  };

  ws.onmessage = ev => {
    const msg = JSON.parse(ev.data);
    switch (msg.type) {
      case 'log':         appendLog(msg.level, msg.text); break;
      case 'finding':     handlers.onFinding?.(msg.data); break;
      case 'devices':     handlers.onDevices?.(msg.data); break;
      case 'host_result': handlers.onHostResult?.(msg.data); break;
      case 'new_assets':  _showNewAssetsAlert(msg.ips); break;
      case 'new_critical':
        appendLog('error', `⚠ ${msg.count} nuevos hallazgos CRÍTICOS detectados`);
        toast(`⚠ ${msg.count} nuevos hallazgos críticos`, 'error');
        break;
      case 'done':
        S.running = false;
        S.lastScanId = msg.scan_id;
        setStatus('done', `Completado — ${msg.count} hallazgos`);
        appendLog('ok', `✓ ${msg.count} hallazgos. Scan ID: ${msg.scan_id}. Score: ${msg.score ?? '—'}/100`);
        handlers.onDone?.(msg);
        // Recargar dashboard en background
        setTimeout(loadDashboard, 500);
        break;
      case 'error':
        S.running = false;
        setStatus('error', msg.text);
        appendLog('error', '✗ ' + msg.text);
        toast(msg.text, 'error');
        handlers.onError?.(msg);
        break;
    }
  };

  ws.onerror = (ev) => {
    appendLog('warn', 'Error en la conexión WebSocket');
  };

  ws.onclose = (ev) => {
    const wasRunning = S.running;
    S.running = false;
    // Reconexión automática con backoff exponencial si se cortó durante un scan
    if (wasRunning && S.wsRetries < 3) {
      S.wsRetries++;
      const delay = [1500, 3000, 7000][S.wsRetries - 1] || 7000;
      appendLog('warn', `⚡ Conexión perdida. Reconectando en ${delay/1000}s… (${S.wsRetries}/3)`);
      setStatus('running', `Reconectando (${S.wsRetries}/3)…`);
      setTimeout(() => _wsConnect(task, params, handlers), delay);
    } else if (wasRunning) {
      setStatus('error', 'Conexión perdida');
      appendLog('error', '✗ No se pudo restablecer la conexión.');
      toast('Conexión perdida — inténtalo de nuevo', 'error');
      handlers.onError?.({ text: 'Conexión perdida' });
    }
  };
}

// ── Dashboard ─────────────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    const [statsResp, trendResp] = await Promise.all([
      fetch('/api/dashboard'),
      fetch('/api/score/trend?type=audit&days=30'),
    ]);
    // Si la sesión expiró, redirigir al login
    if (statsResp.status === 401 || statsResp.redirected) {
      window.location.href = '/login?error=Sesión+expirada';
      return;
    }
    const contentType = statsResp.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      // No es JSON — probablemente redirigido al login
      return;
    }
    const stats = await statsResp.json();
    const trend = trendResp.ok ? await trendResp.json() : [];
    _renderDashboard(stats, trend);
  } catch (e) {
    // Error silencioso en el polling — no saturar el log
    if (e.message && !e.message.includes('JSON')) {
      appendLog('warn', 'Dashboard: ' + e.message);
    }
  }
}

function _renderDashboard(stats, trend) {
  // Score
  const audit = stats.last_scans?.audit;
  if (audit) {
    const score = audit.score ?? 0;
    const color = score >= 80 ? 'var(--green)' : score >= 50 ? 'var(--medium)' : 'var(--red)';
    const label = score >= 80 ? 'Bueno' : score >= 50 ? 'Mejorable' : 'Crítico';
    document.getElementById('score-num').textContent = score;
    document.getElementById('score-circle').style.borderColor = color;
    document.getElementById('score-label').textContent = label;
    document.getElementById('score-label').style.color = color;
    document.getElementById('score-hint').textContent = `Último audit: ${fmt(audit.started_at)}`;

    // Contadores del último audit
    ['critical','high','medium','low'].forEach(s => {
      const el = document.getElementById('cnt-' + s);
      if (el) el.textContent = audit[s] ?? 0;
    });
  }

  // Dispositivos
  const devEl = document.getElementById('dash-devices-count');
  if (devEl) devEl.textContent = stats.total_assets || '—';
  const unauthEl = document.getElementById('dash-unauth');
  if (unauthEl && stats.unauthorized_assets > 0) {
    unauthEl.innerHTML = `<span style="color:var(--red)">⚠ ${stats.unauthorized_assets} dispositivo(s) no autorizado(s)</span>`;
  }

  // Últimos scans por tipo
  const scansList = document.getElementById('dash-last-scans');
  if (scansList) {
    const icons = {audit:'🔍', malware:'🦠', network:'📡', code:'📝'};
    const labels = {audit:'Seguridad', malware:'Malware', network:'Red', code:'Código'};
    scansList.innerHTML = Object.entries(stats.last_scans || {}).map(([type, scan]) =>
      scan ? `<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--border)">
        <span>${icons[type]||'📋'} ${labels[type]||type}</span>
        <span style="color:var(--text2)">${fmt(scan.started_at)}</span>
        <span>${_scorePill(scan.score)}</span>
      </div>` : ''
    ).join('') || '<div style="color:var(--text2);font-size:.82rem">Sin análisis ejecutados todavía</div>';
  }

  // Hallazgos críticos
  const critList = document.getElementById('dash-critical-list');
  if (critList) {
    if (stats.critical_findings?.length) {
      critList.innerHTML = stats.critical_findings.map(f => `
        <div class="critical-item" onclick="openDrawerFromData(${JSON.stringify(f).replace(/"/g,'&quot;')})">
          <span>${_sevBadge('critical')}</span>
          <div>
            <div class="item-title">${esc(f.title)}</div>
            <div class="item-fix">${esc((f.remediation||'').substring(0,80))}</div>
          </div>
          ${f.auto_fix ? '<span class="fix-btn" style="pointer-events:none">⚡</span>' : ''}
        </div>`).join('');
    } else if (audit) {
      critList.innerHTML = '<div style="color:var(--green);padding:10px">✓ Sin hallazgos críticos en el último análisis</div>';
    } else {
      critList.innerHTML = '<div class="empty-hint"><span>⏳</span><p>Ejecuta un análisis de seguridad para ver los resultados.</p></div>';
    }
  }

  // Gráfico de tendencia
  const chartEl = document.getElementById('dash-trend-chart');
  if (chartEl && trend?.length) {
    const maxScore = 100;
    chartEl.innerHTML = trend.map(p => {
      const h = Math.max(4, Math.round((p.avg_score / maxScore) * 70));
      const color = p.avg_score >= 80 ? 'var(--green)' : p.avg_score >= 50 ? 'var(--medium)' : 'var(--red)';
      const day = p.day ? p.day.substring(5) : '';
      return `<div class="trend-bar" style="height:${h}px;background:${color}" title="${day}: ${Math.round(p.avg_score)}/100">
        <div class="tip">${day}: ${Math.round(p.avg_score)}/100</div></div>`;
    }).join('');
  }
}

function _scorePill(score) {
  if (score == null) return '<span style="color:var(--text2)">—</span>';
  const cls = score >= 80 ? 'score-good' : score >= 50 ? 'score-medium' : 'score-bad';
  return `<span class="score-pill ${cls}">${score}</span>`;
}

// ── Audit ─────────────────────────────────────────────────────────────────
function quickAudit() { showPanel('audit'); runAudit(); }



function _appendAuditRow(f) {
  const tbody = document.getElementById('audit-tbody');
  if (!tbody) return;
  const tr = document.createElement('tr');
  tr.dataset.sev = f.severity;
  tr.onclick = () => openDrawer(f);
  tr.innerHTML = `
    <td>${_sevBadge(f.severity)}</td>
    <td><b>${esc(f.title)}</b></td>
    <td style="color:var(--text2);font-size:.82rem">${esc((f.description||'').substring(0,100))}</td>
    <td>${f.auto_fix
      ? `<button class="fix-btn" id="fix-${esc(f.id)}" onclick="event.stopPropagation();applyFix('${esc(f.id)}',this)">⚡ Corregir</button>`
      : `<span style="font-size:.75rem;color:var(--text2)">Manual</span>`
    }</td>`;
  tbody.appendChild(tr);
  document.getElementById('audit-results')?.style && (document.getElementById('audit-results').style.display = '');
  document.getElementById('audit-empty') && (document.getElementById('audit-empty').style.display = 'none');
}

// ── Malware ───────────────────────────────────────────────────────────────
function quickMalware() { showPanel('malware'); runMalware(); }



// ── Code ──────────────────────────────────────────────────────────────────
function runCode() {
  const path = document.getElementById('code-path')?.value.trim();
  if (!path) { toast('Introduce la ruta del proyecto', 'error'); return; }
  S.findings.code = [];
  document.getElementById('code-results').style.display = 'none';
  document.getElementById('code-empty').style.display = '';
  document.getElementById('code-tbody').innerHTML = '';
  btn('btn-code', true, '⏳ Analizando…');
  appendLog('section', `═══ ANÁLISIS DE CÓDIGO: ${path} ═══`);
  wsRun('code', {path}, {
    onFinding(f) {
      S.findings.code.push(f);
      const tbody = document.getElementById('code-tbody');
      const tr = document.createElement('tr');
      tr.dataset.sev = f.severity; tr.onclick = () => openDrawer(f);
      tr.innerHTML = `
        <td>${_sevBadge(f.severity)}</td>
        <td style="font-family:monospace;font-size:.75rem">${esc(f.file_path||'')}${f.line_number?':'+f.line_number:''}</td>
        <td>${esc(f.title)}</td>
        <td style="font-size:.78rem;color:var(--text2)">${esc((f.remediation||'').substring(0,80))}</td>`;
      tbody.appendChild(tr);
      document.getElementById('code-results').style.display = '';
      document.getElementById('code-empty').style.display = 'none';
    },
    onDone() { btn('btn-code', false, '▶ Analizar'); },
  });
}

// ── Network ───────────────────────────────────────────────────────────────
function quickNetwork() { showPanel('network'); runNetworkScan(); }

function discoverOnly() {
  const networks = document.getElementById('net-networks')?.value || '';
  fetch('/api/network/discover' + (networks ? '?networks='+encodeURIComponent(networks) : ''))
    .then(r => r.json())
    .then(d => {
      if (d.hosts?.length) {
        toast(`✓ ${d.hosts.length} dispositivos encontrados`);
        appendLog('ok', `Descubiertos: ${d.hosts.join(', ')}`);
        _renderNetworkTable(d.hosts.map(ip => ({ip, scan_status:'discovered', open_ports:[]})));
      } else toast('Sin dispositivos detectados');
    }).catch(e => toast('Error: ' + e, 'error'));
}

function runNetworkScan() {
  S.findings.network = []; S.devices = [];
  document.getElementById('network-table').style.display = 'none';
  document.getElementById('network-empty').style.display = '';
  document.getElementById('network-findings-tbody').innerHTML = '';
  document.getElementById('ssh-findings-area').style.display = 'none';
  document.getElementById('host-chips').innerHTML = '';
  btn('btn-network', true, '⏳ Escaneando red…');
  appendLog('section', '═══ ESCANEO DE RED ═══');
  wsRun('network', {
    networks: document.getElementById('net-networks')?.value || '',
    ssh_user: document.getElementById('net-user')?.value || 'root',
    ssh_port: document.getElementById('net-port')?.value || '22',
    ssh_key:  document.getElementById('net-key')?.value || '',
    ssh_password: document.getElementById('net-pass')?.value || '',
    ssh_audit: true,
    vuln_scan: document.getElementById('vuln-scan')?.checked || false,
  }, {
    onDevices(devices) {
      S.devices = devices;
      _renderNetworkTable(devices);
      document.getElementById('network-empty').style.display = 'none';
    },
    onHostResult(hr) { _updateHostChip(hr); },
    onFinding(f) {
      S.findings.network.push(f);
      document.getElementById('ssh-findings-area').style.display = '';
      const tbody = document.getElementById('network-findings-tbody');
      const host = f.source_host || (f.id?.includes('::') ? f.id.split('::')[0] : '');
      const tr = document.createElement('tr');
      tr.dataset.sev = f.severity;
      tr.onclick = () => openDrawer(f, host);
      tr.innerHTML = `
        <td style="font-family:monospace;font-size:.78rem;color:var(--blue)">${esc(host)}</td>
        <td>${_sevBadge(f.severity)}</td>
        <td>${esc(f.title)}</td>
        <td style="font-size:.78rem;color:var(--text2)">${esc((f.remediation||'').substring(0,60))}</td>
        <td>${f.auto_fix ? `<button class="fix-btn remote" onclick="event.stopPropagation();applyFixRemote('${esc(f.id)}','${esc(host)}',this)">⚡ Fix</button>` : ''}</td>`;
      tbody.appendChild(tr);
    },
    onDone() { btn('btn-network', false, '▶ Descubrir y analizar'); },
  });
}

function _renderNetworkTable(devices) {
  const tbody = document.getElementById('network-tbody');
  document.getElementById('network-table').style.display = 'table';
  document.getElementById('network-empty').style.display = 'none';
  // Chips de estado
  const chips = document.getElementById('host-chips');
  chips.innerHTML = '';
  devices.forEach(d => {
    const chip = document.createElement('span');
    chip.className = 'host-chip scanning';
    chip.id = `chip-${d.ip.replace(/\./g,'_')}`;
    chip.textContent = `⏳ ${d.ip}`;
    chips.appendChild(chip);
  });
  // Tabla
  tbody.innerHTML = '';
  devices.forEach(d => {
    const ports = (d.open_ports||[]).slice(0,5).map(p =>
      `<span style="background:var(--bg3);padding:1px 5px;border-radius:3px;font-size:.72rem">${typeof p === 'object' ? p.port+'/'+(p.service||'?') : p}</span>`
    ).join(' ');
    const risk = d.risk_level || 'low';
    const riskCls = risk === 'high' ? 'risk-high' : risk === 'medium' ? 'risk-medium' : 'risk-low';
    const cveCount = (d.cves||[]).length;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><b>${esc(d.ip)}</b><br><span style="font-size:.75rem;color:var(--text2)">${esc(d.hostname||d.mac||'')}</span></td>
      <td style="font-size:.82rem">${esc(d.os_name||'Desconocido')}</td>
      <td>${ports||'—'}</td>
      <td class="${riskCls}">${risk.toUpperCase()}</td>
      <td>${cveCount ? `<span style="color:var(--red);font-weight:600">${cveCount} CVEs</span>` : '—'}</td>
      <td id="status-${d.ip.replace(/\./g,'_')}" style="font-size:.78rem;color:var(--text2)">Pendiente</td>
      <td>${d.has_ssh !== false ? `<button class="fix-btn remote" onclick="sshAuditOne('${esc(d.ip)}',${d.ssh_port||22})">🔍 Auditar</button>` : ''}</td>`;
    tbody.appendChild(tr);
  });
}

function _updateHostChip(hr) {
  const chip = document.getElementById(`chip-${hr.host.replace(/\./g,'_')}`);
  if (!chip) return;
  const icons = {ok:'✓', unreachable:'✗', auth_failed:'🔑', error:'⚠'};
  chip.className = `host-chip ${hr.status}`;
  chip.textContent = `${icons[hr.status]||'?'} ${hr.host}${hr.status==='ok'?` (${hr.count})`:hr.error?` — ${hr.error.substring(0,25)}`:''}`;
  const statusEl = document.getElementById(`status-${hr.host.replace(/\./g,'_')}`);
  if (statusEl) {
    statusEl.textContent = hr.status === 'ok' ? `✓ ${hr.count} hallazgos` : hr.status;
    statusEl.style.color = hr.status === 'ok' ? 'var(--green)' : 'var(--red)';
  }
}

function _showNewAssetsAlert(ips) {
  const alert = document.createElement('div');
  alert.className = 'new-asset-alert';
  alert.innerHTML = `⚠ Nuevos dispositivos en la red: <b>${ips.join(', ')}</b>`;
  document.getElementById('host-chips').before(alert);
  setTimeout(() => alert.remove(), 30000);
}

function sshAuditOne(ip, port) {
  appendLog('section', `═══ SSH AUDIT: ${ip} ═══`);
  wsRun('ssh', {
    hosts: ip,
    ssh_user: document.getElementById('net-user')?.value || 'root',
    ssh_port: port,
    ssh_key:  document.getElementById('net-key')?.value || '',
    ssh_password: document.getElementById('net-pass')?.value || '',
  }, {
    onFinding(f) {
      S.findings.network.push(f);
      document.getElementById('ssh-findings-area').style.display = '';
      const tbody = document.getElementById('network-findings-tbody');
      const tr = document.createElement('tr');
      tr.dataset.sev = f.severity; tr.onclick = () => openDrawer(f, ip);
      tr.innerHTML = `
        <td style="font-family:monospace;font-size:.78rem;color:var(--blue)">${esc(ip)}</td>
        <td>${_sevBadge(f.severity)}</td><td>${esc(f.title)}</td>
        <td style="font-size:.78rem;color:var(--text2)">${esc((f.remediation||'').substring(0,60))}</td>
        <td>${f.auto_fix?`<button class="fix-btn remote" onclick="event.stopPropagation();applyFixRemote('${esc(f.id)}','${esc(ip)}',this)">⚡ Fix</button>`:''}</td>`;
      tbody.appendChild(tr);
    },
  });
}

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
    const typeLabels = {audit:'🔍 Seguridad', malware:'🦠 Malware', network:'📡 Red', code:'📝 Código', ssh:'🖥️ SSH'};
    tbody.innerHTML = data.map(s => `
      <tr onclick="loadHistoryDetail(${s.id},this)" style="cursor:pointer">
        <td style="white-space:nowrap">${fmt(s.started_at)}</td>
        <td>${typeLabels[s.scan_type]||s.scan_type}</td>
        <td style="font-size:.82rem;color:var(--text2)">${esc(s.target||'localhost')}</td>
        <td>${_scorePill(s.score)}</td>
        <td>${_findingBar(s)}</td>
        <td style="color:var(--text2);font-size:.82rem">${dur(s.duration_s)}</td>
        <td><span style="font-size:.75rem;color:var(--text2)">${s.triggered_by==='scheduler'?'🕐 Auto':'👤 Manual'}</span></td>
        <td>
          ${s.status==='completed'?`<button class="fix-btn" onclick="event.stopPropagation();loadHistoryDetail(${s.id})">Ver</button>`:''}
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
      <span class="comp-new">▲ ${comparison.new.length} nuevos</span>
      <span class="comp-resolved">▼ ${comparison.resolved.length} resueltos</span>
      <span class="comp-same">= ${comparison.unchanged} sin cambio</span>`;
  }
  // Tabla de findings
  const tbody = document.getElementById('hist-detail-tbody');
  tbody.innerHTML = findings.map(f => `
    <tr data-sev="${esc(f.severity)}" onclick="openDrawerFromData(${JSON.stringify(f).replace(/"/g,'&quot;')})">
      <td>${_sevBadge(f.severity)}</td>
      <td style="font-size:.78rem;color:var(--text2)">${esc(f.category)}</td>
      <td>${esc(f.title)}</td>
      <td>${f.fixed_at ? `<span class="fixed-badge">✓ Corregido</span>` : ''}</td>
    </tr>`).join('');
  document.getElementById('history-detail').scrollIntoView({behavior:'smooth'});
}

function closeHistoryDetail() {
  document.getElementById('history-detail').style.display = 'none';
}

// ── Fix local / remoto ────────────────────────────────────────────────────
async function applyFix(findingId, btnEl) {
  if (btnEl) { btnEl.disabled = true; btnEl.textContent = '⏳'; }
  try {
    const r = await fetch('/api/fix/local', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({finding_id: findingId}),
    });
    const d = await r.json();
    if (d.ok) {
      appendLog('ok', `✓ Corregido: ${findingId}`);
      toast('✓ Corrección aplicada');
      if (btnEl) { btnEl.textContent = '✓ Listo'; btnEl.style.background = 'var(--green)'; }
    } else {
      toast('Error: ' + d.error, 'error');
      if (btnEl) { btnEl.disabled = false; btnEl.textContent = '⚡ Corregir'; }
    }
  } catch(e) {
    toast('Error: ' + e, 'error');
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = '⚡ Corregir'; }
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
  if (btnEl) { btnEl.disabled = true; btnEl.textContent = '⏳'; }
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
      if (btnEl) { btnEl.textContent = '✓'; btnEl.style.background = 'var(--green)'; }
    } else {
      toast('Error: ' + d.error, 'error');
      if (btnEl) { btnEl.disabled = false; btnEl.textContent = '⚡ Fix'; }
    }
  } catch(e) {
    toast('Error: ' + e, 'error');
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = '⚡ Fix'; }
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
    ${f.auto_fix && !hostLabel && !f.fixed_at ? `<button class="d-fix-btn" onclick="applyFix('${esc(f.id||f.finding_id||'')}',this)">⚡ Aplicar corrección</button>` : ''}
    ${f.auto_fix && hostLabel && !f.fixed_at ? `<button class="d-fix-btn remote" onclick="applyFixRemote('${esc(f.id||'')}','${esc(hostLabel)}',this)">⚡ Corregir en ${esc(hostLabel)}</button>` : ''}
    ${!f.auto_fix ? `<div style="margin-top:10px;padding:10px;background:var(--bg3);border-radius:6px;font-size:.82rem;color:var(--text2)">ℹ️ Esta corrección requiere revisión manual.</div>` : ''}
    <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn-secondary small" onclick="suppressFinding('${esc(f.id||f.finding_id||'')}')">🔕 Suprimir (falso positivo)</button>
    </div>`;
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

// ── Scheduler ─────────────────────────────────────────────────────────────
async function loadScheduler() {
  try {
    const data = await fetch('/api/scheduler').then(r => r.json());
    const container = document.getElementById('scheduler-list');
    if (!container) return;
    const names = {daily_audit:'🔍 Audit de seguridad diario', weekly_malware:'🦠 Malware scan semanal', daily_network:'📡 Network scan diario'};
    container.innerHTML = data.map(e => `
      <div class="sched-card">
        <div class="sched-info">
          <div class="sched-name">${names[e.name]||e.name}</div>
          <div class="sched-meta">
            ${e.enabled ? '🟢 Activo' : '⭕ Desactivado'} ·
            ${e.hour.toString().padStart(2,'0')}:${e.minute.toString().padStart(2,'0')} ·
            Último: ${fmt(e.last_run)} · Próximo: ${fmt(e.next_run)}
          </div>
        </div>
        <div class="sched-actions">
          <button class="toggle-btn ${e.enabled?'active':''}"
            onclick="toggleScheduler('${esc(e.name)}',${!e.enabled},this)">
            ${e.enabled ? 'Desactivar' : 'Activar'}
          </button>
          <button class="fix-btn" onclick="runSchedulerNow('${esc(e.name)}',this)">▶ Ejecutar ahora</button>
        </div>
      </div>`).join('') || '<p style="color:var(--text2)">Scheduler no activo</p>';
  } catch(e) { console.error('loadScheduler:', e); }
}

async function toggleScheduler(name, enabled, btnEl) {
  const r = await fetch(`/api/scheduler/${encodeURIComponent(name)}/toggle`, {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({enabled}),
  });
  const d = await r.json();
  if (d.ok) { loadScheduler(); toast(enabled ? '✓ Activado' : '✓ Desactivado'); }
  else toast('Error: ' + d.error, 'error');
}

async function runSchedulerNow(name, btnEl) {
  if (btnEl) { btnEl.disabled = true; btnEl.textContent = '⏳'; }
  const r = await fetch(`/api/scheduler/${encodeURIComponent(name)}/run`, {method: 'POST'});
  const d = await r.json();
  if (d.ok) { toast('✓ Tarea ejecutada'); loadScheduler(); }
  else toast('Error: ' + d.error, 'error');
  if (btnEl) { btnEl.disabled = false; btnEl.textContent = '▶ Ejecutar ahora'; }
}

// ── Usuarios ──────────────────────────────────────────────────────────────
async function loadUsers() {
  try {
    const users = await fetch('/api/users').then(r => r.json());
    const tbody = document.getElementById('users-tbody');
    if (!tbody) return;
    const roleColors = {admin:'var(--red)', operator:'var(--blue)', viewer:'var(--text2)'};
    tbody.innerHTML = users.map(u => `
      <tr>
        <td><b>${esc(u.username)}</b></td>
        <td><span style="color:${roleColors[u.role]||'var(--text2)'};font-weight:600">${esc(u.role)}</span></td>
        <td style="color:var(--text2);font-size:.82rem">${fmt(u.last_login)}</td>
        <td>${u.active ? '<span style="color:var(--green)">Activo</span>' : '<span style="color:var(--text2)">Desactivado</span>'}</td>
        <td style="display:flex;gap:6px">
          <select onchange="changeUserRole('${esc(u.username)}',this.value)" style="background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:3px 6px;border-radius:4px;font-size:.78rem">
            <option value="admin" ${u.role==='admin'?'selected':''}>admin</option>
            <option value="operator" ${u.role==='operator'?'selected':''}>operator</option>
            <option value="viewer" ${u.role==='viewer'?'selected':''}>viewer</option>
          </select>
          <button class="btn-secondary small" onclick="deleteUser('${esc(u.username)}')">🗑</button>
        </td>
      </tr>`).join('');
  } catch(e) { console.error('loadUsers:', e); }
}

function showCreateUser() {
  document.getElementById('create-user-form').style.display = '';
  document.getElementById('new-username').focus();
}

async function createUser() {
  const username = document.getElementById('new-username')?.value.trim();
  const password = document.getElementById('new-password')?.value;
  const role     = document.getElementById('new-role')?.value;
  const msg      = document.getElementById('user-create-msg');
  if (!username || !password) { if(msg) msg.textContent = '❌ Rellena todos los campos'; return; }
  const r = await fetch('/api/users', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({username, password, role}),
  });
  const d = await r.json();
  if (d.ok) {
    if (msg) { msg.textContent = '✓ Usuario creado'; msg.style.color = 'var(--green)'; }
    setTimeout(() => { document.getElementById('create-user-form').style.display = 'none'; loadUsers(); }, 1000);
  } else {
    if (msg) { msg.textContent = '❌ ' + d.error; msg.style.color = 'var(--red)'; }
  }
}

async function changeUserRole(username, role) {
  const r = await fetch(`/api/users/${encodeURIComponent(username)}`, {
    method: 'PATCH', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({role}),
  });
  const d = await r.json();
  if (d.ok) toast(`✓ Rol de ${username} cambiado a ${role}`);
  else toast('Error: ' + d.error, 'error');
}

async function deleteUser(username) {
  if (!confirm(`¿Desactivar usuario "${username}"?`)) return;
  const r = await fetch(`/api/users/${encodeURIComponent(username)}`, {method: 'DELETE'});
  const d = await r.json();
  if (d.ok) { toast(`✓ Usuario ${username} desactivado`); loadUsers(); }
  else toast('Error: ' + d.error, 'error');
}

// ── Supresiones ───────────────────────────────────────────────────────────
async function loadSuppresions() {
  try {
    const data = await fetch('/api/suppressions').then(r => r.json());
    const tbody = document.getElementById('suppressions-tbody');
    const empty = document.getElementById('suppressions-empty');
    if (!tbody) return;
    if (!data.length) { tbody.innerHTML = ''; empty.style.display = ''; return; }
    empty.style.display = 'none';
    tbody.innerHTML = data.map(s => `
      <tr>
        <td><code style="font-size:.82rem">${esc(s.finding_id_pattern)}</code></td>
        <td style="font-size:.82rem">${esc(s.reason)}</td>
        <td style="font-size:.78rem;color:var(--text2)">${esc(s.created_by)}</td>
        <td style="font-size:.78rem;color:var(--text2)">${s.expires_at ? fmt(s.expires_at) : 'Permanente'}</td>
        <td><button class="btn-secondary small" onclick="removeSuppression('${esc(s.finding_id_pattern)}')">🗑 Eliminar</button></td>
      </tr>`).join('');
  } catch(e) { console.error('loadSuppresions:', e); }
}

async function addSuppression() {
  const pattern = document.getElementById('supp-pattern')?.value.trim();
  const reason  = document.getElementById('supp-reason')?.value.trim();
  const expires = document.getElementById('supp-expires')?.value;
  if (!pattern || !reason) { toast('Rellena patrón y motivo', 'error'); return; }
  const r = await fetch('/api/suppressions', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({pattern, reason, expires_at: expires || null}),
  });
  const d = await r.json();
  if (d.ok) { toast('✓ Supresión añadida'); loadSuppresions();
    document.getElementById('supp-pattern').value = '';
    document.getElementById('supp-reason').value = '';
  } else toast('Error: ' + d.error, 'error');
}

async function removeSuppression(pattern) {
  if (!confirm(`¿Eliminar supresión "${pattern}"?`)) return;
  const r = await fetch(`/api/suppressions/${encodeURIComponent(pattern)}`, {method: 'DELETE'});
  const d = await r.json();
  if (d.ok) { toast('✓ Supresión eliminada'); loadSuppresions(); }
  else toast('Error: ' + d.error, 'error');
}

// ── API Keys ──────────────────────────────────────────────────────────────
async function loadKeys() {
  try {
    const d = await fetch('/api/config/keys').then(r => r.json());
    const map = {shodan:'key-shodan', virustotal:'key-vt', abuseipdb:'key-abuse', greynoise:'key-grey', hibp:'key-hibp'};
    Object.entries(map).forEach(([k,id]) => {
      const el = document.getElementById(id);
      if (el && d[k]) el.value = d[k];
    });
  } catch(e) {}
}

async function saveKeys() {
  const body = {
    shodan:     document.getElementById('key-shodan')?.value,
    virustotal: document.getElementById('key-vt')?.value,
    abuseipdb:  document.getElementById('key-abuse')?.value,
    greynoise:  document.getElementById('key-grey')?.value,
    hibp:       document.getElementById('key-hibp')?.value,
  };
  const r = await fetch('/api/config/keys', {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body),
  });
  const d = await r.json();
  const msg = document.getElementById('keys-msg');
  if (msg) { msg.textContent = d.ok ? '✓ Guardado' : '✗ ' + d.error; msg.style.color = d.ok ? 'var(--green)' : 'var(--red)'; }
  toast(d.ok ? '✓ API keys guardadas' : '✗ Error', d.ok ? 'info' : 'error');
}

// ── Notificaciones ────────────────────────────────────────────────────────
async function loadNotifications() {
  try {
    const d = await fetch('/api/config/notifications').then(r => r.json());
    document.getElementById('notif-email-enabled')?.removeAttribute('checked');
    if (d.email_enabled) document.getElementById('notif-email-enabled').checked = true;
    if (d.smtp_host)     document.getElementById('notif-smtp-host').value = d.smtp_host;
    if (d.smtp_port)     document.getElementById('notif-smtp-port').value = d.smtp_port;
    if (d.smtp_user)     document.getElementById('notif-smtp-user').value = d.smtp_user;
    if (d.email_from)    document.getElementById('notif-email-from').value = d.email_from;
    if (d.email_to)      document.getElementById('notif-email-to').value = Array.isArray(d.email_to) ? d.email_to.join(', ') : d.email_to;
    if (d.webhook_enabled) document.getElementById('notif-webhook-enabled').checked = true;
    if (d.webhook_url)   document.getElementById('notif-webhook-url').value = d.webhook_url;
    if (d.min_level)     document.getElementById('notif-min-level').value = d.min_level;
    toggleNotifEmail();
  } catch(e) {}
}

function toggleNotifEmail() {
  const enabled = document.getElementById('notif-email-enabled')?.checked;
  const fields = document.getElementById('notif-email-fields');
  if (fields) fields.style.opacity = enabled ? '1' : '.4';
}

async function saveNotifications() {
  const emailTo = document.getElementById('notif-email-to')?.value
    .split(',').map(s => s.trim()).filter(Boolean) || [];
  const body = {
    email_enabled:   document.getElementById('notif-email-enabled')?.checked || false,
    smtp_host:       document.getElementById('notif-smtp-host')?.value,
    smtp_port:       parseInt(document.getElementById('notif-smtp-port')?.value) || 587,
    smtp_user:       document.getElementById('notif-smtp-user')?.value,
    smtp_password:   document.getElementById('notif-smtp-pass')?.value,
    email_from:      document.getElementById('notif-email-from')?.value,
    email_to:        emailTo,
    webhook_enabled: document.getElementById('notif-webhook-enabled')?.checked || false,
    webhook_url:     document.getElementById('notif-webhook-url')?.value,
    min_level:       document.getElementById('notif-min-level')?.value,
  };
  const r = await fetch('/api/config/notifications', {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body),
  });
  const d = await r.json();
  const msg = document.getElementById('notif-msg');
  if (msg) { msg.textContent = d.ok ? '✓ Guardado' : '✗ ' + d.error; msg.style.color = d.ok ? 'var(--green)' : 'var(--red)'; }
  toast(d.ok ? '✓ Notificaciones guardadas' : '✗ Error', d.ok ? 'info' : 'error');
}

async function testNotifications() {
  const r = await fetch('/api/config/notifications/test', {method: 'POST'});
  const d = await r.json();
  const msg = document.getElementById('notif-msg');
  if (msg) {
    const results = Object.entries(d).map(([k,v]) => `${k}: ${v?'✓':'✗'}`).join(', ');
    msg.textContent = results || 'Sin canales configurados';
    msg.style.color = Object.values(d).every(v=>v) ? 'var(--green)' : 'var(--red)';
  }
}

// ── Exportar / Informes ───────────────────────────────────────────────────
function exportJSON(scope) {
  const data = S.findings[scope];
  if (!data?.length) { toast('Sin datos para exportar'); return; }
  const blob = new Blob([JSON.stringify(data, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `cyberhound_${scope}_${new Date().toISOString().slice(0,10)}.json`;
  a.click();
}

function downloadReport(fmt, scope) {
  const findings = S.findings[scope];
  if (!findings?.length) { toast(`Ejecuta primero el análisis de ${scope}`, 'error'); return; }
  fetch(`/api/report/${fmt}`, {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({findings, source: scope}),
  }).then(r => r.blob()).then(blob => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `cyberhound_${scope}_${new Date().toISOString().slice(0,10)}.${fmt==='ansible'?'yml':fmt}`;
    a.click();
  }).catch(e => toast('Error: ' + e, 'error'));
}

function downloadLog() {
  if (!S.logLines.length) { toast('Sin log'); return; }
  const blob = new Blob([S.logLines.join('\n')], {type:'text/plain'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `cyberhound_log_${new Date().toISOString().slice(0,16).replace(':','-')}.txt`;
  a.click();
}

// ── Summary bar ───────────────────────────────────────────────────────────
function _renderSummary(containerId, findings) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const counts = {};
  findings.forEach(f => { counts[f.severity] = (counts[f.severity]||0) + 1; });
  const order = ['critical','high','medium','low','info'];
  const labels = {critical:'Críticos',high:'Altos',medium:'Medios',low:'Bajos',info:'Info'};
  let html = '<div class="summary-bar">';
  order.forEach(s => {
    if (counts[s]) html += `<span class="sum-chip ${s}">${counts[s]} ${labels[s]}</span>`;
  });
  if (!findings.length) html += '<span class="sum-chip ok">✓ Sin problemas detectados</span>';
  html += '</div>';
  el.innerHTML = html;
}

// ── Severity badge ────────────────────────────────────────────────────────
function sevBadge(sev) {
  const labels = {critical:'CRÍTICO', high:'ALTO', medium:'MEDIO', low:'BAJO', info:'INFO'};
  return `<span class="sev sev-${esc(sev)}">${labels[sev]||esc((sev||'').toUpperCase())}</span>`;
}

const _sevBadge = sevBadge; // alias para compatibilidad

// ── Init ──────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  setStatus('idle', 'Listo');
  appendLog('info', 'CyberHound Pro v6.1 iniciado.');
  loadDashboard();
  loadKeys();
  // Actualizar dashboard cada 5 minutos
  setInterval(loadDashboard, 5 * 60 * 1000);
});

// ── Docker ────────────────────────────────────────────────────────────────────
function quickDocker() { showPanel('docker'); runDocker(); }



function renderDockerChips(findings) {
  const summary = document.getElementById('docker-summary');
  const chips   = document.getElementById('docker-chips');
  summary.style.display = '';
  const cats = {};
  findings.forEach(f => {
    const k = f.category.replace('docker/','');
    cats[k] = (cats[k]||0)+1;
  });
  chips.innerHTML = Object.entries(cats).map(([k,n]) =>
    `<span class="host-chip" style="border-color:var(--yellow);color:var(--yellow)">
       🐳 ${esc(k)}: ${n}
     </span>`
  ).join('');
}

// ── SIEM config ───────────────────────────────────────────────────────────────
async function loadSIEM() {
  const r = await fetch('/api/config/siem');
  const d = await r.json();
  document.getElementById('siem-wazuh-enabled').checked = d.wazuh_enabled;
  document.getElementById('siem-wazuh-host').value      = d.wazuh_host || 'localhost';
  document.getElementById('siem-wazuh-port').value      = d.wazuh_port || 1514;
  document.getElementById('siem-wazuh-api').value       = d.wazuh_api_url || '';
  document.getElementById('siem-elk-enabled').checked   = d.elk_enabled;
  document.getElementById('siem-elk-url').value         = d.elk_url || 'http://localhost:9200';
  document.getElementById('siem-elk-index').value       = d.elk_index || 'cyberhound-findings';
  document.getElementById('siem-splunk-enabled').checked= d.splunk_enabled;
  document.getElementById('siem-splunk-url').value      = d.splunk_hec_url || '';
  document.getElementById('siem-splunk-index').value    = d.splunk_index || 'cyberhound';
  document.getElementById('siem-min-severity').value    = d.min_severity || 'medium';
}

async function saveSIEM() {
  const body = {
    wazuh_enabled:    document.getElementById('siem-wazuh-enabled').checked,
    wazuh_host:       document.getElementById('siem-wazuh-host').value,
    wazuh_port:       parseInt(document.getElementById('siem-wazuh-port').value)||1514,
    wazuh_api_url:    document.getElementById('siem-wazuh-api').value,
    elk_enabled:      document.getElementById('siem-elk-enabled').checked,
    elk_url:          document.getElementById('siem-elk-url').value,
    elk_index:        document.getElementById('siem-elk-index').value,
    elk_api_key:      document.getElementById('siem-elk-key').value,
    splunk_enabled:   document.getElementById('siem-splunk-enabled').checked,
    splunk_hec_url:   document.getElementById('siem-splunk-url').value,
    splunk_hec_token: document.getElementById('siem-splunk-token').value,
    splunk_index:     document.getElementById('siem-splunk-index').value,
    min_severity:     document.getElementById('siem-min-severity').value,
  };
  const r = await fetch('/api/config/siem', {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)
  });
  const d = await r.json();
  const msg = document.getElementById('siem-msg');
  msg.textContent  = d.ok ? '✓ Configuración SIEM guardada' : '✗ Error: ' + d.error;
  msg.style.color  = d.ok ? 'var(--green)' : 'var(--red)';
  toast(d.ok ? '✓ SIEM guardado' : '✗ Error: ' + d.error);
}

async function testSIEM() {
  const msg = document.getElementById('siem-msg');
  msg.textContent = '⏳ Probando conexión…';
  msg.style.color = 'var(--text2)';
  const r = await fetch('/api/config/siem/test', { method: 'POST' });
  const d = await r.json();
  const results = Object.entries(d).map(([k,ok]) =>
    `${ok ? '✓' : '✗'} ${k}`
  ).join(' · ');
  msg.textContent = results || 'Sin SIEMs configurados';
  msg.style.color = Object.values(d).every(v=>v) ? 'var(--green)' : 'var(--yellow)';
}

// ── Scoring breakdown en dashboard ────────────────────────────────────────────
async function loadScoreBreakdown() {
  try {
    const r = await fetch('/api/score/detail');
    if (!r.ok) return;
    const d = await r.json();
    const card = document.getElementById('score-breakdown-card');
    const list = document.getElementById('score-breakdown-list');
    const exp  = document.getElementById('score-exposure');
    if (!card || !list) return;
    card.style.display = '';

    // Grade
    const gradeEl = document.getElementById('score-grade');
    if (gradeEl) {
      const gradeColors = {A:'var(--green)',B:'var(--green)',C:'var(--yellow)',D:'var(--orange)',F:'var(--red)'};
      gradeEl.innerHTML = `<span style="font-weight:700;color:${gradeColors[d.grade]||'var(--text2)'}">
        Grado ${d.grade}</span> — ${esc(d.grade_label)}`;
    }

    // Top 5 penalizaciones
    const top5 = (d.breakdown_top10 || []).slice(0,5);
    list.innerHTML = top5.length
      ? '<div style="margin-bottom:6px;color:var(--text2);font-size:.72rem;font-weight:600">TOP PENALIZACIONES</div>' +
        top5.map(b => `
          <div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid var(--border)">
            <span style="font-size:.78rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px" title="${esc(b.finding_id)}">${esc(b.finding_id.substring(0,35))}</span>
            <span style="font-size:.75rem;font-weight:600;color:${b.final_penalty>15?'var(--red)':b.final_penalty>8?'var(--orange)':'var(--yellow)'};flex-shrink:0;margin-left:8px">-${b.final_penalty.toFixed(1)}pts</span>
          </div>`).join('')
      : '<p style="color:var(--text2);font-size:.8rem">Sin hallazgos significativos</p>';

    // Contexto de exposición
    if (exp) {
      const mult = d.exposure_multiplier || 1.0;
      exp.innerHTML = mult > 1.1
        ? `⚠ Factor exposición: <b style="color:var(--orange)">×${mult.toFixed(1)}</b> ${d.internet_facing ? '(expuesto a internet)' : ''}`
        : `✓ Factor exposición normal (×${mult.toFixed(1)})`;
    }
  } catch(e) {
    // Sin datos todavía — silencioso
  }
}

// ── Gráfico de tendencia SVG ──────────────────────────────────────────────────
function renderTrendChart(containerId, data) {
  const el = document.getElementById(containerId);
  if (!el || !data.length) return;

  const W = el.offsetWidth || 600;
  const H = 60;
  const PAD = { l:30, r:10, t:8, b:18 };
  const chartW = W - PAD.l - PAD.r;
  const chartH = H - PAD.t - PAD.b;

  const scores = data.map(d => d.score ?? d.avg_score ?? 0).filter(s => s != null);
  if (!scores.length) return;

  const minS = Math.max(0,  Math.min(...scores) - 5);
  const maxS = Math.min(100, Math.max(...scores) + 5);
  const range = maxS - minS || 1;

  const toX = i => PAD.l + (i / (scores.length - 1 || 1)) * chartW;
  const toY = s => PAD.t + chartH - ((s - minS) / range) * chartH;

  // Línea del gráfico
  const points = scores.map((s, i) => `${toX(i)},${toY(s)}`).join(' ');
  // Área bajo la curva
  const area = `${toX(0)},${toY(minS)} ${points} ${toX(scores.length-1)},${toY(minS)}`;

  // Color basado en último score
  const lastScore = scores[scores.length - 1];
  const lineColor = lastScore >= 75 ? '#3fb950' : lastScore >= 50 ? '#d29922' : '#f85149';

  el.innerHTML = `
    <svg width="100%" height="${H}" viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg">
      <!-- Grid lines -->
      ${[0,50,100].map(s => {
        const y = toY(s < minS ? minS : s > maxS ? maxS : s);
        return `<line x1="${PAD.l}" y1="${y}" x2="${W-PAD.r}" y2="${y}"
                  stroke="var(--border)" stroke-width="1" stroke-dasharray="3,3"/>
                <text x="${PAD.l-4}" y="${y+4}" fill="var(--text2)" font-size="9" text-anchor="end">${s}</text>`;
      }).join('')}
      <!-- Area -->
      <polygon points="${area}" fill="${lineColor}" fill-opacity="0.12"/>
      <!-- Line -->
      <polyline points="${points}" fill="none" stroke="${lineColor}" stroke-width="2" stroke-linejoin="round"/>
      <!-- Dots -->
      ${scores.map((s, i) => `
        <circle cx="${toX(i)}" cy="${toY(s)}" r="3" fill="${lineColor}"/>
      `).join('')}
      <!-- Último valor -->
      <text x="${toX(scores.length-1)}" y="${toY(lastScore)-7}" fill="${lineColor}"
            font-size="10" text-anchor="middle" font-weight="bold">${lastScore}</text>
      <!-- Fechas (primera y última) -->
      ${data.length > 0 ? `
        <text x="${PAD.l}" y="${H}" fill="var(--text2)" font-size="8">${(data[0].day||data[0].started_at||'').substring(5,10)}</text>
        <text x="${W-PAD.r}" y="${H}" fill="var(--text2)" font-size="8" text-anchor="end">${(data[data.length-1].day||data[data.length-1].started_at||'').substring(5,10)}</text>
      ` : ''}
    </svg>`;
}



// ══════════════════════════════════════════════════════════════════════════════
// PANEL DE ACTIVIDAD EN TIEMPO REAL + ESCANEOS PARALELOS
// ══════════════════════════════════════════════════════════════════════════════

// Estado de escaneos paralelos
const SCANS = {};  // { scanId: { type, count, crits, highs, startTime, ws } }

function toggleActivityPanel() {
  document.body.classList.toggle('activity-open');
  document.getElementById('activity-panel').classList.toggle('open');
}

function clearActivity() {
  document.getElementById('activity-feed').innerHTML =
    '<div style="padding:20px;text-align:center;color:var(--text2);font-size:.82rem">Sin actividad reciente.</div>';
}

// ── Añadir item al feed de actividad ──────────────────────────────────────────
function addActivityItem(type, icon, title, desc, severity = 'info') {
  const feed = document.getElementById('activity-feed');
  if (!feed) return;

  // Quitar placeholder si es el primero
  const placeholder = feed.querySelector('div[style*="text-align:center"]');
  if (placeholder) placeholder.remove();

  const time = new Date().toLocaleTimeString('es', {hour:'2-digit', minute:'2-digit', second:'2-digit'});
  const item = document.createElement('div');
  item.className = `activity-item ${severity}`;
  item.innerHTML = `
    <span class="ai-icon">${icon}</span>
    <div class="ai-body">
      <div class="ai-title">${esc(title)}</div>
      ${desc ? `<div class="ai-desc">${esc(desc)}</div>` : ''}
    </div>
    <span class="ai-time">${time}</span>`;
  feed.insertBefore(item, feed.firstChild);

  // Abrir el panel automáticamente si hay hallazgo crítico
  if (severity === 'critical' || severity === 'high') {
    document.getElementById('activity-panel')?.classList.add('open');
    document.body.classList.add('activity-open');
  }

  // Limitar a 100 items
  while (feed.children.length > 100) {
    feed.removeChild(feed.lastChild);
  }
}

// ── Barra de progreso de un scan ──────────────────────────────────────────────
function createScanProgress(scanKey, title, icon) {
  const container = document.getElementById('parallel-scans');
  if (!container) return;
  const el = document.createElement('div');
  el.className = 'scan-progress';
  el.id = `progress-${scanKey}`;
  el.innerHTML = `
    <div class="scan-progress-header">
      <span class="scan-progress-title">${icon} ${esc(title)}</span>
      <span class="scan-progress-count" id="prog-count-${scanKey}">Iniciando…</span>
    </div>
    <div class="scan-progress-bar">
      <div class="scan-progress-bar-fill" id="prog-bar-${scanKey}" style="width:5%"></div>
    </div>
    <div class="scan-progress-details" id="prog-details-${scanKey}">
      <span class="scan-stat">Analizando…</span>
    </div>`;
  container.appendChild(el);
  // Abrir el panel
  document.getElementById('activity-panel')?.classList.add('open');
  document.body.classList.add('activity-open');
}

function updateScanProgress(scanKey, count, crits, highs, mediums, detail = '') {
  const countEl   = document.getElementById(`prog-count-${scanKey}`);
  const barEl     = document.getElementById(`prog-bar-${scanKey}`);
  const detailsEl = document.getElementById(`prog-details-${scanKey}`);
  if (!countEl) return;

  countEl.textContent = `${count} hallazgos`;

  // Animar barra — sin saber el total, usamos logaritmo
  const pct = Math.min(95, 5 + Math.log(count + 1) * 15);
  if (barEl) barEl.style.width = pct + '%';

  if (detailsEl) {
    const stats = [
      crits   > 0 ? `<span class="scan-stat has-value" style="color:var(--critical)">🔴 ${crits} críticos</span>` : '',
      highs   > 0 ? `<span class="scan-stat has-value" style="color:var(--high)">🟠 ${highs} altos</span>` : '',
      mediums > 0 ? `<span class="scan-stat has-value">🟡 ${mediums} medios</span>` : '',
      detail  ? `<span class="scan-stat">${esc(detail.substring(0,40))}</span>` : '',
    ].filter(Boolean).join('');
    detailsEl.innerHTML = stats || '<span class="scan-stat">Sin hallazgos por ahora…</span>';
  }
}

function completeScanProgress(scanKey, count, score) {
  const el = document.getElementById(`progress-${scanKey}`);
  if (!el) return;
  const scoreStr = score != null ? ` · Score: ${score}/100` : '';
  el.style.opacity = '0.6';
  const bar = document.getElementById(`prog-bar-${scanKey}`);
  if (bar) { bar.style.width = '100%'; bar.style.background = 'var(--green)'; bar.style.animation = 'none'; }
  const countEl = document.getElementById(`prog-count-${scanKey}`);
  if (countEl) countEl.textContent = `✓ ${count} hallazgos${scoreStr}`;
  // Quitar a los 10 segundos
  setTimeout(() => el.remove(), 10000);
}

// ── Versión mejorada de wsRun que alimenta el panel de actividad ──────────────
function wsRunWithActivity(task, params, handlers = {}, scanLabel = '', scanIcon = '🔍') {
  const scanKey = task + '_' + Date.now();
  createScanProgress(scanKey, scanLabel || task, scanIcon);

  const counts = { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
  let lastDetail = '';

  const wrappedHandlers = {
    ...handlers,
    onFinding(f) {
      counts.total++;
      if (f.severity in counts) counts[f.severity]++;

      // Añadir al feed de actividad
      const sevIcon = {critical:'🔴', high:'🟠', medium:'🟡', low:'🔵', info:'⚪'}[f.severity] || '⚪';
      lastDetail = f.title;
      addActivityItem(task, sevIcon, f.title,
        (f.source_host ? `${f.source_host} · ` : '') + (f.category || ''),
        f.severity);

      // Actualizar barra de progreso
      updateScanProgress(scanKey, counts.total,
        counts.critical, counts.high, counts.medium, f.title);

      // Llamar handler original
      if (handlers.onFinding) handlers.onFinding(f);
    },
    onLog(level, text) {
      // Mostrar mensajes de sección/fase en el feed de actividad
      if (level === 'section' || level === 'ok') {
        const icon = level === 'ok' ? '✓' : '📋';
        addActivityItem(task, icon === '✓' ? '✅' : '🔄', text, '', 'info');
      }
      if (handlers.onLog) handlers.onLog(level, text);
    },
    onDone(msg) {
      completeScanProgress(scanKey, counts.total, msg.score);
      const scoreStr = msg.score != null ? ` (score: ${msg.score}/100)` : '';
      addActivityItem(task, '✅',
        `${scanLabel || task} completado${scoreStr}`,
        `${counts.critical} críticos · ${counts.high} altos · ${counts.medium} medios`,
        counts.critical > 0 ? 'critical' : counts.high > 0 ? 'high' : 'ok');
      if (handlers.onDone) handlers.onDone(msg);
    },
    onDevices(devices) {
      addActivityItem('network', '📡',
        `${devices.length} dispositivos encontrados en la red`, '', 'info');
      updateScanProgress(scanKey, devices.length, 0, 0, 0, `${devices.length} dispositivos`);
      if (handlers.onDevices) handlers.onDevices(devices);
    },
    onHostResult(hr) {
      const icon = hr.status === 'ok' ? '✅' : '❌';
      addActivityItem('ssh', icon,
        `${hr.host}: ${hr.status === 'ok' ? hr.count + ' hallazgos' : hr.error || hr.status}`,
        hr.os_info || '', hr.status === 'ok' ? (hr.count > 0 ? 'high' : 'ok') : 'medium');
      if (handlers.onHostResult) handlers.onHostResult(hr);
    },
    onError(e) {
      completeScanProgress(scanKey, counts.total, null);
      addActivityItem(task, '❌', `Error en ${scanLabel || task}`, e.text, 'critical');
      if (handlers.onError) handlers.onError(e);
    },
  };

  // Interceptar los mensajes de log del WS antes de appendLog
  const origLog = window._wsLogHandler;
  wsRun(task, params, wrappedHandlers);
}

// ── Sobrescribir runAudit, runMalware, runNetworkScan, runDocker para usar wsRunWithActivity ──

function runAudit() {
  S.findings.audit = [];
  document.getElementById('audit-results').style.display = 'none';
  document.getElementById('audit-empty').style.display = '';
  document.getElementById('audit-tbody').innerHTML = '';
  btn('btn-audit', true, '⏳ Analizando…');
  appendLog('section', '═══ ANÁLISIS DE SEGURIDAD ═══');

  wsRunWithActivity('audit', {}, {
    onFinding(f) {
      S.findings.audit.push(f);
      appendAuditRow(f);
    },
    onDone(msg) {
      btn('btn-audit', false, '▶ Iniciar análisis completo');
      document.getElementById('audit-results').style.display = '';
      document.getElementById('audit-empty').style.display = 'none';
      renderSummary('audit-summary-bar', S.findings.audit);
      const fixable = S.findings.audit.filter(f => f.auto_fix);
      if (fixable.length) {
        const el = document.getElementById('btn-fix-all');
        if (el) { el.textContent = `⚡ Corregir ${fixable.length} automáticamente`; el.style.display = ''; }
      }
      loadDashboard();
      if (document.getElementById('audit-fix-all')?.checked) fixAll('audit');
    },
  }, 'Análisis de seguridad', '🔍');
}

function runMalware() {
  S.findings.malware = [];
  document.getElementById('malware-results').style.display = 'none';
  document.getElementById('malware-empty').style.display = '';
  document.getElementById('malware-tbody').innerHTML = '';
  btn('btn-malware', true, '⏳ Escaneando…');
  appendLog('section', '═══ MALWARE SCAN ═══');

  const skip = [];
  if (!document.getElementById('m-yara')?.checked)     skip.push('yara');
  if (!document.getElementById('m-hash')?.checked)     skip.push('hash');
  if (!document.getElementById('m-auditd')?.checked)   skip.push('auditd');
  if (!document.getElementById('m-cron')?.checked)     skip.push('cron');
  if (!document.getElementById('m-webshell')?.checked) skip.push('webshell');

  wsRunWithActivity('malware', {
    skip,
    yara_rules: document.getElementById('yara-rules')?.value || null,
    web_roots:  (document.getElementById('web-roots')?.value || '').split(/\s+/).filter(Boolean) || null,
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
      loadDashboard();
    },
  }, 'Malware scan', '🦠');
}

function runDocker() {
  S.findings.docker = [];
  document.getElementById('docker-results').style.display = 'none';
  document.getElementById('docker-empty').style.display = '';
  document.getElementById('docker-tbody').innerHTML = '';
  document.getElementById('docker-summary').style.display = 'none';
  btn('btn-docker', true, '⏳ Analizando…');
  appendLog('section', '═══ DOCKER / KUBERNETES SCAN ═══');

  wsRunWithActivity('docker', {
    scan_images_cve: document.getElementById('docker-scan-cve')?.checked ?? true,
    scan_k8s:        document.getElementById('docker-scan-k8s')?.checked ?? true,
  }, {
    onFinding(f) {
      const finding = { ...f, id: f.id || f.finding_id };
      S.findings.docker.push(finding);
      const tbody = document.getElementById('docker-tbody');
      const tr = document.createElement('tr');
      tr.dataset.sev = finding.severity;
      tr.onclick = () => openDrawer(finding);
      const catIcons = {
        'docker/privilege':'🔐','docker/escape':'🚨','docker/secrets':'🔑',
        'docker/mounts':'📁','docker/cve':'🐛','docker/updates':'🔄',
        'kubernetes/rbac':'🔐','kubernetes/network':'🌐',
        'kubernetes/pod_security':'🛡','kubernetes/secrets':'🔑',
      };
      const icon  = catIcons[finding.category] || '🐳';
      const label = (finding.category||'').replace(/^(docker|kubernetes)\//, '').replace(/_/g,' ');
      tr.innerHTML = `
        <td>${sevBadge(finding.severity)}</td>
        <td style="font-size:.8rem;color:var(--text2)">${icon} ${esc(label)}</td>
        <td><b>${esc(finding.title)}</b></td>
        <td style="font-size:.78rem;color:var(--text2)">${esc((finding.remediation||'').substring(0,70))}</td>`;
      tbody.appendChild(tr);
    },
    onDone(msg) {
      btn('btn-docker', false, '▶ Analizar Docker/K8s');
      const results = document.getElementById('docker-results');
      const empty   = document.getElementById('docker-empty');
      if (S.findings.docker.length > 0) {
        results.style.display = '';
        empty.style.display = 'none';
        renderSummary('docker-summary-bar', S.findings.docker);
        renderDockerChips(S.findings.docker);
      } else {
        empty.style.display = '';
        const h3 = empty.querySelector('h3');
        const p  = empty.querySelector('p');
        if (h3) h3.textContent = '✅ Sin problemas detectados';
        if (p)  p.textContent  = 'Tus contenedores tienen buena configuración.';
      }
      loadDashboard();
    },
    onError(e) {
      btn('btn-docker', false, '▶ Analizar Docker/K8s');
    },
  }, 'Docker / Kubernetes', '🐳');
}

// ── Monitoreo: verificar si hay nuevos dispositivos en la red ─────────────────
async function checkForNewDevices() {
  try {
    const r = await fetch('/api/assets');
    if (!r.ok) return;
    const assets = await r.json();
    const unauthorized = assets.filter(a => !a.is_authorized);
    if (unauthorized.length > 0) {
      addActivityItem('monitor', '⚠',
        `${unauthorized.length} dispositivo(s) no autorizado(s) en la red`,
        unauthorized.map(a => a.ip).join(', '),
        'high');
    }
  } catch(e) { /* silencioso */ }
}

// Monitoreo periódico cada 15 minutos
setInterval(checkForNewDevices, 15 * 60 * 1000);
