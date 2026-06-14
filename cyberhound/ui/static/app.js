/* CyberHound Pro v6.1 — app.js */
'use strict';

// ── Estado global ──────────────────────────────────────────────────────────
const S = {
  findings: { audit: [], malware: [], code: [], network: [], services: [], tls: [], webhdr: [], dnssec: [] },
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
  // ── Carga de datos — lista única y definitiva (sin monkey-patching) ─────────
  const _panelLoaders = {
    dashboard: () => loadDashboard(),
    history:   () => { loadHistory(); loadAgentFilterOptions(); },
    settings:  () => { loadKeys(); loadNotifications(); loadScheduler(); loadSuppressions(); loadUsers(); },
    monitor:   () => { loadMonitorStatus(); loadMonitorHistory(); },
  };
  _panelLoaders[name]?.();
}

function showCfgTab(name) {
  document.querySelectorAll('.cfg-tab').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.cfg-panel').forEach(p => p.classList.remove('active'));
  document.querySelector(`[data-cfg="${name}"]`)?.classList.add('active');
  document.getElementById('cfg-' + name)?.classList.add('active');
  // ── Carga de datos — lista única y definitiva (sin monkey-patching) ─────────
  const _cfgLoaders = {
    siem:         () => loadSIEM(),
    users:        () => loadUsers(),
    suppressions: () => loadSuppressions(),
    scheduler:    () => loadScheduler(),
    '2fa':        () => load2FAStatus(),
    yara:         () => loadYaraRules(),
    agents:       () => loadAgents(),
    license:      () => loadLicenseInfo(),
    quarantine:   () => loadQuarantine(),
    ansible:      () => loadAnsibleJobs(),
  };
  _cfgLoaders[name]?.();
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
      appendLog('warn', `Conexión perdida. Reconectando en ${delay/1000}s… (${S.wsRetries}/3)`);
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
    const icons = {audit:'', malware:'', network:'', code:''};
    const labels = {audit:'Seguridad', malware:'Malware', network:'Red', code:'Código'};
    scansList.innerHTML = Object.entries(stats.last_scans || {}).map(([type, scan]) =>
      scan ? `<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--border)">
        <span>${icons[type]||''} ${labels[type]||type}</span>
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
          ${f.auto_fix ? '<span class="fix-tag" title="Corrección automática disponible">Auto-fix</span>' : ''}
        </div>`).join('');
    } else if (audit) {
      critList.innerHTML = '<div style="color:var(--green);padding:10px">✓ Sin hallazgos críticos en el último análisis</div>';
    } else {
      critList.innerHTML = '<div class="empty-hint"><span></span><p>Ejecuta un análisis de seguridad para ver los resultados.</p></div>';
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
      ? `<button class="fix-btn" id="fix-${esc(f.id)}" onclick="event.stopPropagation();applyFix('${esc(f.id)}',this)">Corregir</button>`
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
  btn('btn-code', true, 'Analizando…');
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
  btn('btn-network', true, 'Escaneando red…');
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
        <td>${f.auto_fix ? `<button class="fix-btn remote" onclick="event.stopPropagation();applyFixRemote('${esc(f.id)}','${esc(host)}',this)">Fix</button>` : ''}</td>`;
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
    chip.textContent = `${d.ip}`;
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
      <td>${d.has_ssh !== false ? `<button class="fix-btn remote" onclick="sshAuditOne('${esc(d.ip)}',${d.ssh_port||22})">Auditar</button>` : ''}</td>`;
    tbody.appendChild(tr);
  });
}

function _updateHostChip(hr) {
  const chip = document.getElementById(`chip-${hr.host.replace(/\./g,'_')}`);
  if (!chip) return;
  const icons = {ok:'✓', unreachable:'✗', auth_failed:'', error:'⚠'};
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
        <td>${f.auto_fix?`<button class="fix-btn remote" onclick="event.stopPropagation();applyFixRemote('${esc(f.id)}','${esc(ip)}',this)">Fix</button>`:''}</td>`;
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
    const typeLabels = {audit:'Seguridad', malware:'Malware', network:'Red', code:'Código', ssh:'SSH'};
    tbody.innerHTML = data.map(s => `
      <tr onclick="loadHistoryDetail(${s.id},this)" style="cursor:pointer">
        <td style="white-space:nowrap">${fmt(s.started_at)}</td>
        <td>${typeLabels[s.scan_type]||s.scan_type}</td>
        <td style="font-size:.82rem;color:var(--text2)">${esc(s.target||'localhost')}</td>
        <td>${_scorePill(s.score)}</td>
        <td>${_findingBar(s)}</td>
        <td style="color:var(--text2);font-size:.82rem">${dur(s.duration_s)}</td>
        <td><span style="font-size:.75rem;color:var(--text2)">${s.triggered_by==='scheduler'?'Auto':'Manual'}</span></td>
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
      <span class="comp-new">${comparison.new.length} nuevos</span>
      <span class="comp-resolved">${comparison.resolved.length} resueltos</span>
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
  const el = document.getElementById('history-detail');
  if (el) el.style.display = 'none';
}

// ── Fix local / remoto ────────────────────────────────────────────────────
async function applyFix(findingId, btnEl) {
  if (btnEl) { btnEl.disabled = true; btnEl.textContent = ''; }
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
      if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'Corregir'; }
    }
  } catch(e) {
    toast('Error: ' + e, 'error');
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'Corregir'; }
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
  if (btnEl) { btnEl.disabled = true; btnEl.textContent = ''; }
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
      if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'Fix'; }
    }
  } catch(e) {
    toast('Error: ' + e, 'error');
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'Fix'; }
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
    ${f.auto_fix && !hostLabel && !f.fixed_at ? `<button class="d-fix-btn" onclick="applyFix('${esc(f.id||f.finding_id||'')}',this)">Aplicar corrección</button>` : ''}
    ${f.auto_fix && hostLabel && !f.fixed_at ? `<button class="d-fix-btn remote" onclick="applyFixRemote('${esc(f.id||'')}','${esc(hostLabel)}',this)">Corregir en ${esc(hostLabel)}</button>` : ''}
    ${!f.auto_fix ? `<div style="margin-top:10px;padding:10px;background:var(--bg3);border-radius:6px;font-size:.82rem;color:var(--text2)">ℹ️ Esta corrección requiere revisión manual.</div>` : ''}
    <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn-secondary small" onclick="suppressFinding('${esc(f.id||f.finding_id||'')}')">Suprimir (falso positivo)</button>
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
    const names = {daily_audit:'Audit de seguridad diario', weekly_malware:'Malware scan semanal', daily_network:'Network scan diario'};
    container.innerHTML = data.map(e => `
      <div class="sched-card">
        <div class="sched-info">
          <div class="sched-name">${names[e.name]||e.name}</div>
          <div class="sched-meta">
            ${e.enabled ? 'Activo' : 'Desactivado'} ·
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
  if (btnEl) { btnEl.disabled = true; btnEl.textContent = ''; }
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
          <button class="btn-secondary small" onclick="deleteUser('${esc(u.username)}')"></button>
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
  if (!username || !password) { if(msg) msg.textContent = 'Rellena todos los campos'; return; }
  const r = await fetch('/api/users', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({username, password, role}),
  });
  const d = await r.json();
  if (d.ok) {
    if (msg) { msg.textContent = '✓ Usuario creado'; msg.style.color = 'var(--green)'; }
    setTimeout(() => { document.getElementById('create-user-form').style.display = 'none'; loadUsers(); }, 1000);
  } else {
    if (msg) { msg.textContent = '' + d.error; msg.style.color = 'var(--red)'; }
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
        <td><button class="btn-secondary small" onclick="removeSuppression('${esc(s.finding_id_pattern)}')">Eliminar</button></td>
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
  appendLog('info', 'CyberHound Pro v6.3.0 iniciado.');
  loadDashboard();
  loadKeys();
  // Polling del dashboard cada 5 minutos (respaldo del WS push)
  setInterval(loadDashboard, 5 * 60 * 1000);
  // Canal push WebSocket (sin polling)
  setTimeout(initPushWebSocket, 2000);
  // Monitoreo de nuevos dispositivos cada 15 minutos
  setInterval(checkForNewDevices, 15 * 60 * 1000);
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
       ${esc(k)}: ${n}
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
  msg.textContent = 'Probando conexión…';
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
      crits   > 0 ? `<span class="scan-stat has-value" style="color:var(--critical)">${crits} críticos</span>` : '',
      highs   > 0 ? `<span class="scan-stat has-value" style="color:var(--high)">${highs} altos</span>` : '',
      mediums > 0 ? `<span class="scan-stat has-value">${mediums} medios</span>` : '',
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
function wsRunWithActivity(task, params, handlers = {}, scanLabel = '', scanIcon = '') {
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
      const sevIcon = {critical:'', high:'', medium:'', low:'', info:''}[f.severity] || '';
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
        const icon = level === 'ok' ? '✓' : '';
        addActivityItem(task, icon === '✓' ? '' : '', text, '', 'info');
      }
      if (handlers.onLog) handlers.onLog(level, text);
    },
    onDone(msg) {
      completeScanProgress(scanKey, counts.total, msg.score);
      const scoreStr = msg.score != null ? ` (score: ${msg.score}/100)` : '';
      addActivityItem(task, '',
        `${scanLabel || task} completado${scoreStr}`,
        `${counts.critical} críticos · ${counts.high} altos · ${counts.medium} medios`,
        counts.critical > 0 ? 'critical' : counts.high > 0 ? 'high' : 'ok');
      if (handlers.onDone) handlers.onDone(msg);
    },
    onDevices(devices) {
      addActivityItem('network', '',
        `${devices.length} dispositivos encontrados en la red`, '', 'info');
      updateScanProgress(scanKey, devices.length, 0, 0, 0, `${devices.length} dispositivos`);
      if (handlers.onDevices) handlers.onDevices(devices);
    },
    onHostResult(hr) {
      const icon = hr.status === 'ok' ? '' : '';
      addActivityItem('ssh', icon,
        `${hr.host}: ${hr.status === 'ok' ? hr.count + ' hallazgos' : hr.error || hr.status}`,
        hr.os_info || '', hr.status === 'ok' ? (hr.count > 0 ? 'high' : 'ok') : 'medium');
      if (handlers.onHostResult) handlers.onHostResult(hr);
    },
    onError(e) {
      completeScanProgress(scanKey, counts.total, null);
      addActivityItem(task, '', `Error en ${scanLabel || task}`, e.text, 'critical');
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
  btn('btn-audit', true, 'Analizando…');
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
        if (el) { el.textContent = `Corregir ${fixable.length} automáticamente`; el.style.display = ''; }
      }
      loadDashboard();
      if (document.getElementById('audit-fix-all')?.checked) fixAll('audit');
    },
  }, 'Análisis de seguridad', '');
}

function runMalware() {
  S.findings.malware = [];
  document.getElementById('malware-results').style.display = 'none';
  document.getElementById('malware-empty').style.display = '';
  document.getElementById('malware-tbody').innerHTML = '';
  btn('btn-malware', true, 'Escaneando…');
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
  }, 'Malware scan', '');
}

function runDocker() {
  S.findings.docker = [];
  document.getElementById('docker-results').style.display = 'none';
  document.getElementById('docker-empty').style.display = '';
  document.getElementById('docker-tbody').innerHTML = '';
  document.getElementById('docker-summary').style.display = 'none';
  btn('btn-docker', true, 'Analizando…');
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
        'docker/privilege':'','docker/escape':'','docker/secrets':'',
        'docker/mounts':'','docker/cve':'','docker/updates':'',
        'kubernetes/rbac':'','kubernetes/network':'',
        'kubernetes/pod_security':'','kubernetes/secrets':'',
      };
      const icon  = catIcons[finding.category] || '';
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
        if (h3) h3.textContent = 'Sin problemas detectados';
        if (p)  p.textContent  = 'Tus contenedores tienen buena configuración.';
      }
      loadDashboard();
    },
    onError(e) {
      btn('btn-docker', false, '▶ Analizar Docker/K8s');
    },
  }, 'Docker / Kubernetes', '');
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

// ══════════════════════════════════════════════════════════════════════════════
// SERVICIOS, 2FA Y YARA
// ══════════════════════════════════════════════════════════════════════════════

// ── Auditoría de servicios ────────────────────────────────────────────────────
S.findings.services = [];

function runServicesAudit() {
  S.findings.services = [];
  document.getElementById('services-results').style.display = 'none';
  document.getElementById('services-empty').style.display = '';
  document.getElementById('services-tbody').innerHTML = '';
  btn('btn-services', true, 'Auditando…');

  const services = [...document.querySelectorAll('.svc-check:checked')].map(c => c.value);
  if (!services.length) { toast('Selecciona al menos un servicio'); return; }

  wsRunWithActivity('services', { services }, {
    onFinding(f) {
      S.findings.services.push(f);
      const tbody = document.getElementById('services-tbody');
      const tr = document.createElement('tr');
      tr.dataset.sev = f.severity;
      tr.onclick = () => openDrawer(f);
      const svcIcons = { nginx:'', apache:'', mysql:'', postgresql:'', redis:'', mongodb:'' };
      const svc = (f.category||'').replace('services/', '');
      tr.innerHTML = `
        <td>${sevBadge(f.severity)}</td>
        <td style="font-size:.8rem">${svcIcons[svc]||''} ${esc(svc)}</td>
        <td><b>${esc(f.title)}</b></td>
        <td style="font-size:.78rem;color:var(--text2)">${esc((f.remediation||'').substring(0,70))}</td>`;
      tbody.appendChild(tr);
    },
    onDone() {
      btn('btn-services', false, '▶ Auditar servicios');
      if (S.findings.services.length) {
        document.getElementById('services-results').style.display = '';
        document.getElementById('services-empty').style.display = 'none';
        renderSummary('services-summary-bar', S.findings.services);
      } else {
        const h3 = document.querySelector('#services-empty h3');
        const p  = document.querySelector('#services-empty p');
        if (h3) h3.textContent = 'Servicios con buena configuración';
        if (p)  p.textContent  = 'No se detectaron problemas en los servicios analizados.';
      }
    },
    onError() { btn('btn-services', false, '▶ Auditar servicios'); },
  }, 'Auditoría de servicios', '');
}

function runTLSScan() {
  S.findings.tls = [];
  document.getElementById('tls-results').style.display = 'none';
  document.getElementById('tls-empty').style.display = '';
  document.getElementById('tls-tbody').innerHTML = '';
  btn('btn-tls', true, 'Escaneando…');

  const raw = (document.getElementById('tls-targets').value || '').trim();
  const targets = raw ? raw.split('\n').map(s => s.trim()).filter(Boolean) : [];

  wsRunWithActivity('tls', { targets }, {
    onFinding(f) {
      S.findings.tls.push(f);
      const tbody = document.getElementById('tls-tbody');
      const tr = document.createElement('tr');
      tr.dataset.sev = f.severity;
      tr.onclick = () => openDrawer(f);
      const tgt = f.source_host || (f.evidence || '').split(',')[0] || '—';
      tr.innerHTML = `
        <td>${sevBadge(f.severity)}</td>
        <td style="font-size:.8rem">${esc(tgt)}</td>
        <td><b>${esc(f.title)}</b></td>
        <td style="font-size:.78rem;color:var(--text2)">${esc((f.remediation||'').substring(0,70))}</td>`;
      tbody.appendChild(tr);
    },
    onDone() {
      btn('btn-tls', false, '▶ Escanear TLS');
      if (S.findings.tls.length) {
        document.getElementById('tls-results').style.display = '';
        document.getElementById('tls-empty').style.display = 'none';
        renderSummary('tls-summary-bar', S.findings.tls);
      } else {
        const h3 = document.querySelector('#tls-empty h3');
        const p  = document.querySelector('#tls-empty p');
        if (h3) h3.textContent = 'TLS sin problemas detectados';
        if (p)  p.textContent  = 'Los certificados analizados son válidos y seguros.';
      }
    },
    onError() { btn('btn-tls', false, '▶ Escanear TLS'); },
  }, 'Escaneo TLS/SSL', '');
}

function runWebHeadersScan() {
  S.findings.webhdr = [];
  document.getElementById('webhdr-results').style.display = 'none';
  document.getElementById('webhdr-empty').style.display = '';
  document.getElementById('webhdr-tbody').innerHTML = '';

  const raw = (document.getElementById('webhdr-urls').value || '').trim();
  const urls = raw ? raw.split('\n').map(s => s.trim()).filter(Boolean) : [];
  if (!urls.length) { toast('Introduce al menos una URL'); return; }
  btn('btn-webhdr', true, 'Analizando…');

  wsRunWithActivity('web_headers', { urls }, {
    onFinding(f) {
      S.findings.webhdr.push(f);
      const tbody = document.getElementById('webhdr-tbody');
      const tr = document.createElement('tr');
      tr.dataset.sev = f.severity;
      tr.onclick = () => openDrawer(f);
      tr.innerHTML = `
        <td>${sevBadge(f.severity)}</td>
        <td style="font-size:.8rem">${esc(f.source_host || '—')}</td>
        <td><b>${esc(f.title)}</b></td>
        <td style="font-size:.78rem;color:var(--text2)">${esc((f.remediation||'').substring(0,70))}</td>`;
      tbody.appendChild(tr);
    },
    onDone() {
      btn('btn-webhdr', false, '▶ Analizar cabeceras');
      if (S.findings.webhdr.length) {
        document.getElementById('webhdr-results').style.display = '';
        document.getElementById('webhdr-empty').style.display = 'none';
        renderSummary('webhdr-summary-bar', S.findings.webhdr);
      } else {
        const h3 = document.querySelector('#webhdr-empty h3');
        const p  = document.querySelector('#webhdr-empty p');
        if (h3) h3.textContent = 'Cabeceras correctamente configuradas';
        if (p)  p.textContent  = 'No se detectaron problemas en las cabeceras de seguridad.';
      }
    },
    onError() { btn('btn-webhdr', false, '▶ Analizar cabeceras'); },
  }, 'Cabeceras de seguridad web', '');
}

function runWebExposureScan() {
  S.findings.webexp = [];
  document.getElementById('webexp-results').style.display = 'none';
  document.getElementById('webexp-empty').style.display = '';
  document.getElementById('webexp-tbody').innerHTML = '';

  const raw = (document.getElementById('webexp-urls').value || '').trim();
  const urls = raw ? raw.split('\n').map(s => s.trim()).filter(Boolean) : [];
  if (!urls.length) { toast('Introduce al menos una URL'); return; }
  btn('btn-webexp', true, 'Analizando…');

  wsRunWithActivity('web_exposure', { urls }, {
    onFinding(f) {
      S.findings.webexp.push(f);
      const tbody = document.getElementById('webexp-tbody');
      const tr = document.createElement('tr');
      tr.dataset.sev = f.severity;
      tr.onclick = () => openDrawer(f);
      tr.innerHTML = `
        <td>${sevBadge(f.severity)}</td>
        <td style="font-size:.8rem">${esc(f.source_host || '—')}</td>
        <td><b>${esc(f.title)}</b></td>
        <td style="font-size:.78rem;color:var(--text2)">${esc((f.remediation||'').substring(0,70))}</td>`;
      tbody.appendChild(tr);
    },
    onDone() {
      btn('btn-webexp', false, '▶ Analizar exposición');
      if (S.findings.webexp.length) {
        document.getElementById('webexp-results').style.display = '';
        document.getElementById('webexp-empty').style.display = 'none';
        renderSummary('webexp-summary-bar', S.findings.webexp);
      } else {
        const h3 = document.querySelector('#webexp-empty h3');
        const p  = document.querySelector('#webexp-empty p');
        if (h3) h3.textContent = 'Sin exposiciones detectadas';
        if (p)  p.textContent  = 'No se encontraron recursos sensibles accesibles públicamente.';
      }
    },
    onError() { btn('btn-webexp', false, '▶ Analizar exposición'); },
  }, 'Exposición de recursos web', '');
}

function runAPISecurityScan() {
  S.findings.apisec = [];
  document.getElementById('apisec-results').style.display = 'none';
  document.getElementById('apisec-empty').style.display = '';
  document.getElementById('apisec-tbody').innerHTML = '';

  const raw = (document.getElementById('apisec-urls').value || '').trim();
  const urls = raw ? raw.split('\n').map(s => s.trim()).filter(Boolean) : [];
  if (!urls.length) { toast('Introduce al menos una URL'); return; }
  btn('btn-apisec', true, 'Analizando…');

  wsRunWithActivity('api_security', { urls }, {
    onFinding(f) {
      S.findings.apisec.push(f);
      const tbody = document.getElementById('apisec-tbody');
      const tr = document.createElement('tr');
      tr.dataset.sev = f.severity;
      tr.onclick = () => openDrawer(f);
      tr.innerHTML = `
        <td>${sevBadge(f.severity)}</td>
        <td style="font-size:.8rem">${esc(f.source_host || '—')}</td>
        <td><b>${esc(f.title)}</b></td>
        <td style="font-size:.78rem;color:var(--text2)">${esc((f.remediation||'').substring(0,70))}</td>`;
      tbody.appendChild(tr);
    },
    onDone() {
      btn('btn-apisec', false, '▶ Analizar API/CORS');
      if (S.findings.apisec.length) {
        document.getElementById('apisec-results').style.display = '';
        document.getElementById('apisec-empty').style.display = 'none';
        renderSummary('apisec-summary-bar', S.findings.apisec);
      } else {
        const h3 = document.querySelector('#apisec-empty h3');
        const p  = document.querySelector('#apisec-empty p');
        if (h3) h3.textContent = 'API/CORS sin problemas detectados';
        if (p)  p.textContent  = 'No se detectaron fallos de CORS ni documentación expuesta.';
      }
    },
    onError() { btn('btn-apisec', false, '▶ Analizar API/CORS'); },
  }, 'Seguridad de API / CORS', '');
}

function runDNSScan() {
  S.findings.dnssec = [];
  document.getElementById('dnssec-results').style.display = 'none';
  document.getElementById('dnssec-empty').style.display = '';
  document.getElementById('dnssec-tbody').innerHTML = '';

  const raw = (document.getElementById('dnssec-domains').value || '').trim();
  const domains = raw ? raw.split('\n').map(s => s.trim()).filter(Boolean) : [];
  if (!domains.length) { toast('Introduce al menos un dominio'); return; }
  btn('btn-dnssec', true, 'Auditando…');

  wsRunWithActivity('dns', { domains }, {
    onFinding(f) {
      S.findings.dnssec.push(f);
      const tbody = document.getElementById('dnssec-tbody');
      const tr = document.createElement('tr');
      tr.dataset.sev = f.severity;
      tr.onclick = () => openDrawer(f);
      tr.innerHTML = `
        <td>${sevBadge(f.severity)}</td>
        <td style="font-size:.8rem">${esc(f.source_host || '—')}</td>
        <td><b>${esc(f.title)}</b></td>
        <td style="font-size:.78rem;color:var(--text2)">${esc((f.remediation||'').substring(0,70))}</td>`;
      tbody.appendChild(tr);
    },
    onDone() {
      btn('btn-dnssec', false, '▶ Auditar DNS');
      if (S.findings.dnssec.length) {
        document.getElementById('dnssec-results').style.display = '';
        document.getElementById('dnssec-empty').style.display = 'none';
        renderSummary('dnssec-summary-bar', S.findings.dnssec);
      } else {
        const h3 = document.querySelector('#dnssec-empty h3');
        const p  = document.querySelector('#dnssec-empty p');
        if (h3) h3.textContent = 'DNS correctamente configurado';
        if (p)  p.textContent  = 'SPF, DMARC, DNSSEC y CAA en orden.';
      }
    },
    onError() { btn('btn-dnssec', false, '▶ Auditar DNS'); },
  }, 'Seguridad DNS', '');
}

function runSubdomainScan() {
  S.findings.subenum = [];
  document.getElementById('subenum-results').style.display = 'none';
  document.getElementById('subenum-empty').style.display = '';
  document.getElementById('subenum-tbody').innerHTML = '';

  const raw = (document.getElementById('subenum-domains').value || '').trim();
  const domains = raw ? raw.split('\n').map(s => s.trim()).filter(Boolean) : [];
  if (!domains.length) { toast('Introduce al menos un dominio'); return; }
  btn('btn-subenum', true, 'Enumerando…');

  wsRunWithActivity('subdomain_enum', { domains }, {
    onFinding(f) {
      S.findings.subenum.push(f);
      const tbody = document.getElementById('subenum-tbody');
      const tr = document.createElement('tr');
      tr.dataset.sev = f.severity;
      tr.onclick = () => openDrawer(f);
      tr.innerHTML = `
        <td>${sevBadge(f.severity)}</td>
        <td style="font-size:.8rem">${esc(f.source_host || '—')}</td>
        <td><b>${esc(f.title)}</b></td>
        <td style="font-size:.78rem;color:var(--text2)">${esc((f.evidence||'').substring(0,70))}</td>`;
      tbody.appendChild(tr);
    },
    onDone() {
      btn('btn-subenum', false, '▶ Enumerar subdominios');
      if (S.findings.subenum.length) {
        document.getElementById('subenum-results').style.display = '';
        document.getElementById('subenum-empty').style.display = 'none';
        renderSummary('subenum-summary-bar', S.findings.subenum);
      } else {
        const h3 = document.querySelector('#subenum-empty h3');
        const p  = document.querySelector('#subenum-empty p');
        if (h3) h3.textContent = 'Sin subdominios en CT logs';
        if (p)  p.textContent  = 'No se encontraron subdominios publicados (o crt.sh no respondió).';
      }
    },
    onError() { btn('btn-subenum', false, '▶ Enumerar subdominios'); },
  }, 'Enumeración de subdominios', '');
}

function runNucleiScan() {
  S.findings.nuclei = [];
  document.getElementById('nuclei-results').style.display = 'none';
  document.getElementById('nuclei-empty').style.display = '';
  document.getElementById('nuclei-tbody').innerHTML = '';

  const raw = (document.getElementById('nuclei-urls').value || '').trim();
  const urls = raw ? raw.split('\n').map(s => s.trim()).filter(Boolean) : [];
  if (!urls.length) { toast('Introduce al menos una URL'); return; }
  btn('btn-nuclei', true, 'Escaneando…');

  wsRunWithActivity('nuclei', { urls }, {
    onFinding(f) {
      S.findings.nuclei.push(f);
      const tbody = document.getElementById('nuclei-tbody');
      const tr = document.createElement('tr');
      tr.dataset.sev = f.severity;
      tr.onclick = () => openDrawer(f);
      tr.innerHTML = `
        <td>${sevBadge(f.severity)}</td>
        <td style="font-size:.8rem">${esc(f.source_host || '—')}</td>
        <td><b>${esc(f.title)}</b></td>
        <td style="font-size:.78rem;color:var(--text2)">${esc((f.evidence||'').substring(0,70))}</td>`;
      tbody.appendChild(tr);
    },
    onDone() {
      btn('btn-nuclei', false, '▶ Ejecutar Nuclei');
      if (S.findings.nuclei.length) {
        document.getElementById('nuclei-results').style.display = '';
        document.getElementById('nuclei-empty').style.display = 'none';
        renderSummary('nuclei-summary-bar', S.findings.nuclei);
      } else {
        const h3 = document.querySelector('#nuclei-empty h3');
        const p  = document.querySelector('#nuclei-empty p');
        if (h3) h3.textContent = 'Sin hallazgos de Nuclei';
        if (p)  p.textContent  = 'No hubo coincidencias (o el binario nuclei no está instalado en el servidor).';
      }
    },
    onError() { btn('btn-nuclei', false, '▶ Ejecutar Nuclei'); },
  }, 'Nuclei', '');
}

// ── 2FA ───────────────────────────────────────────────────────────────────────
async function load2FAStatus() {
  try {
    const r = await fetch('/api/auth/2fa/status');
    if (!r.ok) return;
    const d = await r.json();
    const statusBox  = document.getElementById('2fa-status-box');
    const disableBtn = document.getElementById('2fa-disable-btn');
    if (d.enabled) {
      if (statusBox) statusBox.innerHTML = `<div style="color:var(--green);font-weight:600">✓ 2FA activado para <b>${esc(d.user)}</b></div>`;
      if (disableBtn) disableBtn.style.display = '';
    } else {
      if (statusBox) statusBox.innerHTML = `<div style="color:var(--text2)">⚠ 2FA no activado — tu cuenta solo está protegida por contraseña</div>`;
      if (disableBtn) disableBtn.style.display = 'none';
    }
  } catch(e) { /* silencioso */ }
}

async function setup2FA() {
  const r = await fetch('/api/auth/2fa/setup', { method: 'POST' });
  if (!r.ok) { toast('Error iniciando 2FA'); return; }
  const d = await r.json();

  // Mostrar QR
  const qrEl = document.getElementById('2fa-qr');
  if (qrEl) qrEl.innerHTML = d.qr_svg || `<div style="font-size:.78rem;word-break:break-all;padding:8px;max-width:200px">${esc(d.uri)}</div>`;

  // Mostrar secreto
  const secretEl = document.getElementById('2fa-secret-display');
  if (secretEl) { secretEl.value = d.secret; secretEl.style.display = ''; }

  // Mostrar códigos de recuperación
  const codesEl = document.getElementById('2fa-recovery-codes');
  if (codesEl && d.recovery_codes) {
    codesEl.innerHTML = d.recovery_codes.map(c => `<div>${esc(c)}</div>`).join('');
  }

  document.getElementById('2fa-setup-area').style.display = '';
  document.getElementById('2fa-verify-code')?.focus();
}

async function activate2FA() {
  const code = document.getElementById('2fa-verify-code')?.value.trim();
  if (!code || code.length !== 6) { toast('Introduce el código de 6 dígitos'); return; }

  const r = await fetch('/api/auth/2fa/activate', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ code }),
  });
  const d = await r.json();
  const msg = document.getElementById('2fa-msg');
  if (d.ok) {
    if (msg) { msg.textContent = '✓ 2FA activado correctamente'; msg.style.color = 'var(--green)'; }
    document.getElementById('2fa-setup-area').style.display = 'none';
    toast('✓ 2FA activado');
    await load2FAStatus();
  } else {
    if (msg) { msg.textContent = '✗ Código incorrecto — inténtalo de nuevo'; msg.style.color = 'var(--red)'; }
    toast('Código incorrecto');
  }
}

async function disable2FA() {
  if (!confirm('¿Seguro que quieres desactivar el 2FA? Tu cuenta quedará menos protegida.')) return;
  const r = await fetch('/api/auth/2fa/disable', { method: 'POST' });
  const d = await r.json();
  if (d.ok) {
    toast('2FA desactivado');
    await load2FAStatus();
  }
}

// ── YARA ──────────────────────────────────────────────────────────────────────
async function updateYaraRules() {
  const sources = [];
  if (document.getElementById('yara-src-default')?.checked) sources.push('default');
  if (document.getElementById('yara-src-community')?.checked) sources.push('community');
  if (!sources.length) { toast('Selecciona al menos una fuente'); return; }

  const msg = document.getElementById('yara-update-msg');
  if (msg) { msg.textContent = 'Descargando reglas…'; msg.style.color = 'var(--text2)'; }

  const r = await fetch('/api/yara/update', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ sources }),
  });
  const d = await r.json();

  if (msg) {
    const updated = (d.updated||[]).length;
    const errors  = (d.errors||[]).length;
    msg.textContent = `✓ ${updated} regla(s) actualizada(s)` + (errors ? ` · ✗ ${errors} error(es)` : '');
    msg.style.color = errors > 0 ? 'var(--yellow)' : 'var(--green)';
  }
  await loadYaraRules();
}

async function loadYaraRules() {
  const r = await fetch('/api/yara/rules');
  if (!r.ok) return;
  const rules = await r.json();
  const table = document.getElementById('yara-rules-table');
  const tbody = document.getElementById('yara-rules-tbody');
  if (!table || !tbody) return;
  if (!rules.length) { table.style.display = 'none'; return; }
  table.style.display = '';
  tbody.innerHTML = rules.map(rule => `
    <tr>
      <td style="font-family:monospace;font-size:.8rem">${esc(rule.name)}</td>
      <td style="color:var(--text2)">${rule.size_kb} KB</td>
      <td style="color:var(--text2)">${new Date(rule.modified * 1000).toLocaleDateString('es')}</td>
    </tr>`).join('');
}

// ── Integrar carga de 2FA y YARA al activar tabs ──────────────────────────────
// (showCfgTab ya llama a loadSIEM, loadUsers, etc. de forma centralizada)

// ══════════════════════════════════════════════════════════════════════════════
// HISTORIAL MEJORADO + AGENTES
// ══════════════════════════════════════════════════════════════════════════════




async function openHistoryDetail(scanId) {
  const [findings, comparison] = await Promise.all([
    fetch(`/api/history/${scanId}`).then(r => r.json()),
    fetch(`/api/history/${scanId}/compare`).then(r => r.json()),
  ]);

  const detail = document.getElementById('history-detail');
  const title  = document.getElementById('history-detail-title');
  const comp   = document.getElementById('history-comparison');
  const tbody  = document.getElementById('hist-detail-tbody');
  if (!detail || !tbody) return;

  detail.style.display = '';
  if (title) title.textContent = `${findings.length} hallazgos en scan #${scanId}`;

  // Mostrar comparación
  if (comp && !comparison.first_scan) {
    const newCount  = comparison.new?.length  || 0;
    const resolved  = comparison.resolved?.length || 0;
    const unchanged = comparison.unchanged || 0;
    comp.innerHTML = [
      newCount  > 0 ? `<span style="color:var(--red)">+${newCount} nuevos</span>`         : '',
      resolved  > 0 ? `<span style="color:var(--green)">-${resolved} resueltos</span>`    : '',
      unchanged > 0 ? `<span style="color:var(--text2)">${unchanged} sin cambio</span>`   : '',
    ].filter(Boolean).join(' · ');
  } else if (comp) {
    comp.textContent = comparison.first_scan ? '(primer scan de este tipo)' : '';
  }

  // Marcar findings nuevos vs resueltos vs sin cambio
  const newIds = new Set((comparison.new || []).map(f => f.id));
  tbody.innerHTML = findings.map(f => {
    const isNew = newIds.has(f.finding_id);
    const isFixed = !!f.fixed_at;
    const badge = isFixed
      ? '<span style="font-size:.7rem;color:var(--green)">✓ Corregido</span>'
      : isNew
      ? '<span style="font-size:.7rem;color:var(--red)">Nuevo</span>'
      : '';
    return `<tr>
      <td>${sevBadge(f.severity)}</td>
      <td style="font-size:.78rem;color:var(--text2)">${esc(f.category||'')}</td>
      <td style="font-size:.82rem">${esc(f.title)}</td>
      <td>${badge}</td>
    </tr>`;
  }).join('');

  detail.scrollIntoView({ behavior: 'smooth' });
}

function compareHistory(scanId) {
  // Redirige a openHistoryDetail que ya incluye la comparación
  openHistoryDetail(scanId);
}

// ── Agentes ───────────────────────────────────────────────────────────────────
async function loadAgents() {
  try {
    const r = await fetch('/api/agent/list');
    if (!r.ok) return;
    const agents = await r.json();
    const container = document.getElementById('agents-list');
    if (!container) return;

    if (!agents.length) {
      container.innerHTML = '<p style="color:var(--text2);font-size:.82rem">Sin agentes conectados todavía.</p>';
      return;
    }

    container.innerHTML = `
      <table>
        <thead><tr><th>Agente</th><th>Hostname</th><th>Último scan</th><th>Score</th><th>Última vez visto</th></tr></thead>
        <tbody>${agents.map(a => `
          <tr>
            <td style="font-weight:600">${esc(a.name||'')}</td>
            <td style="color:var(--text2)">${esc(a.hostname||'')}</td>
            <td style="font-size:.78rem">${esc(a.last_scan||'—')}</td>
            <td>${a.score != null ? `<span style="color:${a.score>=80?'var(--green)':a.score>=50?'var(--yellow)':'var(--red)'}">${a.score}</span>` : '—'}</td>
            <td style="font-size:.78rem;color:var(--text2)">${a.last_seen ? new Date(a.last_seen).toLocaleString('es') : '—'}</td>
          </tr>`).join('')}
        </tbody>
      </table>`;
  } catch(e) { /* silencioso */ }
}

// Mostrar agentes en la pestaña y en el filtro del historial
async function loadAgentFilterOptions() {
  try {
    const r = await fetch('/api/agent/list');
    if (!r.ok) return;
    const agents = await r.json();
    const sel = document.getElementById('hist-agent');
    if (!sel || !agents.length) return;
    document.getElementById('history-agent-filter')?.style && (
      document.getElementById('history-agent-filter').style.display = ''
    );
    agents.forEach(a => {
      const opt = document.createElement('option');
      opt.value = a.name;
      opt.textContent = a.name;
      sel.appendChild(opt);
    });
  } catch(e) { /* silencioso */ }
}


// ══════════════════════════════════════════════════════════════════════════════
// LICENCIAS + LDAP/AD + WEBSOCKET PUSH (sin polling)
// ══════════════════════════════════════════════════════════════════════════════

// ── WebSocket push — notificaciones en tiempo real sin polling ────────────────
let _pushWs = null;
let _pushReconnectTimer = null;

function initPushWebSocket() {
  if (_pushWs && _pushWs.readyState === WebSocket.OPEN) return;
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  _pushWs = new WebSocket(`${proto}://${location.host}/ws/push`);

  _pushWs.onmessage = ev => {
    try {
      const msg = JSON.parse(ev.data);
      handlePushEvent(msg);
    } catch(e) {}
  };

  _pushWs.onopen = () => {
    appendLog('info', 'Canal de notificaciones push conectado');
    if (_pushReconnectTimer) { clearTimeout(_pushReconnectTimer); _pushReconnectTimer = null; }
  };

  _pushWs.onclose = () => {
    // Reconectar en 30 segundos
    _pushReconnectTimer = setTimeout(initPushWebSocket, 30000);
  };

  _pushWs.onerror = () => {
    // Silencioso — la reconexión lo maneja onclose
  };
}

function handlePushEvent(msg) {
  switch (msg.type) {
    case 'initial':
      // Estado inicial al conectar — actualizar dashboard sin polling
      if (msg.data) _renderDashboard(msg.data, []);
      break;

    case 'new_findings':
      // Hay nuevos hallazgos críticos
      const { critical, total, scan_id, score, titles } = msg.data || {};
      if (critical > 0) {
        toast(`${critical} hallazgo(s) crítico(s) detectado(s)`, 'critical');
        addActivityItem('push', '',
          `${critical} hallazgo(s) CRÍTICO(S)`,
          titles?.join(' · ') || '',
          'critical');
        // Refrescar dashboard sin polling
        loadDashboard();
      }
      break;

    case 'scan_complete':
      // Un scan automático (scheduler) terminó
      addActivityItem('scheduler', '',
        `Scan automático completado: ${msg.data?.scan_type || ''}`,
        `Score: ${msg.data?.score ?? '—'}/100`,
        'ok');
      loadDashboard();
      break;

    case 'new_device':
      // Nuevo dispositivo detectado en la red
      toast(`Nuevo dispositivo en la red: ${msg.data?.ip || ''}`, 'warning');
      addActivityItem('monitor', '',
        `Nuevo dispositivo: ${msg.data?.ip || ''}`,
        msg.data?.hostname || '',
        'high');
      break;
  }
}

// ── Licencias ─────────────────────────────────────────────────────────────────
async function loadLicenseInfo() {
  try {
    const r = await fetch('/api/license');
    if (!r.ok) return;
    const lic = await r.json();
    const box = document.getElementById('license-info');
    if (!box) return;
    const tierColors = { community:'var(--text2)', starter:'var(--blue)', professional:'var(--green)', enterprise:'var(--yellow)' };
    const color = tierColors[lic.tier] || 'var(--text2)';
    box.innerHTML = `
      <div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap">
        <div>
          <div style="font-size:1.1rem;font-weight:700;color:${color}">${(lic.tier||'').toUpperCase()}</div>
          <div style="color:var(--text2);font-size:.82rem">${esc(lic.licensee||'')}</div>
        </div>
        <div style="flex:1;min-width:200px">
          <div style="font-size:.82rem;margin-bottom:4px">
            ${lic.valid_until
              ? `Expira: ${new Date(lic.valid_until).toLocaleDateString('es')} (${lic.days_remaining} días)`
              : '<span style="color:var(--green)">Licencia perpetua</span>'}
          </div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;font-size:.72rem">
            ${lic.limits?.siem_enabled ? '<span style="background:var(--bg3);padding:2px 6px;border-radius:3px">✓ SIEM</span>' : '<span style="background:var(--bg3);padding:2px 6px;border-radius:3px;opacity:.4">✗ SIEM</span>'}
            ${lic.limits?.agent_enabled ? '<span style="background:var(--bg3);padding:2px 6px;border-radius:3px">✓ Agentes</span>' : '<span style="background:var(--bg3);padding:2px 6px;border-radius:3px;opacity:.4">✗ Agentes</span>'}
            ${lic.limits?.intel_enabled ? '<span style="background:var(--bg3);padding:2px 6px;border-radius:3px">✓ Intel</span>' : '<span style="background:var(--bg3);padding:2px 6px;border-radius:3px;opacity:.4">✗ Intel</span>'}
            ${lic.limits?.max_hosts > 0 ? `<span style="background:var(--bg3);padding:2px 6px;border-radius:3px">máx ${lic.limits.max_hosts} hosts</span>` : '<span style="background:var(--bg3);padding:2px 6px;border-radius:3px">✓ Hosts ilimitados</span>'}
          </div>
        </div>
      </div>`;
  } catch(e) {}
}

async function activateLicense() {
  const key = document.getElementById('license-key')?.value.trim();
  const msg = document.getElementById('license-msg');
  if (!key) { if (msg) { msg.textContent = 'Introduce la clave de licencia'; msg.style.color='var(--yellow)'; } return; }

  const r = await fetch('/api/license/activate', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ key }),
  });
  const d = await r.json();
  if (msg) {
    msg.textContent = d.message || (d.ok ? '✓ Licencia activada' : '✗ Error');
    msg.style.color = d.ok ? 'var(--green)' : 'var(--red)';
  }
  if (d.ok) { await loadLicenseInfo(); toast('✓ Licencia activada correctamente'); }
}

// ── LDAP / AD ─────────────────────────────────────────────────────────────────
async function runLDAPScan() {
  const body = {
    uri:    document.getElementById('ldap-uri')?.value.trim() || '',
    base:   document.getElementById('ldap-base')?.value.trim() || '',
    binddn: document.getElementById('ldap-binddn')?.value.trim() || '',
    bindpw: document.getElementById('ldap-bindpw')?.value || '',
  };

  const btnEl = document.getElementById('btn-ldap');
  if (btnEl) { btnEl.disabled = true; btnEl.textContent = 'Analizando…'; }

  try {
    const r = await fetch('/api/scan/ldap', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify(body),
    });
    const d = await r.json();
    const tbody  = document.getElementById('ldap-tbody');
    const results = document.getElementById('ldap-results');
    const empty  = document.getElementById('ldap-empty');

    if (!tbody) return;

    if (!d.findings?.length) {
      if (results) results.style.display = 'none';
      if (empty)   empty.style.display = '';
    } else {
      if (results) results.style.display = '';
      if (empty)   empty.style.display   = 'none';
      renderSummary('ldap-summary-bar', d.findings);
      tbody.innerHTML = d.findings.map(f => `
        <tr onclick="openDrawer(${JSON.stringify(f).replace(/"/g,'&quot;')})">
          <td>${sevBadge(f.severity)}</td>
          <td style="font-size:.78rem;color:var(--text2)">${esc((f.category||'').replace('ldap/',''))}</td>
          <td>${esc(f.title)}</td>
          <td style="font-size:.78rem;color:var(--text2)">${esc((f.remediation||'').substring(0,70))}</td>
        </tr>`).join('');
      toast(`LDAP: ${d.findings.length} hallazgos detectados`);
    }
  } catch(e) {
    toast('Error en LDAP scan: ' + e.message);
  } finally {
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = '▶ Auditar AD/LDAP'; }
  }
}


// ══════════════════════════════════════════════════════════════════════════════
// CUARENTENA + SBOM
// ══════════════════════════════════════════════════════════════════════════════

// ── Cuarentena ────────────────────────────────────────────────────────────────
async function loadQuarantine() {
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
        <button class="btn-secondary small" onclick="restoreQuarantine('${esc(item.quarantine_name)}')">Restaurar</button>
        <button class="btn-danger small" onclick="deleteQuarantine('${esc(item.quarantine_name)}')">Eliminar</button>
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
    renderSummary('img-scan-summary-bar', d.findings);

    if (tbody) {
      tbody.innerHTML = d.findings.map(f => `
        <tr onclick="openDrawer(${JSON.stringify(f).replace(/"/g,'&quot;')})">
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
    renderSummary('rt-summary-bar', d.findings);
    if (tbody) {
      tbody.innerHTML = d.findings.map(f => `
        <tr onclick="openDrawer(${JSON.stringify(f).replace(/"/g,'&quot;')})">
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


// ══════════════════════════════════════════════════════════════════════════════
// BÚSQUEDA GLOBAL + EXPORTACIÓN CSV + ATAJOS DE TECLADO + UX MEJORADA
// ══════════════════════════════════════════════════════════════════════════════

// ── Búsqueda global de hallazgos ──────────────────────────────────────────────
let _searchTimer = null;

async function globalSearch(query) {
  const resultsEl = document.getElementById('global-search-results');
  if (!query || query.length < 2) {
    if (resultsEl) resultsEl.style.display = 'none';
    return;
  }

  clearTimeout(_searchTimer);
  _searchTimer = setTimeout(async () => {
    try {
      // Buscar en el historial de scans recientes
      const r = await fetch('/api/history?limit=10');
      if (!r.ok) return;
      const history = await r.json();

      const allFindings = [];
      const q = query.toLowerCase();

      // Buscar en findings en memoria (S.findings)
      const sources = ['audit','malware','network','docker','services'];
      for (const src of sources) {
        if (S.findings[src]) {
          for (const f of S.findings[src]) {
            if ((f.title||'').toLowerCase().includes(q) ||
                (f.category||'').toLowerCase().includes(q) ||
                (f.description||'').toLowerCase().includes(q) ||
                (f.evidence||'').toLowerCase().includes(q)) {
              allFindings.push({ ...f, _source: src });
            }
          }
        }
      }

      if (!resultsEl) return;

      if (!allFindings.length) {
        resultsEl.style.display = '';
        resultsEl.innerHTML = '<div style="padding:12px;color:var(--text2);font-size:.82rem">Sin resultados para "' + esc(query) + '"</div>';
        return;
      }

      resultsEl.style.display = '';
      const sevColors = { critical:'var(--critical)', high:'var(--high)', medium:'var(--medium)', low:'var(--text2)' };
      resultsEl.innerHTML = allFindings.slice(0, 8).map(f => {
        const color = sevColors[f.severity] || 'var(--text2)';
        return `<div style="padding:10px 14px;border-bottom:1px solid var(--border);cursor:pointer;hover:background:var(--bg3)"
          onclick="openDrawer(${JSON.stringify(f).replace(/"/g,'&quot;')});closeGlobalSearch()"
          onmouseover="this.style.background='var(--bg3)'"
          onmouseout="this.style.background=''"
        >
          <div style="display:flex;gap:8px;align-items:center">
            <span style="color:${color};font-size:.72rem;font-weight:700">${(f.severity||'').toUpperCase()}</span>
            <span style="font-size:.8rem;font-weight:600;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(f.title||'')}</span>
            <span style="font-size:.7rem;color:var(--text2);flex-shrink:0">${esc(f._source||'')}</span>
          </div>
          <div style="font-size:.72rem;color:var(--text2);margin-top:2px">${esc((f.category||'').substring(0,50))}</div>
        </div>`;
      }).join('') +
      (allFindings.length > 8 ? `<div style="padding:8px 14px;color:var(--text2);font-size:.75rem">… y ${allFindings.length-8} más</div>` : '');

    } catch(e) { /* silencioso */ }
  }, 200);
}

function closeGlobalSearch() {
  const input   = document.getElementById('global-search');
  const results = document.getElementById('global-search-results');
  if (input)   input.value = '';
  if (results) results.style.display = 'none';
}

// Cerrar búsqueda al clic fuera
document.addEventListener('click', e => {
  const wrap = document.getElementById('global-search-wrap');
  if (wrap && !wrap.contains(e.target)) closeGlobalSearch();
});

// ── Exportación CSV ────────────────────────────────────────────────────────────
function exportCSV(source) {
  const findings = S.findings[source];
  if (!findings?.length) { toast('Sin datos para exportar'); return; }

  const cols = ['severity', 'category', 'title', 'description', 'remediation', 'evidence', 'file_path'];
  const header = cols.join(',');
  const rows = findings.map(f =>
    cols.map(c => {
      const val = String(f[c] || '').replace(/"/g, '""').replace(/\n/g, ' ');
      return `"${val}"`;
    }).join(',')
  );

  const csv  = [header, ...rows].join('\r\n');
  const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' });  // BOM para Excel
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url;
  a.download = `cyberhound-${source}-${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
  toast(`✓ CSV exportado: ${findings.length} filas`);
}

// ── Atajos de teclado ─────────────────────────────────────────────────────────
let _keyBuffer = '';
let _keyTimer  = null;

document.addEventListener('keydown', e => {
  // No actuar si el usuario está escribiendo en un input/textarea
  const tag = (e.target.tagName || '').toLowerCase();
  if (['input','textarea','select'].includes(tag)) {
    if (e.key === 'Escape') {
      e.target.blur();
      closeGlobalSearch();
    }
    return;
  }

  // Cerrar diálogos
  if (e.key === 'Escape') {
    closeDrawer();
    document.getElementById('keyboard-help').style.display = 'none';
    closeGlobalSearch();
    return;
  }

  // Mostrar ayuda
  if (e.key === '?') {
    const help = document.getElementById('keyboard-help');
    if (help) help.style.display = help.style.display === 'none' ? 'flex' : 'none';
    return;
  }

  // Activar búsqueda
  if (e.key === '/') {
    e.preventDefault();
    document.getElementById('global-search')?.focus();
    return;
  }

  // Recargar dashboard
  if (e.key === 'R' && !e.ctrlKey && !e.metaKey) {
    loadDashboard();
    toast('↻ Dashboard recargado');
    return;
  }

  // Secuencias de 2 teclas (g + letra)
  _keyBuffer += e.key;
  clearTimeout(_keyTimer);
  _keyTimer = setTimeout(() => { _keyBuffer = ''; }, 1000);

  const nav = {
    'gd': 'dashboard', 'ga': 'audit',   'gn': 'network',
    'gm': 'malware',   'gr': 'history', 'gs': 'settings',
    'gc': 'code',      'gk': 'docker',  'go': 'monitor',
  };

  if (_keyBuffer.length === 2) {
    const dest = nav[_keyBuffer.toLowerCase()];
    if (dest) {
      showPanel(dest);
      _keyBuffer = '';
      toast(`${dest.charAt(0).toUpperCase() + dest.slice(1)}`);
    }
  }
});

// ── Mejoras de UX — Toast mejorado ────────────────────────────────────────────
// Sobreescribir toast con versión con tipos visuales
const _origToast = window.toast || function(){};
window.toast = function(msg, type = 'info') {
  const el = document.getElementById('toast');
  if (!el) return;
  const icons = { info: 'ℹ', ok: '✓', error: '✗', warning: '⚠' };
  const colors = {
    info:    'var(--blue)',
    ok:      'var(--green)',
    error:   'var(--red)',
    warning: 'var(--yellow)',
  };
  const icon  = icons[type]  || icons.info;
  const color = colors[type] || colors.info;

  el.style.borderLeft = `3px solid ${color}`;
  el.innerHTML = `<span style="color:${color};margin-right:6px">${icon}</span>${esc(msg)}`;
  el.classList.add('show');
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.remove('show'), 3500);
};

// ── Dashboard: añadir mini-stats de compliance ────────────────────────────────
async function loadDashboardCompliance() {
  try {
    const r = await fetch('/api/compliance?frameworks=ens,cis');
    if (!r.ok) return;
    const d = await r.json();
    const el = document.getElementById('dash-compliance-mini');
    if (!el) return;
    el.innerHTML = Object.entries(d).map(([fw, res]) => {
      const color = res.score_pct >= 90 ? 'var(--green)' : res.score_pct >= 70 ? 'var(--yellow)' : 'var(--red)';
      return `<div style="display:flex;justify-content:space-between;padding:3px 0;font-size:.78rem;border-bottom:1px solid var(--border)">
        <span style="color:var(--text2)">${fw.toUpperCase()}</span>
        <span style="color:${color};font-weight:600">${res.score_pct}%</span>
      </div>`;
    }).join('');
  } catch(e) {}
}

// Integrar compliance mini en loadDashboard
const _origLoadDashboard = loadDashboard;
loadDashboard = async function() {
  await _origLoadDashboard();
  loadDashboardCompliance();
};

// ══════════════════════════════════════════════════════════════════════════════
// NOTIFICACIONES PUSH DEL NAVEGADOR
// ══════════════════════════════════════════════════════════════════════════════

let _browserNotifEnabled = false;

async function requestBrowserNotifications() {
  if (!('Notification' in window)) {
    toast('Tu navegador no soporta notificaciones push', 'warning');
    return false;
  }
  if (Notification.permission === 'granted') {
    _browserNotifEnabled = true;
    return true;
  }
  if (Notification.permission === 'denied') {
    toast('Notificaciones bloqueadas — actívalas en la configuración del navegador', 'warning');
    return false;
  }
  const perm = await Notification.requestPermission();
  _browserNotifEnabled = perm === 'granted';
  if (_browserNotifEnabled) {
    toast('✓ Notificaciones activadas', 'ok');
    new Notification('CyberHound Pro', {
      body: 'Recibirás alertas cuando se detecten hallazgos críticos.',
      icon: '/favicon.ico',
    });
  }
  return _browserNotifEnabled;
}

function sendBrowserNotif(title, body, severity = 'info') {
  if (!_browserNotifEnabled || Notification.permission !== 'granted') return;
  const icons = { critical: '', high: '', medium: '', low: '', info: 'ℹ️' };
  const tag = `cyberhound-${severity}-${Date.now()}`;
  const n = new Notification(`${icons[severity] || 'ℹ️'} CyberHound: ${title}`, {
    body,
    icon: '/favicon.ico',
    tag,
    requireInteraction: severity === 'critical',
  });
  n.onclick = () => { window.focus(); n.close(); };
  // Auto-cerrar en 8s excepto críticos
  if (severity !== 'critical') setTimeout(() => n.close(), 8000);
}

// Integrar con el canal WebSocket push — notificar hallazgos críticos al llegar
const _origPushHandler = window._wsPushHandler;
window._wsPushHandler = function(event) {
  if (_origPushHandler) _origPushHandler(event);
  try {
    const msg = JSON.parse(event.data);
    if (msg.type === 'new_findings' && msg.critical > 0) {
      sendBrowserNotif(
        `${msg.critical} hallazgo(s) crítico(s)`,
        `Scan de ${msg.scan_type || 'seguridad'} completado en ${msg.target || 'localhost'}`,
        'critical',
      );
    } else if (msg.type === 'scan_complete' && msg.score < 50) {
      sendBrowserNotif(
        `Score bajo: ${msg.score}/100`,
        `El análisis de ${msg.scan_type || 'seguridad'} obtuvo un score preocupante.`,
        'high',
      );
    } else if (msg.type === 'new_device') {
      sendBrowserNotif(
        `Nuevo dispositivo detectado`,
        `IP: ${msg.ip || '?'} — Verifica si está autorizado en el panel de Assets.`,
        'medium',
      );
    }
  } catch(e) { /* ignorar mensajes no JSON */ }
};

// ── Panel de estado del sistema ────────────────────────────────────────────────
async function loadSystemStatus() {
  try {
    const [monR, licR, schedR] = await Promise.all([
      fetch('/api/monitor/status'),
      fetch('/api/license'),
      fetch('/api/scheduler'),
    ]);
    const mon   = monR.ok   ? await monR.json()   : {};
    const lic   = licR.ok   ? await licR.json()   : {};
    const sched = schedR.ok ? await schedR.json() : {};

    const el = document.getElementById('dash-system-status');
    if (!el) return;

    const items = [
      {
        label: 'Monitor',
        value: mon.active ? `Activo (${mon.mode})` : 'Inactivo',
        color: mon.active ? 'var(--green)' : 'var(--yellow)',
        tip:   mon.active ? '' : 'sudo apt install auditd',
      },
      {
        label: 'Licencia',
        value: lic.tier ? `${lic.tier} — ${lic.licensee || 'Community'}` : '?',
        color: 'var(--text)',
      },
      {
        label: 'Notif. push',
        value: _browserNotifEnabled ? 'Activadas' : 'Desactivadas',
        color: _browserNotifEnabled ? 'var(--green)' : 'var(--text2)',
        onclick: 'requestBrowserNotifications()',
      },
    ];

    el.innerHTML = items.map(item => `
      <div style="display:flex;justify-content:space-between;align-items:center;
                  padding:5px 0;border-bottom:1px solid var(--border);font-size:.8rem"
           ${item.onclick ? `onclick="${item.onclick}" style="cursor:pointer"` : ''}>
        <span style="color:var(--text2)">${item.label}</span>
        <span style="color:${item.color}">${item.value}
          ${item.tip ? `<span style="color:var(--text2);font-size:.72rem"> — ${item.tip}</span>` : ''}
        </span>
      </div>`).join('');
  } catch(e) {}
}

// ── Extender loadDashboard para incluir el estado del sistema ─────────────────
const _loadDashWithSystem = loadDashboard;
loadDashboard = async function() {
  await _loadDashWithSystem();
  loadSystemStatus();
};

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

  if (!target) { toast('Introduce una IP o dominio', 'warning'); return; }

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
      const target = f.evidence?.match(/ip=([^\s]+)/)?.[1] ||
                     f.evidence?.match(/domain=([^\s]+)/)?.[1] || '—';
      return `<tr onclick="openDrawer(${JSON.stringify(f).replace(/"/g,'&quot;')})">
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
           onclick="loadIntelScanDetail(${scan.id})">
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

// ── Integrar en showPanel ─────────────────────────────────────────────────────
const _showPanelIntel = showPanel;
showPanel = function(name) {
  _showPanelIntel(name);
  if (name === 'intel') {
    loadIntelConfig();
  }
};

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
