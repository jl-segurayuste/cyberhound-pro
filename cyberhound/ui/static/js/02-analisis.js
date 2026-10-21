// Dashboard y análisis de seguridad local, malware, código y red.
// Se cargan en orden (ver index.html); comparten el ámbito global como si fueran un solo fichero.
'use strict';

// ── Dashboard ─────────────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    const statsResp = await fetch('/api/dashboard');
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
    // score_trend ya viene agregado por día ({day, avg_score}), que es lo que pinta el gráfico
    _renderDashboard(stats, stats.score_trend || []);
    loadDashboardCompliance();
    loadSystemStatus();
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
        <div class="critical-item" ${on('click', 'openDrawerFromData', f)}>
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
      ? `<button class="fix-btn" id="fix-${esc(f.id)}" ${on('click', 'applyFix', f.id, '$this')} data-stop>Corregir</button>`
      : `<span style="font-size:.75rem;color:var(--text2)">Manual</span>`
    }</td>`;
  tbody.appendChild(tr);
  document.getElementById('audit-results')?.style && (document.getElementById('audit-results').style.display = '');
  document.getElementById('audit-empty') && (document.getElementById('audit-empty').style.display = 'none');
}

// Renderiza una fila de hallazgo de malware en la tabla del panel (5 columnas:
// Severidad · Tipo · Descripción · Fichero · Acción).
function _appendMalwareRow(f) {
  const tbody = document.getElementById('malware-tbody');
  if (!tbody) return;
  const tr = document.createElement('tr');
  tr.dataset.sev = f.severity;
  tr.onclick = () => openDrawer(f);
  tr.innerHTML = `
    <td>${_sevBadge(f.severity)}</td>
    <td style="font-size:.78rem;color:var(--text2)">${esc(f.category||'')}</td>
    <td><b>${esc(f.title)}</b></td>
    <td style="font-family:monospace;font-size:.72rem">${esc(f.file_path||'')}</td>
    <td>${f.auto_fix
      ? `<button class="fix-btn" id="fix-${esc(f.id)}" ${on('click', 'applyFix', f.id, '$this')} data-stop>Corregir</button>`
      : `<span style="font-size:.75rem;color:var(--text2)">Manual</span>`
    }</td>`;
  tbody.appendChild(tr);
  document.getElementById('malware-results')?.style && (document.getElementById('malware-results').style.display = '');
  document.getElementById('malware-empty') && (document.getElementById('malware-empty').style.display = 'none');
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
      if (d.error) { toast('✗ ' + d.error, 'error'); return; }
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
        <td>${f.auto_fix ? `<button class="fix-btn remote" ${on('click', 'applyFixRemote', f.id, host, '$this')} data-stop>Fix</button>` : ''}</td>`;
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
      <td>${d.has_ssh !== false ? `<button class="fix-btn remote" ${on('click', 'sshAuditOne', d.ip, d.ssh_port || 22)}>Auditar</button>` : ''}</td>`;
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
        <td>${f.auto_fix?`<button class="fix-btn remote" ${on('click', 'applyFixRemote', f.id, ip, '$this')} data-stop>Fix</button>`:''}</td>`;
      tbody.appendChild(tr);
    },
  });
}
