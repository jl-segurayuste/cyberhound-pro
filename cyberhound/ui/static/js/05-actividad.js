// Panel de actividad en tiempo real y análisis que lo alimentan.
// Se cargan en orden (ver index.html); comparten el ámbito global como si fueran un solo fichero.
'use strict';

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

// ── Análisis que alimentan el panel de actividad (wsRunWithActivity) ──

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
      _appendAuditRow(f);
    },
    onDone(msg) {
      btn('btn-audit', false, '▶ Iniciar análisis completo');
      document.getElementById('audit-results').style.display = '';
      document.getElementById('audit-empty').style.display = 'none';
      _renderSummary('audit-summary-bar', S.findings.audit);
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
      _appendMalwareRow(f);
    },
    onDone() {
      btn('btn-malware', false, '▶ Iniciar escaneo');
      document.getElementById('malware-results').style.display = '';
      document.getElementById('malware-empty').style.display = 'none';
      _renderSummary('malware-summary-bar', S.findings.malware);
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
        _renderSummary('docker-summary-bar', S.findings.docker);
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
