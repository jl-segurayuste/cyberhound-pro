// Scheduler, usuarios, supresiones, API keys, notificaciones, exportación, inicio, Docker, SIEM, ticketing y gráficos.
// Se cargan en orden (ver index.html); comparten el ámbito global como si fueran un solo fichero.
'use strict';

// ── Scheduler ─────────────────────────────────────────────────────────────
async function loadScheduler() {
  if (!hostAccess()) return;   // de la plataforma: un tenant recibiría 403
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
            ${on('click', 'toggleScheduler', e.name, !e.enabled, '$this')}>
            ${e.enabled ? 'Desactivar' : 'Activar'}
          </button>
          <button class="fix-btn" ${on('click', 'runSchedulerNow', e.name, '$this')}>▶ Ejecutar ahora</button>
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
  if (btnEl) { btnEl.disabled = true; btnEl.textContent = '…'; }
  const r = await fetch(`/api/scheduler/${encodeURIComponent(name)}/run`, {method: 'POST'});
  const d = await r.json();
  if (d.ok) { toast('✓ Tarea ejecutada'); loadScheduler(); }
  else toast('Error: ' + d.error, 'error');
  if (btnEl) { btnEl.disabled = false; btnEl.textContent = '▶ Ejecutar ahora'; }
}

// ── Usuarios ──────────────────────────────────────────────────────────────
async function loadUsers() {
  if (!USER.permissions.includes('users')) return;   // solo admin: evita el 403 al abrir Ajustes
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
          <select ${on('change', 'changeUserRole', u.username, '$value')} style="background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:3px 6px;border-radius:4px;font-size:.78rem">
            <option value="admin" ${u.role==='admin'?'selected':''}>admin</option>
            <option value="operator" ${u.role==='operator'?'selected':''}>operator</option>
            <option value="viewer" ${u.role==='viewer'?'selected':''}>viewer</option>
          </select>
          <button class="btn-secondary small" ${on('click', 'deleteUser', u.username)}>Borrar</button>
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
  else { toast('Error: ' + d.error, 'error'); loadUsers(); }  // el select volvería a mostrar un rol que no se aplicó
}

async function deleteUser(username) {
  if (!confirm(`¿Desactivar usuario "${username}"?`)) return;
  const r = await fetch(`/api/users/${encodeURIComponent(username)}`, {method: 'DELETE'});
  const d = await r.json();
  if (d.ok) { toast(`✓ Usuario ${username} desactivado`); loadUsers(); }
  else toast('Error: ' + d.error, 'error');
}

// ── Supresiones ───────────────────────────────────────────────────────────
async function loadSuppressions() {
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
        <td><button class="btn-secondary small" ${on('click', 'removeSuppression', s.finding_id_pattern)}>Eliminar</button></td>
      </tr>`).join('');
  } catch(e) { console.error('loadSuppressions:', e); }
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
  if (d.ok) { toast('✓ Supresión añadida'); loadSuppressions();
    document.getElementById('supp-pattern').value = '';
    document.getElementById('supp-reason').value = '';
  } else toast('Error: ' + d.error, 'error');
}

async function removeSuppression(pattern) {
  if (!confirm(`¿Eliminar supresión "${pattern}"?`)) return;
  const r = await fetch(`/api/suppressions/${encodeURIComponent(pattern)}`, {method: 'DELETE'});
  const d = await r.json();
  if (d.ok) { toast('✓ Supresión eliminada'); loadSuppressions(); }
  else toast('Error: ' + d.error, 'error');
}

// ── API Keys ──────────────────────────────────────────────────────────────
async function loadKeys() {
  if (!hostAccess()) return;   // de la plataforma: un tenant recibiría 403
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
  if (msg && d.error) { msg.textContent = '✗ ' + d.error; msg.style.color = 'var(--red)'; return; }
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
document.addEventListener('DOMContentLoaded', async () => {
  setStatus('idle', 'Listo');
  appendLog('info', 'CyberHound Pro iniciado.');
  await loadMe();   // antes de cargar nada: decide qué puede ver este usuario
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
  if (d.error) { msg.textContent = '✗ ' + d.error; msg.style.color = 'var(--red)'; return; }
  const results = Object.entries(d).map(([k,ok]) =>
    `${ok ? '✓' : '✗'} ${k}`
  ).join(' · ');
  msg.textContent = results || 'Sin SIEMs configurados';
  msg.style.color = Object.values(d).every(v=>v) ? 'var(--green)' : 'var(--yellow)';
}

// ── Ticketing config (Jira / ServiceNow) ────────────────────────────────────────
async function loadTicketing() {
  const r = await fetch('/api/config/ticketing');
  const d = await r.json();
  document.getElementById('tkt-jira-enabled').checked  = d.jira_enabled;
  document.getElementById('tkt-jira-url').value        = d.jira_url || '';
  document.getElementById('tkt-jira-email').value      = d.jira_email || '';
  document.getElementById('tkt-jira-project').value    = d.jira_project_key || '';
  document.getElementById('tkt-jira-issuetype').value  = d.jira_issue_type || 'Bug';
  document.getElementById('tkt-snow-enabled').checked  = d.servicenow_enabled;
  document.getElementById('tkt-snow-url').value        = d.servicenow_instance_url || '';
  document.getElementById('tkt-snow-user').value       = d.servicenow_user || '';
  document.getElementById('tkt-snow-table').value      = d.servicenow_table || 'incident';
  document.getElementById('tkt-min-severity').value    = d.min_severity || 'critical';
}

async function saveTicketing() {
  const body = {
    jira_enabled:       document.getElementById('tkt-jira-enabled').checked,
    jira_url:           document.getElementById('tkt-jira-url').value,
    jira_email:         document.getElementById('tkt-jira-email').value,
    jira_api_token:     document.getElementById('tkt-jira-token').value,
    jira_project_key:   document.getElementById('tkt-jira-project').value,
    jira_issue_type:    document.getElementById('tkt-jira-issuetype').value,
    servicenow_enabled:      document.getElementById('tkt-snow-enabled').checked,
    servicenow_instance_url: document.getElementById('tkt-snow-url').value,
    servicenow_user:         document.getElementById('tkt-snow-user').value,
    servicenow_password:     document.getElementById('tkt-snow-pass').value,
    servicenow_table:        document.getElementById('tkt-snow-table').value,
    min_severity: document.getElementById('tkt-min-severity').value,
  };
  const r = await fetch('/api/config/ticketing', {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)
  });
  const d = await r.json();
  const msg = document.getElementById('tkt-msg');
  msg.textContent  = d.ok ? '✓ Configuración de ticketing guardada' : '✗ Error: ' + d.error;
  msg.style.color  = d.ok ? 'var(--green)' : 'var(--red)';
  toast(d.ok ? '✓ Ticketing guardado' : '✗ Error: ' + d.error);
}

async function testTicketing() {
  const msg = document.getElementById('tkt-msg');
  msg.textContent = 'Creando ticket de prueba…';
  msg.style.color = 'var(--text2)';
  const r = await fetch('/api/config/ticketing/test', { method: 'POST' });
  const d = await r.json();
  if (d.error) { msg.textContent = '✗ ' + d.error; msg.style.color = 'var(--red)'; return; }
  const results = Object.entries(d).map(([k,ok]) =>
    `${ok ? '✓' : '✗'} ${k}`
  ).join(' · ');
  msg.textContent = results || 'Sin sistemas de ticketing configurados';
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
