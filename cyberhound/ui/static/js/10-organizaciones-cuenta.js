// Organizaciones, mi cuenta, programados, fixes remotos, auditoría y ámbito.
// Se cargan en orden (ver index.html); comparten el ámbito global como si fueran un solo fichero.
'use strict';

// ── Multi-tenant ──────────────────────────────────────────────────────────────
async function loadTenantSwitch() {
  const sel = document.getElementById('tenant-switch');
  if (!sel) return;
  try {
    const r = await fetch('/api/tenants');
    if (!r.ok) return;
    const tenants = await r.json();
    sel.innerHTML = '<option value="default">Plataforma</option>' +
      tenants.map(t => `<option value="${esc(t.slug)}">${esc(t.name)}</option>`).join('');
    sel.value = USER.tenant;
    sel.hidden = false;
  } catch { /* sin selector */ }
}

async function switchTenant(slug) {
  const r = await fetch('/api/tenant/switch', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({slug}),
  });
  if (r.ok) location.reload();
  else toast('Error: ' + ((await r.json()).error || r.status), 'error');
}

async function loadTenants() {
  const tbody = document.getElementById('tenants-tbody');
  if (!tbody || !(USER.multi_tenant && USER.superadmin)) return;
  try {
    const tenants = await fetch('/api/tenants').then(r => r.json());
    tbody.innerHTML = tenants.length ? tenants.map(t => `<tr>
        <td style="font-family:monospace">${esc(t.slug)}</td><td>${esc(t.name)}</td>
        <td style="font-size:.78rem;color:var(--text2)">${fmt(t.created_at)}</td>
        <td style="white-space:nowrap"><input type="text" id="scope-${esc(t.slug)}" value="${esc((t.allowed_targets || []).join(', '))}"
              placeholder="10.10.0.0/24, ejemplo-demo.es" style="min-width:220px">
          <button class="btn-secondary small" ${on('click', 'saveTenantScope', t.slug)}>Guardar</button></td>
        <td style="white-space:nowrap">
          <button class="btn-secondary small" ${on('click', 'rotateTenantKey', t.slug)}>Nueva clave</button>
          <button class="btn-secondary small danger" ${on('click', 'deleteTenant', t.slug)}>Dar de baja</button>
        </td></tr>`).join('')
      : '<tr><td colspan="5" style="color:var(--text2)">Sin organizaciones todavía.</td></tr>';
  } catch (e) { tbody.innerHTML = `<tr><td colspan="5">Error: ${esc(e.message)}</td></tr>`; }
}

async function createTenant() {
  const val = id => document.getElementById(id)?.value.trim() || '';
  const msg = document.getElementById('tenant-msg');
  const body = { slug: val('tenant-slug').toLowerCase(), name: val('tenant-name'), admin_email: val('tenant-email'),
                 plan: val('tenant-plan') || 'starter', admin_username: val('tenant-admin-user'),
                 admin_password: document.getElementById('tenant-admin-pass')?.value || '' };
  if (!body.slug || !body.name) {
    msg.style.color = 'var(--yellow)'; msg.textContent = 'Indica el identificador y el nombre'; return;
  }
  const r = await fetch('/api/tenants', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
  });
  const d = await r.json();
  if (!r.ok) { msg.style.color = 'var(--red)'; msg.textContent = '✗ ' + (d.error || r.status); return; }
  msg.style.color = 'var(--green)';
  msg.innerHTML = `✓ Creada <b>${esc(d.slug)}</b>. Clave de agente (guárdala, no se vuelve a mostrar aquí):` +
                  `<br><code style="word-break:break-all">${esc(d.api_key)}</code>`;
  ['tenant-slug', 'tenant-name', 'tenant-email', 'tenant-admin-user', 'tenant-admin-pass']
    .forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
  loadTenants(); loadTenantSwitch();
}

async function deleteTenant(slug) {
  if (!confirm(`¿Dar de baja la organización "${slug}"? Sus usuarios dejarán de poder entrar; los datos se archivan.`)) return;
  const r = await fetch(`/api/tenants/${encodeURIComponent(slug)}`, {method: 'DELETE'});
  if (r.ok) { toast('✓ Organización dada de baja'); loadTenants(); loadTenantSwitch(); }
  else toast('Error: ' + ((await r.json()).error || r.status), 'error');
}

async function rotateTenantKey(slug) {
  const r = await fetch(`/api/tenants/${encodeURIComponent(slug)}/rotate-key`, {method: 'POST'});
  const d = await r.json();
  const msg = document.getElementById('tenant-msg');
  if (!r.ok) { toast('Error: ' + (d.error || r.status), 'error'); return; }
  msg.style.color = 'var(--green)';
  msg.innerHTML = `✓ Nueva clave de agente de <b>${esc(slug)}</b> (la anterior deja de valer):` +
                  `<br><code style="word-break:break-all">${esc(d.api_key)}</code>`;
}

async function loadTenantAgentKey() {
  const card = document.getElementById('tenant-agent-key-card');
  if (!card || !USER.multi_tenant || USER.tenant === 'default' || USER.role !== 'admin') return;
  try {
    const r = await fetch('/api/tenant/agent-key');
    if (!r.ok) return;
    document.getElementById('tenant-agent-key').textContent = (await r.json()).api_key;
    card.hidden = false;
  } catch { /* sin clave */ }
}

// ── Mi cuenta: contraseña, sesiones y tokens de API ───────────────────────
function _msg(id, ok, text) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.color = ok ? 'var(--green)' : 'var(--red)';
  el.textContent = (ok ? '✓ ' : '✗ ') + text;
}

async function changeMyPassword() {
  const val = id => document.getElementById(id)?.value || '';
  if (val('acct-pw-new') !== val('acct-pw-new2')) { _msg('acct-pw-msg', false, 'Las dos contraseñas nuevas no coinciden'); return; }
  const r = await fetch('/api/me/password', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({current: val('acct-pw-current'), new: val('acct-pw-new')}),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) { _msg('acct-pw-msg', false, d.error || r.status); return; }
  ['acct-pw-current', 'acct-pw-new', 'acct-pw-new2'].forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
  _msg('acct-pw-msg', true, `Contraseña cambiada (${d.sessions_closed} sesiones cerradas)`);
  loadSessions();
}

async function loadSessions() {
  const tbody = document.getElementById('sessions-tbody');
  if (!tbody) return;
  const r = await fetch('/api/sessions');
  if (!r.ok) { tbody.innerHTML = '<tr><td colspan="4" style="color:var(--text2)">Solo con una sesión de navegador</td></tr>'; return; }
  const rows = await r.json().catch(() => null);
  if (!Array.isArray(rows)) { tbody.innerHTML = ''; return; }
  tbody.innerHTML = rows.map(s => `<tr>
      <td style="font-size:.78rem">${fmt(s.last_seen)}${s.current ? ' <b>(esta)</b>' : ''}</td>
      <td style="font-family:monospace;font-size:.78rem">${esc(s.ip)}</td>
      <td style="font-size:.72rem;color:var(--text2);max-width:260px;overflow:hidden;text-overflow:ellipsis">${esc(s.user_agent)}</td>
      <td><button class="btn-secondary small danger" ${on('click', 'revokeSession', s.id, s.current)}>${s.current ? 'Salir' : 'Cerrar'}</button></td>
    </tr>`).join('') || '<tr><td colspan="4" style="color:var(--text2)">Sin sesiones</td></tr>';
}

async function revokeSession(id, current) {
  const r = await fetch(`/api/sessions/${encodeURIComponent(id)}`, {method: 'DELETE'});
  if (current && r.ok) { location.href = '/login'; return; }
  const d = await r.json().catch(() => ({}));
  _msg('sessions-msg', r.ok, r.ok ? 'Sesión cerrada' : (d.error || r.status));
  loadSessions();
}

async function revokeOtherSessions() {
  const r = await fetch('/api/sessions/revoke-others', {method: 'POST'});
  const d = await r.json().catch(() => ({}));
  _msg('sessions-msg', r.ok, r.ok ? `${d.closed} sesiones cerradas` : (d.error || r.status));
  loadSessions();
}

async function loadApiTokens() {
  const tbody = document.getElementById('tokens-tbody');
  if (!tbody) return;
  const r = await fetch('/api/tokens');
  if (!r.ok) { tbody.innerHTML = ''; return; }
  const rows = await r.json().catch(() => null);
  if (!Array.isArray(rows)) { tbody.innerHTML = ''; return; }
  tbody.innerHTML = rows.map(t => `<tr>
      <td>${esc(t.name)}</td><td>${esc(t.role)}</td>
      <td style="font-size:.78rem">${t.expires_at ? fmt(t.expires_at) : 'nunca'}</td>
      <td style="font-size:.78rem">${t.last_used ? fmt(t.last_used) : '—'}</td>
      <td><button class="btn-secondary small danger" ${on('click', 'revokeApiToken', t.id)}>Revocar</button></td>
    </tr>`).join('') || '<tr><td colspan="5" style="color:var(--text2)">Sin tokens</td></tr>';
}

async function createApiToken() {
  const name = document.getElementById('token-name')?.value.trim() || '';
  const box = document.getElementById('token-new');
  const r = await fetch('/api/tokens', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({name, role: document.getElementById('token-role')?.value,
                          expires_days: parseInt(document.getElementById('token-days')?.value || '90', 10)}),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) { box.style.color = 'var(--red)'; box.textContent = '✗ ' + (d.error || r.status); return; }
  box.style.color = 'var(--green)';
  box.innerHTML = '✓ Token creado. Cópialo ahora, no se vuelve a mostrar:<br>' +
                  `<code style="word-break:break-all">${esc(d.token)}</code>`;
  document.getElementById('token-name').value = '';
  loadApiTokens();
}

async function revokeApiToken(id) {
  const r = await fetch(`/api/tokens/${encodeURIComponent(id)}`, {method: 'DELETE'});
  toast(r.ok ? '✓ Token revocado' : '✗ No se pudo revocar', r.ok ? 'info' : 'error');
  loadApiTokens();
}

// ── Análisis programados ──────────────────────────────────────────────────
const SCHED_TASKS = {web_headers: 'Cabeceras web', web_exposure: 'Exposición web', api_security: 'API / CORS',
                     tls: 'TLS', dns: 'DNS', subdomain_enum: 'Subdominios', nuclei: 'Nuclei', network: 'Red',
                     ssh: 'Auditoría SSH'};
const DAY_NAMES = ['L', 'M', 'X', 'J', 'V', 'S', 'D'];

async function loadSchedules() {
  const tbody = document.getElementById('schedules-tbody');
  if (!tbody) return;
  loadSshCredOptions();
  const r = await fetch('/api/schedules');
  if (!r.ok) { tbody.innerHTML = ''; return; }
  const rows = await r.json().catch(() => null);
  if (!Array.isArray(rows)) { tbody.innerHTML = ''; return; }
  const pad = n => String(n).padStart(2, '0');
  tbody.innerHTML = rows.map(s => `<tr>
      <td>${esc(s.name)}<div style="font-size:.72rem;color:var(--text2)">${esc(s.targets.join(', '))}</div></td>
      <td>${esc(SCHED_TASKS[s.task] || s.task)}${s.ssh_credential ? '<div style="font-size:.72rem;color:var(--text2)">con credencial SSH</div>' : ''}</td>
      <td style="font-size:.78rem">${pad(s.hour)}:${pad(s.minute)} · ${s.days.length === 7 ? 'todos los días' : s.days.map(d => DAY_NAMES[d]).join(' ')}</td>
      <td style="font-size:.78rem">${s.running ? 'en curso…' : (s.last_run ? `${fmt(s.last_run)} · ${esc(s.last_status)}` : '—')}</td>
      <td style="white-space:nowrap">
        <button class="fix-btn" ${on('click', 'runSchedule', s.id)} ${s.running ? 'disabled title="En curso"' : ''}>▶ Ahora</button>
        <button class="toggle-btn ${s.enabled ? 'active' : ''}" ${on('click', 'toggleSchedule', s.id, !s.enabled)}>${s.enabled ? 'Pausar' : 'Reanudar'}</button>
        <button class="btn-secondary small danger" ${on('click', 'deleteSchedule', s.id)}>Borrar</button>
      </td></tr>`).join('') || '<tr><td colspan="5" style="color:var(--text2)">Sin análisis programados</td></tr>';
}

async function createSchedule() {
  const val = id => document.getElementById(id)?.value || '';
  const body = {
    name: val('sched-name').trim(), task: val('sched-task'),
    targets: val('sched-targets').split(',').map(t => t.trim()).filter(Boolean),
    hour: parseInt(val('sched-hour'), 10), minute: parseInt(val('sched-minute'), 10),
    days: [...document.querySelectorAll('.sched-day:checked')].map(el => parseInt(el.value, 10)),
    ssh_credential: val('sched-cred') || null,
  };
  const r = await fetch('/api/schedules', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
  });
  const d = await r.json().catch(() => ({}));
  _msg('sched-msg', r.ok, r.ok ? `Programado: ${d.name}` : (d.error || r.status));
  if (r.ok) { document.getElementById('sched-name').value = ''; document.getElementById('sched-targets').value = ''; }
  loadSchedules();
}

async function runSchedule(id) {
  const r = await fetch(`/api/schedules/${encodeURIComponent(id)}/run`, {method: 'POST'});
  const d = await r.json().catch(() => ({}));
  toast(r.ok ? '▶ Análisis lanzado en segundo plano' : '✗ ' + (d.error || r.status), r.ok ? 'info' : 'error');
  loadSchedules();
}

async function toggleSchedule(id, enabled) {
  await fetch(`/api/schedules/${encodeURIComponent(id)}`, {
    method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({enabled}),
  });
  loadSchedules();
}

async function deleteSchedule(id) {
  if (!confirm('¿Borrar esta programación?')) return;
  await fetch(`/api/schedules/${encodeURIComponent(id)}`, {method: 'DELETE'});
  loadSchedules();
}

// ── Credenciales SSH guardadas ────────────────────────────────────────────
// Lo que se manda al servidor para entrar por SSH: una credencial guardada o lo escrito en el panel Red
function sshCredFields(port) {
  const cred = document.getElementById('net-cred')?.value || '';
  if (cred) return {ssh_credential: cred};
  return {
    ssh_user: document.getElementById('net-user')?.value || 'root',
    ssh_port: port || document.getElementById('net-port')?.value || '22',
    ssh_key:  document.getElementById('net-key')?.value || '',
    ssh_password: document.getElementById('net-pass')?.value || '',
  };
}

function onSshCredChange() {
  const box = document.getElementById('net-manual-creds');
  // display:contents: sus campos siguen siendo parte de la fila del formulario (hidden no puede con él)
  if (box) box.style.display = document.getElementById('net-cred')?.value ? 'none' : 'contents';
}

function onSshCredKindChange() {
  const kind = document.getElementById('sshcred-kind')?.value;
  document.getElementById('sshcred-key-fields').hidden = kind !== 'key';
  document.getElementById('sshcred-pass-fields').hidden = kind !== 'password';
}

// Rellena los desplegables de credencial (panel Red y Programados) sin perder lo elegido
async function loadSshCredOptions() {
  const r = await fetch('/api/config/ssh-credentials');
  const rows = r.ok ? await r.json().catch(() => null) : null;
  if (!Array.isArray(rows)) return [];
  for (const [id, empty] of [['net-cred', 'Escribir usuario y clave o contraseña'], ['sched-cred', 'Ninguna']]) {
    const sel = document.getElementById(id);
    if (!sel) continue;
    const keep = sel.value;
    sel.innerHTML = `<option value="">${empty}</option>` + rows.map(c =>
      `<option value="${esc(c.id)}">${esc(c.name)} (${esc(c.username)}, puerto ${c.port})</option>`).join('');
    sel.value = rows.some(c => c.id === keep) ? keep : '';
  }
  onSshCredChange();
  return rows;
}

async function loadSshCredentials() {
  const tbody = document.getElementById('sshcreds-tbody');
  if (!tbody) return;
  loadSshHostKeys();
  const rows = await loadSshCredOptions();
  tbody.innerHTML = rows.map(c => `<tr>
      <td>${esc(c.name)}${c.kind === 'key' ? `<details style="font-size:.72rem;color:var(--text2)"><summary>${esc(c.fingerprint)}</summary>
        <code style="word-break:break-all;user-select:all">${esc(c.public_key)}</code></details>` : ''}</td>
      <td style="font-family:monospace">${esc(c.username)}:${c.port}</td>
      <td>${c.kind === 'key' ? 'Clave' : 'Contraseña'}</td>
      <td style="font-size:.78rem">${c.last_used ? fmt(c.last_used) : '—'}</td>
      <td><button class="btn-secondary small danger" ${on('click', 'deleteSshCredential', c.id)}>Borrar</button></td>
    </tr>`).join('') || '<tr><td colspan="5" style="color:var(--text2)">Sin credenciales guardadas</td></tr>';
  applyRole(tbody);
}

async function loadSshHostKeys() {
  const tbody = document.getElementById('sshhostkeys-tbody');
  if (!tbody) return;
  const r = await fetch('/api/config/ssh-host-keys');
  const rows = r.ok ? await r.json().catch(() => null) : null;
  if (!Array.isArray(rows)) { tbody.innerHTML = ''; return; }
  tbody.innerHTML = rows.map(k => `<tr>
      <td style="font-family:monospace">${esc(k.host)}:${k.port}</td>
      <td style="font-family:monospace;font-size:.72rem;word-break:break-all">${esc(k.fingerprint)}</td>
      <td style="font-size:.78rem">${fmt(k.first_seen)}</td>
      <td style="font-size:.78rem">${k.last_seen ? fmt(k.last_seen) : '—'}</td>
      <td><button class="btn-secondary small danger" ${on('click', 'forgetSshHostKey', k.host, k.port)}>Olvidar</button></td>
    </tr>`).join('') || '<tr><td colspan="5" style="color:var(--text2)">Ninguna todavía: se guardan al conectar por primera vez</td></tr>';
  applyRole(tbody);
}

async function forgetSshHostKey(host, port) {
  if (!confirm(`¿Olvidar la clave de host de ${host}:${port}? La próxima conexión guardará la que presente.`)) return;
  const r = await fetch(`/api/config/ssh-host-keys/${encodeURIComponent(host)}/${encodeURIComponent(port)}`, {method: 'DELETE'});
  const d = await r.json().catch(() => ({}));
  toast(r.ok ? '✓ Clave de host olvidada' : '✗ ' + (d.error || r.status), r.ok ? 'info' : 'error');
  loadSshHostKeys();
}

async function createSshCredential() {
  const val = id => document.getElementById(id)?.value || '';
  const kind = val('sshcred-kind');
  const body = {name: val('sshcred-name').trim(), username: val('sshcred-user').trim(),
                port: parseInt(val('sshcred-port') || '22', 10), kind};
  if (kind === 'key') Object.assign(body, {private_key: val('sshcred-key'), passphrase: val('sshcred-passphrase')});
  if (kind === 'password') body.password = val('sshcred-password');
  const r = await fetch('/api/config/ssh-credentials', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
  });
  const d = await r.json().catch(() => ({}));
  const box = document.getElementById('sshcred-msg');
  if (!r.ok) { _msg('sshcred-msg', false, d.error || r.status); return; }
  ['sshcred-name', 'sshcred-key', 'sshcred-passphrase', 'sshcred-password'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = '';
  });
  if (d.kind === 'key' && kind === 'generate') {
    box.style.color = 'var(--green)';
    box.innerHTML = `✓ Guardada. Añade esta clave pública a <code>~/.ssh/authorized_keys</code> de ` +
                    `<b>${esc(d.username)}</b> en cada equipo:<br><code style="word-break:break-all;user-select:all">${esc(d.public_key)}</code>`;
  } else {
    _msg('sshcred-msg', true, `Guardada: ${d.name}`);
  }
  loadSshCredentials();
}

async function deleteSshCredential(id) {
  if (!confirm('¿Borrar esta credencial SSH?')) return;
  const r = await fetch(`/api/config/ssh-credentials/${encodeURIComponent(id)}`, {method: 'DELETE'});
  const d = await r.json().catch(() => ({}));
  toast(r.ok ? '✓ Credencial borrada' : '✗ ' + (d.error || r.status), r.ok ? 'info' : 'error');
  loadSshCredentials();
}

// ── Fixes remotos aplicados ───────────────────────────────────────────────
async function loadRemoteFixes() {
  const tbody = document.getElementById('remote-fixes-tbody');
  if (!tbody || !USER.permissions.includes('fix')) return;
  const r = await fetch('/api/fix/remote/history');
  if (!r.ok) { tbody.innerHTML = ''; return; }
  const rows = await r.json().catch(() => null);
  if (!Array.isArray(rows)) { tbody.innerHTML = ''; return; }
  tbody.innerHTML = rows.map(f => `<tr>
      <td style="font-size:.78rem">${fmt(f.ts)}</td>
      <td style="font-family:monospace">${esc(f.host)}</td>
      <td style="font-size:.78rem">${esc(f.finding_id.split('::').pop())}</td>
      <td>${esc(f.username)}</td>
      <td style="font-size:.78rem">${f.undone_at ? `deshecho por ${esc(f.undone_by)}` : (f.undo ? 'aplicado' : 'aplicado (sin deshacer)')}</td>
      <td>${f.reversible ? `<button class="fix-btn" ${on('click', 'undoFixRemote', f.id, f.host, '$this')}>↶ Deshacer</button>` : ''}</td>
    </tr>`).join('') || '<tr><td colspan="6" style="color:var(--text2)">Ningún fix remoto todavía</td></tr>';
}

// ── Registro de auditoría ─────────────────────────────────────────────────
async function loadAudit() {
  if (!USER.permissions.includes('users')) return;
  const tbody = document.getElementById('auditlog-tbody');
  if (!tbody) return;
  const q = new URLSearchParams();
  const val = id => document.getElementById(id)?.value.trim() || '';
  if (val('auditlog-action')) q.set('action', val('auditlog-action'));
  if (val('auditlog-user')) q.set('user', val('auditlog-user'));
  if (val('auditlog-q')) q.set('q', val('auditlog-q'));
  if (document.getElementById('auditlog-failures')?.checked) q.set('failures', '1');
  const r = await fetch('/api/audit?' + q.toString());
  if (!r.ok) { tbody.innerHTML = ''; return; }
  const rows = await r.json().catch(() => null);
  if (!Array.isArray(rows)) { tbody.innerHTML = ''; return; }
  tbody.innerHTML = rows.map(e => `<tr style="${e.ok ? '' : 'color:var(--red)'}">
      <td style="font-size:.75rem;white-space:nowrap">${fmt(e.ts)}</td><td>${esc(e.username)}</td>
      <td style="font-family:monospace;font-size:.78rem">${esc(e.action)}${e.ok ? '' : ' ✗'}</td>
      <td style="font-size:.78rem">${esc(e.target)}</td><td style="font-size:.75rem;color:var(--text2)">${esc(e.detail)}</td>
      <td style="font-family:monospace;font-size:.75rem">${esc(e.ip)}</td></tr>`).join('')
    || '<tr><td colspan="6" style="color:var(--text2)">Sin eventos</td></tr>';
}

// ── Ámbito de cada organización (superadmin) ──────────────────────────────
async function saveTenantScope(slug) {
  const raw = document.getElementById(`scope-${slug}`)?.value || '';
  const r = await fetch(`/api/tenants/${encodeURIComponent(slug)}`, {
    method: 'PATCH', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({allowed_targets: raw.split(/[\s,]+/).filter(Boolean)}),
  });
  const d = await r.json().catch(() => ({}));
  toast(r.ok ? `✓ Ámbito de ${slug}: ${d.allowed_targets.length} entradas` : '✗ ' + (d.error || r.status), r.ok ? 'info' : 'error');
  if (r.ok) loadTenants();
}
