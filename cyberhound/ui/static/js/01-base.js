// Núcleo: estado, utilidades, eventos sin JS inline, roles, navegación, log y WebSocket.
// Se cargan en orden (ver index.html); comparten el ámbito global como si fueran un solo fichero.
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

// ── Eventos sin JS inline ─────────────────────────────────────────────────
// La CSP no permite atributos on*: los controles declaran data-on-<evento>="función"
// y data-args-<evento>='[...]' ("$this" = el elemento, "$value" = su valor,
// "$event" = el evento); data-stop corta la propagación y data-key filtra la tecla.
const _EVENT_TYPES = ['click', 'change', 'input', 'keydown'];

function on(type, fn, ...args) {
  return `data-on-${type}="${esc(fn)}"` + (args.length ? ` data-args-${type}="${esc(JSON.stringify(args))}"` : '');
}

function _dispatch(ev) {
  const sel = `[data-on-${ev.type}]`;
  // Fase de captura + recorrido de dentro a fuera: mismo orden que el burbujeo de
  // los antiguos onclick, y data-stop sigue impidiendo que salte el tr.onclick de la fila.
  for (let el = ev.target.closest?.(sel); el; el = el.parentElement?.closest(sel)) {
    const key = el.getAttribute('data-key');
    if (key && ev.key !== key) continue;
    const name = el.getAttribute(`data-on-${ev.type}`);
    const fn = window[name];
    if (typeof fn !== 'function') { console.error(`Manejador no definido: ${name}`); continue; }
    if (!canDo(name)) { toast(`Tu rol (${USER.role}) no permite esta acción`, 'error'); ev.stopPropagation(); break; }
    const raw = JSON.parse(el.getAttribute(`data-args-${ev.type}`) || '[]');
    fn(...raw.map(a => a === '$this' ? el : a === '$value' ? el.value : a === '$event' ? ev : a));
    if (el.hasAttribute('data-stop')) { ev.stopPropagation(); break; }
  }
}
_EVENT_TYPES.forEach(t => document.addEventListener(t, _dispatch, true));

// ── Roles ─────────────────────────────────────────────────────────────────
// Permiso de ROLE_PERMISSIONS (servidor) que exige cada acción de la interfaz. El
// servidor es quien lo hace cumplir; aquí solo se desactiva lo que daría 403.
// tests/test_frontend_integrity.py comprueba que coincide con _required_permission.
const FN_PERMS = {
  applyFix: 'fix', applyFixRemote: 'fix', fixAll: 'fix', deleteQuarantine: 'fix', restoreQuarantine: 'fix',
  runAnsiblePlaybook: 'fix',
  quickAudit: 'scan', quickDocker: 'scan', quickMalware: 'scan', quickNetwork: 'scan', runAudit: 'scan',
  runAPISecurityScan: 'scan', runCode: 'scan', runDNSScan: 'scan', runDocker: 'scan', runDockerImageScan: 'scan',
  runIntelScan: 'scan', runLDAPScan: 'scan', runMalware: 'scan', runNetworkScan: 'scan', runNucleiScan: 'scan',
  runRuntimeScan: 'scan', runSchedulerNow: 'scan', runServicesAudit: 'scan', runSubdomainScan: 'scan',
  runTLSScan: 'scan', runWebExposureScan: 'scan', runWebHeadersScan: 'scan', sshAuditOne: 'scan',
  explainFinding: 'scan', downloadSBOM: 'scan', generateSBOM: 'scan', importAuditFile: 'scan', loadCompliance: 'scan',
  addSuppression: 'config', removeSuppression: 'config', suppressFinding: 'config', toggleScheduler: 'config',
  saveAgentConfig: 'config', saveKeys: 'config', saveNotifications: 'config', saveSIEM: 'config',
  saveTicketing: 'config', testNotifications: 'config', testSIEM: 'config', testTicketing: 'config',
  updateYaraRules: 'config',
  discoverOnly: 'scan', createTenant: 'users', deleteTenant: 'users', rotateTenantKey: 'users',
  changeUserRole: 'users', createUser: 'users', deleteUser: 'users', loadUsers: 'users',
  loadAudit: 'users', saveTenantScope: 'users', undoFixRemote: 'fix', loadRemoteFixes: 'fix',
  createSchedule: 'config', toggleSchedule: 'config', deleteSchedule: 'config', runSchedule: 'scan',
  createSshCredential: 'config', deleteSshCredential: 'config',
};
// Acciones sobre el propio servidor o su configuración global: en multi-tenant solo el
// superadmin (HOST_TASKS y _PLATFORM_PREFIXES del servidor; lo comprueba test_consistency)
const HOST_FNS = new Set([
  'applyFix', 'fixAll', 'quickAudit', 'quickMalware', 'quickDocker', 'runAudit', 'runMalware', 'runDocker',
  'runCode', 'runServicesAudit', 'runRuntimeScan', 'runDockerImageScan', 'generateSBOM', 'downloadSBOM',
  'deleteQuarantine', 'restoreQuarantine', 'runAnsiblePlaybook', 'updateYaraRules',
  'saveKeys',
  'toggleScheduler', 'runSchedulerNow', 'saveAgentConfig',
  'loadKeys', 'loadMonitorStatus', 'loadSBOM', 'loadScheduler', 'loadYaraRules',   // botones "↻ Cargar"
]);
const HOST_PANELS = ['audit', 'malware', 'docker', 'code', 'services', 'monitor'];
// Notificaciones, SIEM y ticketing no están: cada organización tiene los suyos
const HOST_CFG_TABS = ['keys', 'scheduler', 'yara', 'quarantine', 'sbom', 'ansible'];
let USER = { username: '', role: 'admin', permissions: ['scan', 'fix', 'config', 'users', 'view'],
             host_access: true, superadmin: true, multi_tenant: false, tenant: 'default' };

function hostAccess() { return USER.host_access !== false; }
function canDo(fn) {
  const p = FN_PERMS[fn];
  return (!p || USER.permissions.includes(p)) && (hostAccess() || !HOST_FNS.has(fn));
}

function applyRole(root = document) {
  if (!root.querySelectorAll) return;
  root.querySelectorAll('[data-on-click],[data-on-change]').forEach(el => {
    const fn = el.getAttribute('data-on-click') || el.getAttribute('data-on-change');
    if (canDo(fn)) return;
    el.disabled = true;
    el.classList.add('role-locked');
    el.title = `Tu rol (${USER.role}) no permite esta acción`;
  });
  if (!USER.permissions.includes('users')) document.querySelectorAll('[data-cfg="users"],[data-cfg="audit"]').forEach(el => el.hidden = true);
  if (!USER.permissions.includes('fix')) document.querySelectorAll('[data-cfg="remotefixes"]').forEach(el => el.hidden = true);
  if (!hostAccess()) {
    HOST_PANELS.forEach(n => document.querySelectorAll(`.nav-tab[data-panel="${n}"]`).forEach(el => el.hidden = true));
    HOST_CFG_TABS.forEach(n => document.querySelectorAll(`[data-cfg="${n}"]`).forEach(el => el.hidden = true));
    const mode = document.getElementById('agent-mode-card'); if (mode) mode.hidden = true;
    const sys = document.getElementById('dash-system-status')?.closest('.dash-card'); if (sys) sys.hidden = true;
    // un grupo del menú sin entradas visibles tampoco se muestra
    document.querySelectorAll('.nav-group').forEach(g => {
      g.hidden = ![...g.querySelectorAll('.nav-tab')].some(t => !t.hidden);
    });
  }
}

async function loadMe() {
  try {
    const r = await fetch('/api/me');
    if (!r.ok) return;
    USER = await r.json();
  } catch { return; }
  document.body.dataset.role = USER.role;
  const who = document.getElementById('user-role-badge');
  if (who) who.textContent = USER.multi_tenant
    ? `${USER.username} · ${USER.role} · ${USER.tenant_name}` : `${USER.username} · ${USER.role}`;
  applyRole();
  if (USER.multi_tenant && USER.superadmin) {
    document.querySelectorAll('[data-cfg="tenants"]').forEach(el => el.hidden = false);
    loadTenantSwitch();
  }
  new MutationObserver(ms => ms.forEach(m => m.addedNodes.forEach(n => applyRole(n.parentNode || n))))
    .observe(document.body, { childList: true, subtree: true });
}

function hideEl(id) { const el = document.getElementById(id); if (el) el.style.display = 'none'; }

function toast(msg, type = 'info') {
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
}

function btn(id, disabled, label) {
  const b = document.getElementById(id);
  if (b) { b.disabled = disabled; if (label) b.textContent = label; }
}

// ── Navegación ────────────────────────────────────────────────────────────
function showPanel(name) {
  if (!hostAccess() && HOST_PANELS.includes(name)) name = 'dashboard';
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
  document.getElementById('panel-' + name)?.classList.add('active');
  document.querySelector(`[data-panel="${name}"]`)?.classList.add('active');
  closeDrawer();
  // ── Carga de datos — lista única y definitiva (sin monkey-patching) ─────────
  const _panelLoaders = {
    dashboard: () => loadDashboard(),
    history:   () => { loadHistory(); loadAgentFilterOptions(); },
    settings:  () => {
      loadKeys(); loadNotifications(); loadScheduler(); loadSuppressions(); loadUsers();
      // si la pestaña activa no está disponible para este usuario, abrir la primera que sí
      const act = document.querySelector('#panel-settings .cfg-tab.active');
      if (!act || act.hidden) {
        const first = [...document.querySelectorAll('#panel-settings .cfg-tab')].find(t => !t.hidden);
        if (first) showCfgTab(first.dataset.cfg);
      }
    },
    monitor:   () => { loadMonitorStatus(); loadMonitorHistory(); },
    intel:     () => loadIntelConfig(),
    network:   () => loadSshCredOptions(),
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
    ticketing:    () => loadTicketing(),
    users:        () => loadUsers(),
    suppressions: () => loadSuppressions(),
    scheduler:    () => loadScheduler(),
    '2fa':        () => load2FAStatus(),
    yara:         () => loadYaraRules(),
    agents:       () => { loadAgents(); loadAgentConfig(); loadTenantAgentKey(); },
    tenants:      () => loadTenants(),
    notifications: () => loadNotifications(),
    account:      () => { loadSessions(); loadApiTokens(); },
    schedules:    () => loadSchedules(),
    sshcreds:     () => loadSshCredentials(),
    remotefixes:  () => loadRemoteFixes(),
    audit:        () => loadAudit(),
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
