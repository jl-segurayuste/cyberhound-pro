// Servicios, 2FA, YARA, historial con agentes, canal push y LDAP.
// Se cargan en orden (ver index.html); comparten el ámbito global como si fueran un solo fichero.
'use strict';

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
        _renderSummary('services-summary-bar', S.findings.services);
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
        _renderSummary('tls-summary-bar', S.findings.tls);
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
        _renderSummary('webhdr-summary-bar', S.findings.webhdr);
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
        _renderSummary('webexp-summary-bar', S.findings.webexp);
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
        _renderSummary('apisec-summary-bar', S.findings.apisec);
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
        _renderSummary('dnssec-summary-bar', S.findings.dnssec);
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
        _renderSummary('subenum-summary-bar', S.findings.subenum);
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
        _renderSummary('nuclei-summary-bar', S.findings.nuclei);
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
      if (disableBtn) disableBtn.style.display = 'inline-flex';
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
  const code = document.getElementById('2fa-disable-code')?.value.trim();
  if (!code) { toast('Escribe un código de tu app (o uno de recuperación) para desactivarlo', 'error'); return; }
  if (!confirm('¿Seguro que quieres desactivar el 2FA? Tu cuenta quedará menos protegida.')) return;
  const r = await fetch('/api/auth/2fa/disable', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({code}),
  });
  const d = await r.json();
  if (d.ok) {
    toast('2FA desactivado');
    document.getElementById('2fa-disable-code').value = '';
    await load2FAStatus();
  } else toast('Error: ' + (d.error || r.status), 'error');
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
  if (!hostAccess()) return;   // de la plataforma: un tenant recibiría 403
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
// Muestra/oculta los campos de "manager" según el modo elegido.
function _toggleAgentFields() {
  const mode = document.getElementById('agent-mode')?.value;
  const f = document.getElementById('agent-manager-fields');
  if (f) f.style.display = (mode === 'agent') ? '' : 'none';
}

// Carga la configuración actual del modo agente en el formulario.
async function loadAgentConfig() {
  if (!hostAccess()) return;   // de la plataforma: un tenant recibiría 403
  try {
    const a = await fetch('/api/config/agent').then(r => r.json());
    const sel = document.getElementById('agent-mode');         if (sel) sel.value = a.mode || 'standalone';
    const mu  = document.getElementById('agent-manager-url');  if (mu)  mu.value  = a.manager_url || '';
    const an  = document.getElementById('agent-name');         if (an)  an.value  = a.agent_name || '';
    const badge = document.getElementById('agent-mode-badge'); if (badge) badge.textContent = a.mode || 'standalone';
    const key = document.getElementById('agent-key');          if (key && a.has_key) key.placeholder = '•••••• (sin cambios)';
    _toggleAgentFields();
  } catch(e) { /* silencioso */ }
}

// Guarda la configuración del modo agente.
async function saveAgentConfig() {
  const body = {
    mode:        document.getElementById('agent-mode')?.value,
    manager_url: document.getElementById('agent-manager-url')?.value || '',
    agent_key:   document.getElementById('agent-key')?.value || '',
    agent_name:  document.getElementById('agent-name')?.value || '',
  };
  const msg = document.getElementById('agent-cfg-msg');
  try {
    const r = await fetch('/api/config/agent', {
      method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body),
    });
    const d = await r.json();
    if (msg) { msg.textContent = d.ok ? '✓ Configuración de agente guardada' : '✗ Error: ' + d.error;
               msg.style.color = d.ok ? 'var(--green)' : 'var(--red)'; }
    toast(d.ok ? '✓ Modo agente guardado' : '✗ Error: ' + d.error, d.ok ? 'success' : 'error');
    if (d.ok && document.getElementById('agent-key')) document.getElementById('agent-key').value = '';
  } catch(e) {
    if (msg) { msg.textContent = '✗ Error de red'; msg.style.color = 'var(--red)'; }
  }
}

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
// LDAP/AD + WEBSOCKET PUSH (sin polling)
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
        toast(`${critical} hallazgo(s) crítico(s) detectado(s)`, 'error');
        sendBrowserNotif(`${critical} hallazgo(s) crítico(s)`, titles?.join(' · ') || `Análisis #${scan_id}`, 'critical');
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
      sendBrowserNotif('Nuevo dispositivo detectado', `IP: ${msg.data?.ip || '?'} — revisa si está autorizado.`, 'medium');
      addActivityItem('monitor', '',
        `Nuevo dispositivo: ${msg.data?.ip || ''}`,
        msg.data?.hostname || '',
        'high');
      break;
  }
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
      _renderSummary('ldap-summary-bar', d.findings);
      tbody.innerHTML = d.findings.map(f => `
        <tr ${on('click', 'openDrawer', f)}>
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
