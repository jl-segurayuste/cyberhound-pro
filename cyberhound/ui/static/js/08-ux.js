// Búsqueda global, CSV, atajos, notificaciones del navegador y estado del sistema.
// Se cargan en orden (ver index.html); comparten el ámbito global como si fueran un solo fichero.
'use strict';

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
        return `<div style="padding:10px 14px;border-bottom:1px solid var(--border);cursor:pointer"
          class="gsearch-item" ${on('click', 'openSearchResult', f)}
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

function openSearchResult(f) { openDrawer(f); closeGlobalSearch(); }

function globalSearchKeydown(ev, el) {
  if (ev.key === 'Escape') { el.value = ''; closeGlobalSearch(); }
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

// ── Panel de estado del sistema ────────────────────────────────────────────────
async function loadSystemStatus() {
  if (!hostAccess()) return;   // de la plataforma: un tenant recibiría 403
  try {
    const [monR, schedR] = await Promise.all([
      fetch('/api/monitor/status'),
      fetch('/api/scheduler'),
    ]);
    const mon   = monR.ok   ? await monR.json()   : {};
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
        label: 'Notif. push',
        value: _browserNotifEnabled ? 'Activadas' : 'Desactivadas',
        color: _browserNotifEnabled ? 'var(--green)' : 'var(--text2)',
        onclick: 'requestBrowserNotifications',
      },
    ];

    el.innerHTML = items.map(item => `
      <div style="display:flex;justify-content:space-between;align-items:center;
                  padding:5px 0;border-bottom:1px solid var(--border);font-size:.8rem"
           ${item.onclick ? `${on('click', item.onclick)} role="button"` : ''}>
        <span style="color:var(--text2)">${item.label}</span>
        <span style="color:${item.color}">${item.value}
          ${item.tip ? `<span style="color:var(--text2);font-size:.72rem"> — ${item.tip}</span>` : ''}
        </span>
      </div>`).join('');
  } catch(e) {}
}
