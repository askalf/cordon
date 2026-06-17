// Single-file ops dashboard (GET /dashboard). No build step, no dependencies — the
// page polls /metrics (open) and /admin/* (x-admin-token from localStorage). The HTML
// carries no secrets; admin data calls fail closed without a token.
// NOTE: the inner <script> deliberately avoids template literals and `$` so this outer
// TS template literal stays escape-free.

export const dashboardHtml = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>cordon — dashboard</title>
<style>
  :root { --bg:#0a0a0f; --panel:#13131c; --line:#23232f; --txt:#e8e8f0; --dim:#8a8a9a;
          --vio:#8b5cf6; --mag:#d946ef; --ok:#34d399; --warn:#fbbf24; --bad:#f87171; --cyan:#22d3ee; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--txt);
         font:14px/1.5 "Space Mono","Cascadia Mono",Consolas,monospace; }
  .wrap { max-width:1060px; margin:0 auto; padding:24px 20px 60px; }
  header { display:flex; align-items:baseline; gap:14px; flex-wrap:wrap; margin-bottom:18px; }
  h1 { font-size:22px; margin:0; background:linear-gradient(90deg,var(--vio),var(--mag));
       -webkit-background-clip:text; background-clip:text; color:transparent; }
  .sub { font-size:12px; color:var(--dim); }
  .tag { font-size:11px; padding:2px 8px; border:1px solid var(--line); border-radius:99px; color:var(--dim); }
  .tag.on { color:var(--ok); border-color:var(--ok); }
  .tag.warn { color:var(--warn); border-color:var(--warn); }
  .tag.bad { color:var(--bad); border-color:var(--bad); }
  #tok { margin-left:auto; background:var(--panel); border:1px solid var(--line); color:var(--txt);
         padding:5px 9px; border-radius:6px; width:200px; font:inherit; font-size:12px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:10px; margin-bottom:14px; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:12px 14px; }
  .card .k { font-size:11px; color:var(--dim); text-transform:uppercase; letter-spacing:.08em; }
  .card .v { font-size:24px; margin-top:2px; }
  .card .v.bad { color:var(--bad); }
  .panel { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px 16px; margin-bottom:14px; }
  .panel h2 { font-size:12px; color:var(--dim); text-transform:uppercase; letter-spacing:.08em; margin:0 0 10px; }
  .bar { display:flex; height:18px; border-radius:5px; overflow:hidden; border:1px solid var(--line); }
  .bar div { min-width:1px; }
  .legend { display:flex; gap:14px; flex-wrap:wrap; margin-top:8px; font-size:12px; color:var(--dim); }
  .dot { display:inline-block; width:9px; height:9px; border-radius:2px; margin-right:5px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:4px 10px 4px 0; border-bottom:1px solid var(--line); }
  th { color:var(--dim); font-weight:normal; font-size:11px; text-transform:uppercase; letter-spacing:.06em; }
  .hist { display:flex; align-items:flex-end; gap:6px; height:110px; margin-top:6px; }
  .hist .col { flex:1; display:flex; flex-direction:column; justify-content:flex-end; align-items:center; gap:4px; }
  .hist .colbar { width:100%; background:linear-gradient(180deg,var(--vio),var(--mag)); border-radius:3px 3px 0 0; }
  .hist .n { font-size:11px; color:var(--txt); }
  .hist .lbl { font-size:9px; color:var(--dim); white-space:nowrap; }
  .muted { color:var(--dim); }
  .two { display:grid; grid-template-columns:1fr 1fr; gap:14px; }
  @media (max-width:760px) { .two { grid-template-columns:1fr; } }
  code { color:var(--cyan); }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>cordon</h1>
    <span class="sub">own your prompts — PII never leaves your perimeter</span>
    <span class="tag" id="m-mode">mode …</span>
    <span class="tag" id="m-fail">fail …</span>
    <span class="tag" id="m-audit">audit …</span>
    <input id="tok" type="password" placeholder="x-admin-token" title="admin token (stored locally)">
  </header>

  <div class="grid">
    <div class="card"><div class="k">requests</div><div class="v" id="c-req">–</div></div>
    <div class="card"><div class="k">redacted reqs</div><div class="v" id="c-rr">–</div></div>
    <div class="card"><div class="k">entities redacted</div><div class="v" id="c-ent">–</div></div>
    <div class="card"><div class="k">fail-closed</div><div class="v" id="c-fc">–</div></div>
    <div class="card"><div class="k">bypass</div><div class="v" id="c-by">–</div></div>
  </div>

  <div class="panel">
    <h2>redactions by entity type</h2>
    <div class="hist" id="typehist"></div>
    <div class="muted" id="type-empty" style="display:none">no redactions yet</div>
  </div>

  <div class="two">
    <div class="panel">
      <h2>mode mix</h2>
      <div class="bar" id="modebar"></div>
      <div class="legend" id="modelegend"></div>
    </div>
    <div class="panel">
      <h2>redactions by set</h2>
      <div class="bar" id="setbar"></div>
      <div class="legend" id="setlegend"></div>
    </div>
  </div>

  <div class="panel">
    <h2>tenant policies</h2>
    <div id="tenants" class="muted">none set</div>
  </div>
</div>

<script>
(function () {
  var tokEl = document.getElementById('tok');
  tokEl.value = localStorage.getItem('cordon-admin-token') || '';
  tokEl.addEventListener('change', function () {
    localStorage.setItem('cordon-admin-token', tokEl.value);
    refresh();
  });
  function hdrs() { return tokEl.value ? { 'x-admin-token': tokEl.value } : {}; }
  function el(id) { return document.getElementById(id); }
  function txt(id, v) { el(id).textContent = v; }
  function tag(id, label, cls) { var e = el(id); e.textContent = label; e.className = 'tag' + (cls ? ' ' + cls : ''); }

  var MODECOLORS = { reversible:'#8b5cf6', strip:'#d946ef', off:'#52525e' };
  var SETCOLORS = { pii:'#22d3ee', phi:'#34d399', pci:'#fbbf24', secrets:'#f87171' };

  function renderBar(barId, legId, obj, colors) {
    var bar = el(barId), leg = el(legId);
    bar.innerHTML = ''; leg.innerHTML = '';
    var keys = Object.keys(obj || {});
    var total = 0; keys.forEach(function (k) { total += obj[k]; });
    keys.forEach(function (k) {
      if (!obj[k]) return;
      var c = colors[k] || '#888';
      var d = document.createElement('div');
      d.style.background = c; d.style.width = (100 * obj[k] / (total || 1)) + '%';
      d.title = k + ': ' + obj[k];
      bar.appendChild(d);
      var l = document.createElement('span');
      l.innerHTML = '<span class="dot" style="background:' + c + '"></span>' + k + ' ' + obj[k];
      leg.appendChild(l);
    });
    if (!total) leg.textContent = 'no data yet';
  }

  function renderTypeHist(byType) {
    var hist = el('typehist');
    hist.innerHTML = '';
    var keys = Object.keys(byType || {}).sort(function (a, b) { return byType[b] - byType[a]; });
    el('type-empty').style.display = keys.length ? 'none' : 'block';
    var max = 1; keys.forEach(function (k) { if (byType[k] > max) max = byType[k]; });
    keys.forEach(function (k) {
      var col = document.createElement('div'); col.className = 'col';
      var n = document.createElement('div'); n.className = 'n'; n.textContent = byType[k];
      var b = document.createElement('div'); b.className = 'colbar';
      b.style.height = Math.max(4, 80 * byType[k] / max) + 'px';
      var l = document.createElement('div'); l.className = 'lbl'; l.textContent = k;
      col.appendChild(n); col.appendChild(b); col.appendChild(l);
      hist.appendChild(col);
    });
  }

  function renderTenants(stats) {
    var t = (stats && stats.tenants) || {};
    var keys = Object.keys(t);
    if (!keys.length) { el('tenants').textContent = 'none set'; return; }
    var rows = keys.map(function (k) {
      var p = t[k];
      return '<tr><td>' + k + '</td><td>' + (p.mode || 'default') + '</td><td>' +
             (p.activeSets ? p.activeSets.join('+') : 'default') + '</td><td>' +
             (p.failMode || 'default') + '</td><td>' + (p.consistentPseudonyms ? 'yes' : '–') + '</td></tr>';
    });
    el('tenants').innerHTML = '<table><thead><tr><th>tenant</th><th>mode</th><th>sets</th><th>fail</th><th>pseudo</th></tr></thead><tbody>' +
                              rows.join('') + '</tbody></table>';
  }

  function refresh() {
    fetch('/metrics').then(function (r) { return r.json(); }).then(function (m) {
      txt('c-req', m.requests || 0);
      txt('c-rr', m.redactedRequests || 0);
      txt('c-ent', m.redactedEntities || 0);
      txt('c-fc', m.failClosed || 0);
      el('c-fc').className = 'v' + (m.failClosed ? ' bad' : '');
      txt('c-by', m.bypass || 0);
      var dm = Object.keys(m.byMode || {}).sort(function (a, b) { return (m.byMode[b]) - (m.byMode[a]); })[0];
      tag('m-mode', 'mode ' + (dm || '—'), 'on');
      tag('m-fail', 'fail-closed ' + (m.failClosed || 0), m.failClosed ? 'warn' : '');
      renderTypeHist(m.byType);
      renderBar('modebar', 'modelegend', m.byMode, MODECOLORS);
      renderBar('setbar', 'setlegend', m.bySet, SETCOLORS);
    }).catch(function () {});

    fetch('/admin/audit/verify', { headers: hdrs() }).then(function (r) {
      if (!r.ok) throw new Error('auth');
      return r.json();
    }).then(function (v) {
      if (v.ok) tag('m-audit', 'audit ✓ ' + v.records, 'on');
      else tag('m-audit', 'audit BROKEN @' + v.brokenAt, 'bad');
    }).catch(function () { tag('m-audit', 'audit (needs token)', 'warn'); });

    fetch('/admin/stats', { headers: hdrs() }).then(function (r) {
      if (!r.ok) throw new Error('auth');
      return r.json();
    }).then(function (s) {
      renderTenants(s);
      if (s.metrics) { /* already covered by /metrics */ }
    }).catch(function () {});
  }

  refresh();
  setInterval(refresh, 5000);
})();
</script>
</body>
</html>
`;
