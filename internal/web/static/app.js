"use strict";

// ── Config ──────────────────────────────────────────────────────────
const BASE = (location.pathname.replace(/index\.html$/, "")).replace(/\/?$/, "/");
const TOKEN_KEY = "vpnweb_token";
let TOKEN = localStorage.getItem(TOKEN_KEY) || "";
let ES = null;
let sseRetries = 0;
const SSE_MAX_RETRIES = 3;

// ── Helpers ─────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}
function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.remove("show"), 3000);
}
function debounce(fn, ms) {
  let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

// ── API ─────────────────────────────────────────────────────────────
async function api(path, opts) {
  opts = opts || {};
  const headers = Object.assign({}, opts.headers || {});
  if (TOKEN) headers["Authorization"] = "Bearer " + TOKEN;
  const url = BASE + "api" + (path.startsWith("/") ? path : "/" + path);
  const res = await fetch(url, Object.assign({}, opts, { headers }));
  if (res.status === 401) { promptToken(true); throw new Error("unauthorized"); }
  const ct = res.headers.get("content-type") || "";
  const body = ct.includes("application/json") ? await res.json() : await res.text();
  if (!res.ok) {
    const msg = (body && body.error) || ("HTTP " + res.status);
    throw new Error(msg);
  }
  return body;
}

function promptToken(force) {
  const t = prompt(force ? "Token invalid. Enter web token:" : "Enter web token:", TOKEN);
  if (t != null) {
    TOKEN = t.trim();
    localStorage.setItem(TOKEN_KEY, TOKEN);
    connect();
  }
}

// ── SSE ─────────────────────────────────────────────────────────────
async function connect() {
  if (!TOKEN) { promptToken(false); return; }
  if (ES) ES.close();
  let ticket;
  try {
    const data = await api("sse-ticket", { method: "POST" });
    ticket = data.ticket;
  } catch (e) {
    setConn(false);
    return;
  }
  if (!ticket) { setConn(false); return; }

  ES = new EventSource(BASE + "api/stream?ticket=" + encodeURIComponent(ticket));
  ES.onopen = () => { sseRetries = 0; setConn(true); };
  ES.onerror = () => {
    setConn(false);
    if (sseRetries < SSE_MAX_RETRIES) { sseRetries++; setTimeout(connect, 1500); }
  };
  ES.addEventListener("status", e => renderStatus(JSON.parse(e.data)));
  ES.addEventListener("pipeline", e => renderPipeline(JSON.parse(e.data)));
  ES.addEventListener("nodes", e => {
    rebuildCountryDropdown();
    if (currentTab() === "nodes") loadNodes();
  });
  ES.addEventListener("log", e => appendLog(e.data));
}

function setConn(ok) {
  const b = $("conn-badge");
  b.className = "conn-badge " + (ok ? "on" : "off");
  b.textContent = ok ? "live" : "disconnected";
}

// ── Tabs ────────────────────────────────────────────────────────────
let activeTab = "dashboard";
function currentTab() { return activeTab; }

document.querySelectorAll(".nav-btn").forEach(btn => {
  btn.onclick = () => {
    document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    btn.classList.add("active");
    $("tab-" + btn.dataset.tab).classList.add("active");
    activeTab = btn.dataset.tab;
    const tab = btn.dataset.tab;
    if (tab === "sources") loadSources();
    if (tab === "nodes") { if (!$("node-country-panel").innerHTML.trim()) rebuildCountryDropdown(); loadNodes(); loadBanned(); }
    if (tab === "subscriptions") loadSubscriptions();
    if (tab === "settings") loadSettings();
  };
});

// Keyboard nav: arrow keys to switch tabs
document.addEventListener("keydown", (e) => {
  if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA" || e.target.tagName === "SELECT") return;
  const btns = [...document.querySelectorAll(".nav-btn")];
  const idx = btns.findIndex(b => b.classList.contains("active"));
  if (e.key === "ArrowRight" && idx < btns.length - 1) { btns[idx + 1].click(); btns[idx + 1].focus(); }
  if (e.key === "ArrowLeft" && idx > 0) { btns[idx - 1].click(); btns[idx - 1].focus(); }
});

// ── Dashboard ───────────────────────────────────────────────────────
function renderStatus(d) {
  const k = d.kpis || {};
  $("kpi-row").innerHTML = [
    ["Alive", k.alive, "ok"],
    ["Dead", k.dead, "bad"],
    ["Countries", k.countries, "accent"],
    ["Sources", d.sources, "accent"],
    ["Cycle", d.cycle, "accent"],
  ].map(([label, val, cls]) =>
    `<div class="kpi-card ${cls}"><div class="value">${esc(val != null ? val : 0)}</div><div class="label">${esc(label)}</div></div>`
  ).join("");

  const prog = (label, done, total) => (total > 0 ? `
    <div style="margin-top:6px">
      <div class="muted">${esc(label)}: ${done || 0} / ${total}</div>
      <div style="height:8px;background:var(--bg);border-radius:4px;overflow:hidden;margin-top:3px;border:1px solid var(--border)">
        <div style="height:100%;background:var(--accent);border-radius:4px;transition:width .3s ease;width:${Math.min(100, (100 * (done || 0) / total)).toFixed(1)}%"></div>
      </div>
    </div>` : '');
  const fetchBar = d.phase === 'fetch' ? prog('источники', d.sourceDone, d.sourceTotal) : '';
  const probeBar = d.phase === 'probe' ? prog('проверено', d.probeDone, d.probeTotal) : '';
  const geoLabel = 'geo · ' + (d.geoWorkers != null ? d.geoWorkers : '?') + ' потоков';
  const geoBar = d.phase === 'geo/upsert' ? prog(geoLabel, d.nodesGeoDone, d.nodesGeoTotal) : '';
  const liveStats = d.phase === 'probe' ? `<div class="muted" style="margin-top:2px">Valid: ${d.aliveCount != null ? d.aliveCount : 0}${d.probeDone != null && d.aliveCount != null ? ' · Dropped: ' + Math.max(0, d.probeDone - d.aliveCount) : ''}</div>` : '';
  $("sched-info").innerHTML = `
    <div style="display:flex;gap:8px;align-items:center;margin-bottom:6px">
      <span class="chip ${d.running ? 'chip-ok' : 'chip-bad'}">${d.running ? 'running' : 'stopped'}</span>
      <span class="muted">phase: ${esc(d.phase || '?')}</span>
      <button class="btn btn-sm btn-ghost btn-danger" id="btn-cycle-stop" ${d.running ? '' : 'disabled'} style="margin-left:auto">Stop Cycle</button>
    </div>
    ${fetchBar}
    ${geoBar}
    ${probeBar}
    ${liveStats}
    <div class="muted">last cycle: ${d.lastCycleDurMs ? (d.lastCycleDurMs / 1000).toFixed(1) + 's' : '—'}</div>
    ${d.lastError ? `<div style="color:var(--bad);margin-top:4px;font-size:12px">Error: ${esc(d.lastError)}</div>` : ''}
  `;
  const stopBtn = $("btn-cycle-stop");
  if (stopBtn) stopBtn.onclick = async () => {
    try {
      await api("/cycle/stop", { method: "POST" });
      toast("cycle stopped");
    } catch (e) { toast(e.message); }
  };
}

function renderPipeline(snap) {
  snap = snap || {};
  const steps = [
    ["Fetched", snap.NodesFetched],
    ["Parsed", snap.Parsed],
    ["Dedup", snap.DedupKept],
    ["-Unsup", snap.DroppedUnsupported],
    ["-Insec", snap.DroppedInsecure],
    ["-Broken", snap.DroppedBroken],
    ["-Malw", snap.DroppedMalware],
    ["Kept", snap.Kept],
  ];
  $("pipeline-funnel").innerHTML = steps.map(([l, v], i) => {
    let h = `<div class="funnel-step"><div class="num">${esc(v == null ? 0 : v)}</div><div class="lbl">${esc(l)}</div></div>`;
    if (i < steps.length - 1) h += '<span class="funnel-arrow">→</span>';
    return h;
  }).join("");
}

function appendLog(data) {
  let line = data;
  try {
    const p = JSON.parse(data);
    if (typeof p === "string") line = p;
  } catch (e) {}
  const pre = $("live-log");
  if (!pre) return;
  pre.textContent += line + "\n";
  pre.scrollTop = pre.scrollHeight;
  while (pre.childNodes.length > 400) pre.removeChild(pre.firstChild);
}

// ── Sources ─────────────────────────────────────────────────────────
async function loadSources() {
  try {
    const list = await api("/sources");
    renderSources(list);
  } catch (e) { toast(e.message); }
}

function renderSources(list) {
  const tb = $("src-table").querySelector("tbody");
  const empty = $("src-empty");
  $("src-count").textContent = list.length;
  if (!list.length) {
    tb.innerHTML = "";
    empty.classList.remove("hidden");
    return;
  }
  empty.classList.add("hidden");
  tb.innerHTML = list.map(s => `
    <tr>
      <td style="word-break:break-all;max-width:400px">${esc(s.url)}</td>
      <td><span class="chip chip-neutral">${esc(s.kind)}</span></td>
      <td>${s.enabled ? '<span class="chip chip-ok">enabled</span>' : '<span class="chip chip-bad">disabled</span>'}</td>
      <td style="white-space:nowrap">
        <button class="btn btn-sm btn-ghost" data-toggle="${esc(s.id)}">${s.enabled ? 'disable' : 'enable'}</button>
        <button class="btn btn-sm btn-ghost" data-edit="${esc(s.id)}" data-url="${esc(s.url)}">edit</button>
        <button class="btn btn-sm btn-ghost btn-danger" data-del="${esc(s.id)}">delete</button>
      </td>
    </tr>`).join("");
  tb.querySelectorAll("[data-toggle]").forEach(b => b.onclick = () => toggleSource(b.dataset.toggle));
  tb.querySelectorAll("[data-del]").forEach(b => b.onclick = () => {
    if (confirm("Delete source?")) delSource(b.dataset.del);
  });
  tb.querySelectorAll("[data-edit]").forEach(b => b.onclick = () => editSource(b.dataset.edit, b.dataset.url));
}

// Add single source
$("btn-src-add").onclick = async () => {
  const url = $("src-url").value.trim();
  if (!url) { toast("enter a URL"); return; }
  const errEl = $("src-error");
  errEl.classList.add("hidden");
  try {
    await api("/sources", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }) });
    $("src-url").value = "";
    loadSources();
    toast("source added");
  } catch (e) {
    errEl.textContent = e.message;
    errEl.classList.remove("hidden");
  }
};

// Enter key to add
$("src-url").onkeydown = e => { if (e.key === "Enter") { e.preventDefault(); $("btn-src-add").click(); } };

// Bulk toggle
$("btn-src-toggle-bulk").onclick = () => $("src-bulk-area").classList.toggle("hidden");

// Bulk add
$("btn-src-bulk").onclick = async () => {
  const text = $("src-text").value;
  const errEl = $("src-error");
  errEl.classList.add("hidden");
  try {
    await api("/sources", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }) });
    $("src-text").value = "";
    $("src-bulk-area").classList.add("hidden");
    loadSources();
    toast("sources added");
  } catch (e) {
    errEl.textContent = e.message;
    errEl.classList.remove("hidden");
  }
};

async function toggleSource(id) {
  try { await api("/sources/toggle?id=" + encodeURIComponent(id), { method: "POST" }); loadSources(); }
  catch (e) { toast(e.message); }
}
async function delSource(id) {
  try { await api("/sources?id=" + encodeURIComponent(id), { method: "DELETE" }); loadSources(); }
  catch (e) { toast(e.message); }
}
async function editSource(id, currentUrl) {
  const url = prompt("New URL:", currentUrl);
  if (!url || url === currentUrl) return;
  try {
    await api("/sources?id=" + encodeURIComponent(id), {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    loadSources();
    toast("source updated");
  } catch (e) { toast(e.message); }
}

// ── Nodes ───────────────────────────────────────────────────────────
const ISO_NAMES = {
  AF:"Afghanistan",AL:"Albania",DZ:"Algeria",AR:"Argentina",AU:"Australia",
  AT:"Austria",AZ:"Azerbaijan",BH:"Bahrain",BD:"Bangladesh",BY:"Belarus",
  BE:"Belgium",BO:"Bolivia",BR:"Brazil",BG:"Bulgaria",KH:"Cambodia",CM:"Cameroon",
  CA:"Canada",CL:"Chile",CN:"China",CO:"Colombia",CR:"Costa Rica",HR:"Croatia",
  CU:"Cuba",CY:"Cyprus",CZ:"Czechia",DK:"Denmark",DO:"Dominican Republic",
  EC:"Ecuador",EG:"Egypt",SV:"El Salvador",EE:"Estonia",FI:"Finland",FR:"France",
  GE:"Georgia",DE:"Germany",GH:"Ghana",GR:"Greece",GT:"Guatemala",HK:"Hong Kong",
  HU:"Hungary",IS:"Iceland",IN:"India",ID:"Indonesia",IR:"Iran",IQ:"Iraq",IE:"Ireland",
  IL:"Israel",IT:"Italy",JM:"Jamaica",JP:"Japan",JO:"Jordan",KZ:"Kazakhstan",
  KE:"Kenya",KR:"South Korea",KW:"Kuwait",LV:"Latvia",LB:"Lebanon",LT:"Lithuania",
  LU:"Luxembourg",MY:"Malaysia",MX:"Mexico",MD:"Moldova",MN:"Mongolia",MA:"Morocco",
  NL:"Netherlands",NZ:"New Zealand",NI:"Nicaragua",NG:"Nigeria",MK:"North Macedonia",
  NO:"Norway",PK:"Pakistan",PA:"Panama",PY:"Paraguay",PE:"Peru",PH:"Philippines",
  PL:"Poland",PT:"Portugal",QA:"Qatar",RO:"Romania",RU:"Russia",SA:"Saudi Arabia",
  RS:"Serbia",SG:"Singapore",SK:"Slovakia",SI:"Slovenia",ZA:"South Africa",
  ES:"Spain",LK:"Sri Lanka",SE:"Sweden",CH:"Switzerland",TW:"Taiwan",TZ:"Tanzania",
  TH:"Thailand",TN:"Tunisia",TR:"Turkey",UG:"Uganda",UA:"Ukraine",AE:"United Arab Emirates",
  GB:"United Kingdom",US:"United States",UY:"Uruguay",UZ:"Uzbekistan",VE:"Venezuela",
  VN:"Vietnam",YE:"Yemen",ZM:"Zambia"
};

window._allNodes = [];
window._nodePage = { total: 0, limit: 50, offset: 0, nodes: [] };
window._nodeOffset = 0;

function countryName(code) {
  if (!code) return "Unknown";
  const up = code.toUpperCase();
  if (up === "XX" || up.length !== 2) return "Unknown";
  return ISO_NAMES[up] || up;
}

function flagEmoji(code) {
  if (!code || code.length !== 2) return "🏳";
  const A = 0x1F1E6, base = "A".charCodeAt(0);
  const up = code.toUpperCase();
  return String.fromCodePoint(A + up.charCodeAt(0) - base) +
         String.fromCodePoint(A + up.charCodeAt(1) - base);
}

function latencyHTML(ms, alive) {
  if (!alive) return "—";
  const cls = ms < 300 ? "lat-good" : "lat-bad";
  return `<span class="${cls}">${ms} ms</span>`;
}

// ── Country multi-select ────────────────────────────────────────────
async function rebuildCountryDropdown() {
  const panel = $("node-country-panel");
  if (!panel) return;
  const prevSel = getSelectedCountries();
  let data;
  try { data = await api("/countries"); } catch (e) { return; }
  const countries = (data && data.countries) || [];
  const unknown = (data && data.unknown) || 0;
  const prevAll = prevSel.length === 0;
  let html = `<label class="country-option"><input type="checkbox" data-all="1" ${prevAll ? "checked" : ""} /> All</label>`;
  if (unknown > 0) html += `<label class="country-option"><input type="checkbox" value="unknown" /> 🏳 Unknown (${unknown})</label>`;
  countries.forEach(c => {
    const code = c.code;
    const label = countryName(code);
    const checked = prevSel.includes(code) ? " checked" : "";
    html += `<label class="country-option"><input type="checkbox" value="${esc(code)}"${checked} /> ${flagEmoji(code)} ${esc(label)} (${c.count})</label>`;
  });
  panel.innerHTML = html;

  const allCb = panel.querySelector("[data-all]");
  const codes = panel.querySelectorAll("input:not([data-all])");
  allCb.addEventListener("change", () => {
    codes.forEach(cb => cb.checked = allCb.checked);
    updateCountryBtn();
    window._nodeOffset = 0;
    loadNodes();
  });
  codes.forEach(cb => cb.addEventListener("change", () => {
    allCb.checked = [...codes].every(c => c.checked);
    updateCountryBtn();
    window._nodeOffset = 0;
    loadNodes();
  }));
  updateCountryBtn();
}

function getSelectedCountries() {
  const panel = $("node-country-panel");
  if (!panel) return [];
  const allCb = panel.querySelector("[data-all]");
  if (allCb && allCb.checked) return [];
  return [...panel.querySelectorAll("input:not([data-all]):checked")].map(cb => cb.value).filter(Boolean);
}

function updateCountryBtn() {
  const btn = $("node-country-btn");
  const sel = getSelectedCountries();
  btn.textContent = sel.length ? sel.join(", ") + " ▾" : "All countries ▾";
}

// ── Node table + pagination ─────────────────────────────────────────
function renderNodeTable() {
  const d = window._nodePage || { total: 0, nodes: [] };
  const total = d.total || 0;
  const list = d.nodes || [];
  renderNodeInfo();
  const tb = $("node-table").querySelector("tbody");
  const empty = $("node-empty");
  if (!list.length) {
    tb.innerHTML = "";
    empty.classList.remove("hidden");
    return;
  }
  empty.classList.add("hidden");
  tb.innerHTML = list.map(n => {
    const speed = n.speedKbps != null ? (n.speedKbps >= 1024 ? (n.speedKbps / 1024).toFixed(1) + " MB/s" : n.speedKbps + " KB/s") : "—";
    return `
    <tr>
      <td><input type="checkbox" data-hash="${esc(n.hash)}" /></td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis" title="${esc(n.normName || n.name || "")}">${esc(n.normName || n.name || (n.protocol + " " + n.host))}</td>
      <td>${esc(n.host)}:${esc(n.port)}</td>
      <td>${esc(countryName(n.country))}</td>
      <td><span class="chip chip-neutral">${esc(n.protocol)}</span></td>
      <td>${n.alive ? '<span class="chip chip-ok">alive</span>' : '<span class="chip chip-bad">dead</span>'}</td>
      <td class="lat-cell" data-hash="${esc(n.hash)}">${latencyHTML(n.latencyMs, n.alive)}</td>
      <td>${speed}</td>
      <td style="white-space:nowrap">
        <button class="btn btn-sm btn-ghost" data-speed="${esc(n.hash)}">Замерить скорость</button>
        <button class="btn btn-sm btn-ghost" data-copy-node="${esc(n.hash)}">Copy</button>
        <button class="btn btn-sm btn-ghost btn-danger" data-ban="${esc(n.hash)}">Ban</button>
      </td>
    </tr>`;
  }).join("");
  tb.querySelectorAll("[data-speed]").forEach(b => b.onclick = () => speedTest(b.dataset.speed, b.closest("tr")));
  tb.querySelectorAll("[data-copy-node]").forEach(b => b.onclick = () => copyNodeConfig(b.dataset.copyNode));
  tb.querySelectorAll("[data-ban]").forEach(b => b.onclick = () => banNode(b.dataset.ban));
  updateSortIndicators();
}

// Showing X–Y of Z + page size selector
function renderNodeInfo() {
  const d = window._nodePage || { total: 0, limit: 50, offset: 0 };
  const total = d.total || 0;
  const limit = d.limit || 50;
  const offset = d.offset || 0;
  const from = total > 0 ? offset + 1 : 0;
  const to = Math.min(offset + limit, total);
  const el = $("node-count");
  if (!el) return;
  el.innerHTML = `
    <span class="showing">Showing ${from}–${to} of ${total}</span>
    <span class="node-page-size">
      <label class="muted">Per page:</label>
      <select id="node-page-size">
        <option value="25"${limit === 25 ? ' selected' : ''}>25</option>
        <option value="50"${limit === 50 ? ' selected' : ''}>50</option>
        <option value="100"${limit === 100 ? ' selected' : ''}>100</option>
        <option value="200"${limit === 200 ? ' selected' : ''}>200</option>
      </select>
    </span>`;
  const pageSize = $("node-page-size");
  if (pageSize) {
    pageSize.onchange = () => {
      window._nodePage.limit = parseInt(pageSize.value, 10);
      window._nodeOffset = 0;
      loadNodes();
    };
  }
}

// Full pager: page numbers + prev/next + go-to-page
function renderNodePagination() {
  const d = window._nodePage || { total: 0, limit: 50, offset: 0 };
  const total = d.total || 0;
  const limit = d.limit || 50;
  const offset = d.offset || 0;
  const pages = Math.ceil(total / limit) || 1;
  const cur = Math.floor(offset / limit) + 1;
  const el = $("node-pagination");
  if (!el) return;
  if (total === 0) { el.innerHTML = ""; return; }

  // Windowed page numbers: show up to 7 buttons + ellipsis
  const maxVisible = 7;
  let start = Math.max(1, cur - Math.floor(maxVisible / 2));
  let end = Math.min(pages, start + maxVisible - 1);
  if (end - start < maxVisible - 1) start = Math.max(1, end - maxVisible + 1);

  let btns = "";
  if (start > 1) {
    btns += `<button class="pager-btn" data-page="1">1</button>`;
    if (start > 2) btns += `<span class="pager-ellipsis">…</span>`;
  }
  for (let i = start; i <= end; i++) {
    btns += `<button class="pager-btn${i === cur ? " active" : ""}" data-page="${i}">${i}</button>`;
  }
  if (end < pages) {
    if (end < pages - 1) btns += `<span class="pager-ellipsis">…</span>`;
    btns += `<button class="pager-btn" data-page="${pages}">${pages}</button>`;
  }

  el.innerHTML = `
    <div class="pager-main">
      <button class="pager-btn pager-nav" id="node-prev"${offset <= 0 ? " disabled" : ""}>‹</button>
      ${btns}
      <button class="pager-btn pager-nav" id="node-next"${offset + limit >= total ? " disabled" : ""}>›</button>
    </div>
    <div class="pager-jump">
      <label>Go to:</label>
      <input id="node-page-jump" type="number" min="1" max="${pages}" value="${cur}" />
    </div>`;

  el.querySelectorAll("[data-page]").forEach(btn => {
    btn.onclick = () => {
      const page = parseInt(btn.dataset.page, 10);
      window._nodeOffset = (page - 1) * limit;
      loadNodes();
    };
  });
  const prev = $("node-prev"), next = $("node-next");
  if (prev) prev.onclick = () => { window._nodeOffset = Math.max(0, offset - limit); loadNodes(); };
  if (next) next.onclick = () => { window._nodeOffset = offset + limit; loadNodes(); };
  const jump = $("node-page-jump");
  if (jump) {
    jump.onkeydown = (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        const page = parseInt(jump.value, 10);
        if (page >= 1 && page <= pages) {
          window._nodeOffset = (page - 1) * limit;
          loadNodes();
        }
      }
    };
  }
}

// Sort indicators on column headers
function updateSortIndicators() {
  const sort = $("node-sort").value;
  const order = $("node-order").value;
  document.querySelectorAll("#node-table th.sortable").forEach(th => {
    const icon = th.querySelector(".sort-icon");
    if (!icon) return;
    if (th.dataset.sort === sort) {
      icon.textContent = order === "asc" ? " ▲" : " ▼";
      th.classList.add("sorted");
    } else {
      icon.textContent = "";
      th.classList.remove("sorted");
    }
  });
}

async function loadNodes() {
  const countries = getSelectedCountries();
  const protocol = ($("node-protocol").value || "").trim();
  const maxLatency = $("node-max-latency").value;
  const status = ($("node-status").value || "all").trim();
  const sort = ($("node-sort").value || "").trim();
  const order = ($("node-order").value || "asc").trim();
  const limit = window._nodePage.limit || 50;
  const offset = window._nodeOffset || 0;
  let q = "limit=" + limit + "&offset=" + offset;
  if (countries.length) q += "&country=" + encodeURIComponent(countries.join(","));
  if (protocol) q += "&protocol=" + encodeURIComponent(protocol);
  if (maxLatency !== "") q += "&maxlatency=" + encodeURIComponent(maxLatency);
  if (status !== "all") q += "&status=" + encodeURIComponent(status);
  if (sort) q += "&sort=" + encodeURIComponent(sort) + "&order=" + encodeURIComponent(order);
  try {
    window._nodePage = await api("/nodes?" + q);
    window._nodePage.limit = limit; // preserve chosen page size
    renderNodeTable();
    renderNodePagination();
  } catch (e) {
    $("node-count").innerHTML = '<span class="muted" style="color:var(--bad)">Error loading nodes</span>';
    toast(e.message);
  }
}

// Per-node latency measurement
async function speedTest(hash, row) {
  try {
    const r = await api("/nodes/test", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ids: [hash] })
    });
    const res = (r.results || {})[hash];
    if (!res) { toast("no result"); return; }
    const cell = row ? row.querySelector(".lat-cell") : null;
    if (cell) cell.innerHTML = res.alive ? latencyHTML(res.latencyMs, true) : "dead";
    toast("latency (ping): " + (res.alive ? res.latencyMs + " ms" : "dead"));
  } catch (e) { toast(e.message); }
}

async function banNode(hash) {
  try {
    await api("/nodes/ban", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hash })
    });
    loadBanned();
    toast("banned " + hash.slice(0, 8));
  } catch (e) { toast(e.message); }
}

async function copyNodeConfig(hash) {
  try {
    const d = await api("/nodes/" + encodeURIComponent(hash) + "/config");
    if (!d.uri) { toast("no config"); return; }
    await navigator.clipboard.writeText(d.uri);
    toast("copied node config");
  } catch (e) { toast(e.message); }
}

async function loadBanned() {
  try {
    const d = await api("/nodes/banned");
    const list = d.banned || [];
    const el = $("banned-list");
    if (!el) return;
    if (!list.length) {
      el.innerHTML = '<div class="empty">No banned nodes.</div>';
      return;
    }
    el.innerHTML = list.map(h => `
      <div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border)">
        <code style="font-size:12px;color:var(--muted)">${esc(h.slice(0, 16))}…</code>
        <button class="btn btn-sm btn-ghost" data-unban="${esc(h)}">Unban</button>
      </div>`).join("");
    el.querySelectorAll("[data-unban]").forEach(b => b.onclick = () => unbanNode(b.dataset.unban));
  } catch (e) { toast(e.message); }
}

async function unbanNode(hash) {
  try {
    await api("/nodes/ban/" + encodeURIComponent(hash), { method: "DELETE" });
    loadBanned();
  } catch (e) { toast(e.message); }
}

// Filter wiring
$("btn-node-refresh").onclick = loadNodes;
$("node-protocol").onchange = () => { window._nodeOffset = 0; loadNodes(); };
$("node-max-latency").oninput = debounce(() => { window._nodeOffset = 0; loadNodes(); }, 400);
$("node-status").onchange = () => { window._nodeOffset = 0; loadNodes(); };
$("node-sort").onchange = () => { window._nodeOffset = 0; loadNodes(); };
$("node-order").onchange = () => { window._nodeOffset = 0; loadNodes(); };

// Sortable column headers
document.querySelectorAll("#node-table th.sortable").forEach(th => {
  th.onclick = () => {
    const field = th.dataset.sort;
    const curSort = $("node-sort").value;
    const curOrder = $("node-order").value;
    if (curSort === field) {
      $("node-order").value = curOrder === "asc" ? "desc" : "asc";
    } else {
      $("node-sort").value = field;
      $("node-order").value = "asc";
    }
    window._nodeOffset = 0;
    loadNodes();
  };
});

// Country dropdown toggle
$("node-country-btn").onclick = (e) => {
  e.stopPropagation();
  $("node-country-panel").classList.toggle("hidden");
};
document.addEventListener("click", (e) => {
  const wrap = $("node-country-wrap");
  if (wrap && !wrap.contains(e.target)) $("node-country-panel").classList.add("hidden");
});

$("node-select-all").onchange = function() {
  document.querySelectorAll("#node-table tbody input[type=checkbox]").forEach(cb => cb.checked = this.checked);
};

$("btn-node-test").onclick = async () => {
  const ids = [...document.querySelectorAll("#node-table tbody input[type=checkbox]:checked")].map(c => c.dataset.hash);
  if (!ids.length) { toast("select nodes first"); return; }
  try {
    const r = await api("/nodes/test", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ids })
    });
    const count = Object.keys(r.results || {}).length;
    toast("tested " + count + " node" + (count !== 1 ? "s" : ""));
  } catch (e) { toast(e.message); }
};

// ── Subscriptions ───────────────────────────────────────────────────
async function loadSubscriptions() {
  await Promise.all([loadSubMembers(), loadGenerate(), loadPublish()]);
}

async function loadSubMembers() {
  try {
    const d = await api("/subscription/list");
    renderSubMembers(d);
  } catch (e) { toast(e.message); }
}

function renderSubMembers(d) {
  const list = d.members || [];
  $("sub-mem-count").textContent = list.length;
  const tb = $("sub-mem-table").querySelector("tbody");
  const empty = $("sub-mem-empty");
  if (!list.length) {
    tb.innerHTML = "";
    empty.classList.remove("hidden");
    return;
  }
  empty.classList.add("hidden");
  tb.innerHTML = list.map(m => `
    <tr>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis" title="${esc(m.name || m.hash)}">${esc(m.name || m.hash.slice(0, 16) + "…")}</td>
      <td>${esc(countryName(m.country))}</td>
      <td><span class="chip chip-neutral">${esc(m.protocol)}</span></td>
      <td>${m.alive ? '<span class="chip chip-ok">alive</span>' : '<span class="chip chip-bad">dead</span>'}</td>
      <td class="lat-cell">${latencyHTML(m.latencyMs, m.alive)}</td>
      <td class="muted">${m.pingCheckedAt ? new Date(m.pingCheckedAt).toLocaleString() : "—"}</td>
      <td><button class="btn btn-sm btn-ghost btn-danger" data-sub-rm="${esc(m.hash)}">Remove</button></td>
    </tr>`).join("");
  tb.querySelectorAll("[data-sub-rm]").forEach(b => b.onclick = () => removeSubMember(b.dataset.subRm));
}

async function removeSubMember(hash) {
  try {
    await api("/subscription/" + encodeURIComponent(hash), { method: "DELETE" });
    loadSubMembers();
    toast("member removed");
  } catch (e) { toast(e.message); }
}

async function loadGenerate() {
  try {
    const d = await api("/generate");
    const files = d.files || [];
    const container = $("sub-gen-files");
    const empty = $("sub-gen-empty");
    if (!files.length) { container.innerHTML = ""; empty.classList.remove("hidden"); return; }
    empty.classList.add("hidden");
    container.innerHTML = files.map(f => `
      <div class="sub-file">
        <div class="sub-file-header">
          <span class="sub-file-name">${esc(f.name)}</span>
          <button class="btn btn-sm btn-ghost" data-copy="${esc(f.name)}">Copy</button>
        </div>
        <pre>${esc(f.preview || f.error || '(empty)')}</pre>
      </div>`).join("");
    container.querySelectorAll("[data-copy]").forEach(b => b.onclick = () => copyFileContent(b.dataset.copy));
  } catch (e) { toast(e.message); }
}

async function copyFileContent(name) {
  try {
    const d = await api("/generate");
    const f = (d.files || []).find(x => x.name === name);
    if (f && f.preview) {
      await navigator.clipboard.writeText(f.preview);
      toast("copied " + name);
    }
  } catch (e) { toast(e.message); }
}

async function loadPublish() {
  try {
    const d = await api("/publish");
    const st = d.status || {};
    $("sub-pub-status").innerHTML = `
      <div class="pub-info">
        <div class="pub-info-row"><span class="pub-info-label">Running</span><span class="chip ${st.running ? 'chip-ok' : 'chip-bad'}">${st.running ? 'yes' : 'no'}</span></div>
        <div class="pub-info-row"><span class="pub-info-label">Listen</span><span>${esc(st.listenAddr)}</span></div>
        <div class="pub-info-row"><span class="pub-info-label">Local URL</span><a href="${esc(st.localURL)}" target="_blank">${esc(st.localURL)}</a></div>
        <div class="pub-info-row"><span class="pub-info-label">External IP</span><span>${esc(st.externalIP || '—')}</span></div>
      </div>`;
    const files = d.files || [];
    $("sub-pub-urls").innerHTML = files.length
      ? '<h3 style="margin-top:12px;margin-bottom:6px;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:0.04em">Files</h3><ul style="list-style:none;padding:0">' +
        files.map(f => {
          const primary = f.public || f.url;
          const fallback = f.public ? ` <span style="color:var(--muted);font-size:11px">(${esc(f.url)})</span>` : "";
          return `<li style="padding:4px 0"><a href="${esc(primary)}" target="_blank">${esc(f.name)}</a>${fallback}</li>`;
        }).join("") + "</ul>"
      : "";
    $("sub-pub-nginx").innerHTML = d.nginxSnippet
      ? `<h3 style="margin-top:12px;margin-bottom:6px;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:0.04em">nginx snippet · подписки</h3><pre class="log-box" style="max-height:120px">${esc(d.nginxSnippet)}</pre>`
      : "";
    const domains = d.nginxDomains || [];
    $("sub-pub-nginx-domains").innerHTML = domains.length
      ? `<h3 style="margin-top:12px;margin-bottom:6px;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:0.04em">Detected nginx domains</h3><ul style="list-style:none;padding:0">${domains.map(dn =>
          `<li style="padding:4px 0"><span class="chip chip-ok">${esc(dn)}</span></li>`).join("")}</ul>`
      : `<h3 style="margin-top:12px;margin-bottom:6px;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:0.04em">Detected nginx domains</h3><div style="color:var(--muted);font-size:12px">nginx domains not detected (config not found or no server_name)</div>`;
    $("sub-pub-nginx-admin").innerHTML =
      (d.adminNginxSnippet
        ? `<h3 style="margin-top:12px;margin-bottom:6px;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:0.04em">nginx snippet · админка (SSE)</h3><pre class="log-box" style="max-height:160px">${esc(d.adminNginxSnippet)}</pre>`
        : "") +
      (d.publicAdmin
        ? `<div style="margin-top:8px"><span style="color:var(--muted);font-size:12px">Public admin URL: </span><a href="${esc(d.publicAdmin)}" target="_blank">${esc(d.publicAdmin)}</a></div>`
        : "");
    $("sub-pub-httpd").innerHTML = (d.httpds || []).length
      ? `<h3 style="margin-top:12px;margin-bottom:6px;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:0.04em">Detected HTTP servers</h3><ul style="list-style:none;padding:0">${(d.httpds || []).map(h =>
          `<li style="padding:4px 0">${esc(h.name)} — ${esc(h.binPath || '?')} ${h.running ? '<span class="chip chip-ok">running</span>' : ''}</li>`
        ).join("")}</ul>`
      : "";
  } catch (e) { toast(e.message); }
}

// ── Settings ────────────────────────────────────────────────────────
const SETTINGS_FIELDS = [
  { key: "interval", label: "Interval", type: "text", note: "e.g. 30m, 1h — common scan (refresh of the whole node pool) interval" },
  { key: "topn", label: "Top N", type: "number", note: "best nodes per country for the common pool (3–500)", max: 500 },
  { key: "sub_validity_interval", label: "Subscription Validity Interval", type: "text", note: "e.g. 5m — how often subscription members are re-checked for liveness" },
  { key: "sub_ping_interval", label: "Subscription Ping Interval", type: "text", note: "e.g. 30m — how often subscription members' latency is refreshed" },
  { key: "sub_topn", label: "Subscription Top N", type: "number", note: "subscription nodes per country (0 = use Top N)" },
  { key: "degrade_ms", label: "Degrade Threshold (ms)", type: "number", note: "0 = median-based auto" },
  { key: "minkeep", label: "Min Keep", type: "number", note: "minimum subscription versions kept" },
  { key: "dead_cycles", label: "Corpse Cycles", type: "number", note: "consecutive dead cycles before skipping (0 = disabled)" },
  { key: "workers", label: "Workers", type: "number", note: "concurrent probe goroutines for the embedded mihomo engine (default 32)" },
  { key: "probe_batch", label: "Probe Batch", type: "number", note: "0 = auto (10×Workers); >0 = per-cycle probe window size (mihomo memory bound). RESTART required to take effect." },
  { key: "max_ping_ms", label: "Max Ping (ms)", type: "number", note: "drop nodes slower than this from the served subscription (0 = no cap)" },
  { key: "probe_url", label: "Probe URL", type: "text", note: "URL used for latency/delay checks (e.g. http://www.gstatic.com/generate_204)" },
  { key: "speed_test_url", label: "Speed Test URL", type: "text", note: "URL used for manual speed tests (large download)" },
  { key: "min_speed_mbps", label: "Min Speed (Mbps)", type: "number", note: "minimum speed to keep a node in manual speed tests" },
  { key: "speed_test_topn", label: "Speed Test Top N", type: "number", note: "top N by speed after a manual speed test" },
  { key: "serve_addr", label: "Serve Address", type: "text", note: "subscription HTTP server listen addr (e.g. 127.0.0.1:18080, empty = off)" },
  { key: "serve_token", label: "Serve Token", type: "text", note: "secret path token for subscription server" },
  { key: "web_addr", label: "Web Address", type: "text", note: "admin UI listen address" },
  { key: "web_token", label: "Web Token", type: "text", note: "admin Bearer token (RESTART required to take effect)" },
  { key: "web_secret", label: "Web Secret", type: "text", note: "admin path prefix, min 24 chars (RESTART required, stored in config.json)" },
  { key: "state_path", label: "State DB Path", type: "text", note: "path to state.db", readonly: true },
  { key: "sources_path", label: "Sources Path", type: "text", note: "path to sources whitelist file", readonly: true },
  { key: "assets_dir", label: "Assets Dir", type: "text", note: "GeoIP mmdb directory", readonly: true },
  { key: "out_dir", label: "Output Dir", type: "text", note: "generated subscriptions directory", readonly: true },
  { key: "exclude_countries", label: "Exclude Countries", type: "countries", note: "comma-separated ISO codes to exclude from subscriptions (e.g. ru,cn)" },
  { key: "exclude_protocols", label: "Exclude Protocols", type: "protocols", note: "protocols to skip probing entirely (e.g. vmess,tuic,ss)" },
  { key: "cdn_enabled", label: "CDN Rewrite", type: "checkbox", note: "rewrite Cloudflare-range server IPs to a working CDN edge IP (preserves SNI / ws-gRPC Host)" },
  { key: "cdn_source", label: "CDN Source", type: "select", options: [["vwn", "VWN (connect_host file)"], ["manual", "Manual fallback IP"]], note: "how the working CDN IP is obtained" },
  { key: "cdn_vwn_config", label: "VWN Config Path", type: "text", note: "path to the VWNpy connect_host file (default /usr/local/etc/xray/connect_host)" },
  { key: "cdn_fallback_ip", label: "Fallback CDN IP", type: "text", note: "manual CDN IP, or fallback when the VWN file is missing/empty" },
  { key: "cdn_overrides", label: "CDN Overrides", type: "textarea", note: "per-host override, one 'domain=ip' per line; takes precedence over the auto-resolved CDN IP" },
];

async function loadSettings() {
  try {
    const d = await api("/settings");
    const s = d.settings || {};
    $("settings-note").textContent = d.note || "";

    const form = $("settings-form");
    form.innerHTML = SETTINGS_FIELDS.map(f => {
      if (f.type === "countries" || f.type === "protocols") {
        return `<div class="settings-field">
          <label>${esc(f.label)}</label>
          <div id="sf-${f.key}" class="chip-checks"></div>
          <span class="field-note">${esc(f.note)}</span>
        </div>`;
      }
      if (f.type === "checkbox") {
        return `<div class="settings-field">
          <label><input type="checkbox" id="sf-${f.key}" ${s[f.key] ? "checked" : ""} data-key="${esc(f.key)}" /> ${esc(f.label)}</label>
          <span class="field-note">${esc(f.note)}</span>
        </div>`;
      }
      if (f.type === "select") {
        const opts = (f.options || []).map(([v, l]) =>
          `<option value="${esc(v)}" ${s[f.key] === v ? "selected" : ""}>${esc(l)}</option>`).join("");
        return `<div class="settings-field">
          <label for="sf-${f.key}">${esc(f.label)}</label>
          <select id="sf-${f.key}" data-key="${esc(f.key)}">${opts}</select>
          <span class="field-note">${esc(f.note)}</span>
        </div>`;
      }
      if (f.type === "textarea") {
        const val = (s[f.key] && typeof s[f.key] === "object")
          ? Object.entries(s[f.key]).map(([k, v]) => k + "=" + v).join("\n")
          : "";
        return `<div class="settings-field">
          <label for="sf-${f.key}">${esc(f.label)}</label>
          <textarea id="sf-${f.key}" rows="4" data-key="${esc(f.key)}">${esc(val)}</textarea>
          <span class="field-note">${esc(f.note)}</span>
        </div>`;
      }
      return `
      <div class="settings-field">
        <label for="sf-${f.key}">${esc(f.label)}</label>
        <input id="sf-${f.key}" type="${f.type}" value="${esc(Array.isArray(s[f.key]) ? s[f.key].join(', ') : (s[f.key] != null ? s[f.key] : ''))}" ${f.readonly ? 'readonly' : ''} ${f.max != null ? 'max="' + f.max + '"' : ''} data-key="${esc(f.key)}" />
        <span class="field-note">${esc(f.note)}</span>
      </div>`;
    }).join("") + `
      <div class="settings-actions">
        <button type="submit" class="btn btn-accent">Save Settings</button>
      </div>
      <div class="settings-field db-cleanup">
        <span class="field-note">Prune old probe results/history and remove stale nodes from the database on demand.</span>
        <button type="button" class="btn btn-danger" id="btn-cleanup">Clear old DB records</button>
        <span id="cleanup-result" class="field-note"></span>
      </div>`;

    form.onsubmit = async (e) => {
      e.preventDefault();
      await saveSettings(s);
    };

    // populate exclude_countries checkboxes from /api/countries
    const ccBox = $("sf-exclude_countries");
    if (ccBox) {
      try {
        const cc = await api("/countries");
        const excluded = new Set((s.exclude_countries || []).map(c => c.toUpperCase()));
        ccBox.innerHTML = (cc.countries || []).map(c => {
          const code = c.code.toUpperCase();
          const id = "cc-" + code.toLowerCase();
          return `<label><input type="checkbox" id="${id}" value="${code}" ${excluded.has(code) ? "checked" : ""}> ${esc(code)} (${c.count})</label>`;
        }).join("");
      } catch (e) { ccBox.textContent = "failed to load countries"; }
    }

    // populate exclude_protocols checkboxes (hardcoded list)
    const pcBox = $("sf-exclude_protocols");
    if (pcBox) {
      const PROTOCOLS = ["vmess","vless","trojan","hysteria2","tuic","ss"];
      const excludedP = new Set((s.exclude_protocols || []).map(p => p.toLowerCase()));
      pcBox.innerHTML = PROTOCOLS.map(p => {
        const id = "pc-" + p;
        return `<label><input type="checkbox" id="${id}" value="${p}" ${excludedP.has(p) ? "checked" : ""}> ${esc(p.toUpperCase())}</label>`;
      }).join("");
    }

    const btnCleanup = $("btn-cleanup");
    if (btnCleanup) {
      btnCleanup.onclick = async () => {
        if (!confirm("Clear old DB records? This prunes probe history/results and removes stale nodes.")) return;
        try {
          const r = await api("/admin/cleanup", { method: "POST" });
          $("cleanup-result").textContent =
            `done: removed ${r.removed} node(s), ${r.orphans} orphan(s) (${r.nodesBefore} → ${r.nodesAfter})`;
          toast("database cleaned");
        } catch (e) { toast(e.message); }
      };
    }
  } catch (e) { toast(e.message); }
}

async function saveSettings(current) {
  const patch = {};
  SETTINGS_FIELDS.forEach(f => {
    const el = $("sf-" + f.key);
    if (!el || el.readOnly) return;
    if (f.type === "countries" || f.type === "protocols") {
      patch[f.key] = [...el.querySelectorAll("input[type=checkbox]:checked")].map(cb => cb.value.toUpperCase());
      return;
    }
    if (f.type === "checkbox") {
      patch[f.key] = el.checked;
      return;
    }
    if (f.type === "select") {
      patch[f.key] = el.value;
      return;
    }
    if (f.type === "textarea") {
      const m = {};
      el.value.split("\n").forEach(line => {
        const t = line.trim();
        if (!t) return;
        const i = t.indexOf("=");
        if (i < 0) return;
        const k = t.slice(0, i).trim();
        const v = t.slice(i + 1).trim();
        if (k) m[k] = v;
      });
      patch[f.key] = m;
      return;
    }
    const val = el.value.trim();
    if (f.type === "number") {
      patch[f.key] = val === "" ? current[f.key] : parseInt(val, 10);
    } else {
      patch[f.key] = val || current[f.key];
    }
  });
  try {
    const r = await api("/settings", {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(patch)
    });
    toast("settings saved");
    if (r.note) $("settings-note").textContent = r.note;
  } catch (e) { toast(e.message); }
}

// ── Cycle ───────────────────────────────────────────────────────────
$("btn-cycle").onclick = async () => {
  try {
    await api("/cycle", { method: "POST" });
    toast("cycle requested");
  } catch (e) { toast(e.message); }
};

// ── Token ───────────────────────────────────────────────────────────
$("btn-token").onclick = () => promptToken(false);

// ── Config Modal ───────────────────────────────────────────────────
let configModalFormat = "singbox";

function openConfigModal() {
  $("config-modal").classList.remove("hidden");
  loadConfigContent("singbox");
  document.querySelectorAll(".modal-tab").forEach(t => t.classList.toggle("active", t.dataset.format === "singbox"));
}

function closeConfigModal() {
  $("config-modal").classList.add("hidden");
}

async function loadConfigContent(format) {
  configModalFormat = format;
  const pre = $("config-modal-content");
  pre.textContent = "Loading...";
  try {
    const text = await api("/subscription?format=" + encodeURIComponent(format));
    pre.textContent = typeof text === "string" ? text : JSON.stringify(text, null, 2);
  } catch (e) {
    pre.textContent = "Error: " + e.message;
  }
}

$("btn-show-config").onclick = openConfigModal;
$("config-modal-close").onclick = closeConfigModal;
$("config-modal").addEventListener("click", (e) => {
  if (e.target === $("config-modal")) closeConfigModal();
});
document.querySelectorAll(".modal-tab").forEach(tab => {
  tab.onclick = () => {
    document.querySelectorAll(".modal-tab").forEach(t => t.classList.remove("active"));
    tab.classList.add("active");
    loadConfigContent(tab.dataset.format);
  };
});
$("config-modal-copy").onclick = async () => {
  try {
    const text = $("config-modal-content").textContent;
    await navigator.clipboard.writeText(text);
    toast("copied " + configModalFormat);
  } catch (e) { toast("copy failed: " + e.message); }
};

// ── Boot ────────────────────────────────────────────────────────────
(async function boot() {
  try {
    const d = await api("/status");
    renderStatus(d);
  } catch (e) { /* SSE will supply it once connected */ }
  loadNodes();
  connect();
})();
