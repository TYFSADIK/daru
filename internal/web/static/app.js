"use strict";

// --- theme ---
function applyTheme(t) {
  document.documentElement.setAttribute("data-theme", t);
  const other = t === "dark" ? "Light" : "Dark";
  const label = document.getElementById("theme-label");
  const ic = document.getElementById("theme-ic");
  if (label) label.textContent = other;
  if (ic) ic.textContent = t === "dark" ? "☀" : "☾";
}
(function initTheme() {
  let t = null;
  try { t = localStorage.getItem("daru_theme"); } catch (_) {}
  if (!t) {
    t = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  applyTheme(t);
  document.addEventListener("DOMContentLoaded", () => {
    applyTheme(document.documentElement.getAttribute("data-theme"));
    const btn = document.getElementById("theme-toggle");
    if (btn) btn.addEventListener("click", () => {
      const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      applyTheme(next);
      try { localStorage.setItem("daru_theme", next); } catch (_) {}
    });
  });
})();

// --- API helper ---
const API = {
  async call(method, path, body) {
    const opt = { method, headers: {} };
    if (body !== undefined) {
      opt.headers["Content-Type"] = "application/json";
      opt.body = JSON.stringify(body);
    }
    const res = await fetch(path, opt);
    let data = null;
    try { data = await res.json(); } catch (_) {}
    if (!res.ok) {
      const msg = (data && data.error) || `HTTP ${res.status}`;
      throw new Error(msg);
    }
    return data;
  },
  get(p) { return this.call("GET", p); },
  post(p, b) { return this.call("POST", p, b); },
  del(p) { return this.call("DELETE", p); },
};

// --- state ---
let ME = null;

// --- helpers ---
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "html") n.innerHTML = v;
    else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) n.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null) continue;
    n.appendChild(typeof kid === "string" ? document.createTextNode(kid) : kid);
  }
  return n;
};
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const fmtNum = (n) => Number(n).toLocaleString(undefined, { maximumFractionDigits: 2 });
const roleAtLeast = (r, min) => ({ user: 1, power: 2, admin: 3 }[r] || 0) >= ({ user: 1, power: 2, admin: 3 }[min] || 0);

function fmtTime(v) {
  if (v == null) return "";
  let s = String(v);
  // ClickHouse returns "2026-11-06 12:00:00.000"; show compactly.
  return s.replace("T", " ").replace("Z", "").slice(0, 23);
}

function toast(msg, kind = "info") {
  const t = el("div", { class: "notice", style: "position:fixed;top:16px;right:16px;z-index:999;max-width:360px" }, msg);
  if (kind === "error") t.style.borderLeftColor = "var(--red)";
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

// --- auth flow ---
async function boot() {
  try {
    ME = await API.get("/api/me");
    showApp();
  } catch (_) {
    showLogin();
  }
}

function showLogin() {
  document.getElementById("app").classList.add("hidden");
  document.getElementById("login").classList.remove("hidden");
}

document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const err = document.getElementById("login-error");
  err.textContent = "";
  try {
    const r = await API.post("/api/login", { username: f.username.value, password: f.password.value });
    ME = { username: r.user.username, role: r.user.role };
    showApp();
  } catch (ex) {
    err.textContent = ex.message;
  }
});

document.getElementById("logout-btn").addEventListener("click", async () => {
  await API.post("/api/logout", {});
  ME = null;
  location.hash = "";
  showLogin();
});

function showApp() {
  document.getElementById("login").classList.add("hidden");
  document.getElementById("app").classList.remove("hidden");
  document.getElementById("user-name").textContent = ME.username;
  document.getElementById("user-role").textContent = ME.role;
  buildNav();
  if (!location.hash) location.hash = "#/search";
  route();
}

// --- navigation / router ---
const ROUTES = [
  { path: "#/search", label: "Search", icon: "⌕", min: "user", render: renderSearch },
  { path: "#/dashboards", label: "Dashboards", icon: "▦", min: "user", render: renderDashboards },
  { path: "#/alerts", label: "Alerts", icon: "⚠", min: "user", render: renderAlerts },
  { path: "#/security", label: "Security", icon: "⛨", min: "user", render: renderSecurity },
  { path: "#/network", label: "Network", icon: "☰", min: "user", render: renderNetwork },
  { path: "#/recon", label: "Recon", icon: "◎", min: "user", render: renderRecon },
  { path: "#/admin", label: "Admin", icon: "⚙", min: "admin", render: renderAdmin },
];

function buildNav() {
  const nav = document.getElementById("nav");
  nav.innerHTML = "";
  for (const r of ROUTES) {
    if (!roleAtLeast(ME.role, r.min)) continue;
    nav.appendChild(el("a", { href: r.path, "data-path": r.path },
      el("span", { class: "ic" }, r.icon), r.label));
  }
}

window.addEventListener("hashchange", route);
function route() {
  const hash = location.hash || "#/search";
  const base = "#/" + hash.split("/")[1];
  document.querySelectorAll("#nav a").forEach((a) => {
    a.classList.toggle("active", a.getAttribute("data-path") === base);
  });
  const r = ROUTES.find((x) => x.path === base) || ROUTES[0];
  if (!roleAtLeast(ME.role, r.min)) { location.hash = "#/search"; return; }
  const view = document.getElementById("view");
  view.innerHTML = "";
  r.render(view);
}

function pageHead(title, sub, actions) {
  return el("div", { class: "page-head" },
    el("div", {}, el("h2", {}, title), sub ? el("div", { class: "page-sub" }, sub) : null),
    actions ? el("div", { class: "toolbar", style: "margin:0" }, ...actions) : null);
}

// ===================== SEARCH =====================
const TIME_RANGES = [
  ["-15m", "Last 15 minutes"], ["-60m", "Last 60 minutes"], ["-4h", "Last 4 hours"],
  ["-24h", "Last 24 hours"], ["-7d", "Last 7 days"], ["-30d", "Last 30 days"], ["0", "All time"],
];
let searchState = { query: "", earliest: "-24h", tab: "events", last: null };

function renderSearch(view) {
  const box = el("textarea", { class: "mono", rows: "1", placeholder: 'search index=main status=500  |  stats count by host', spellcheck: "false" });
  box.value = searchState.query;
  box.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) { e.preventDefault(); run(); }
  });
  const timeSel = el("select", { class: "time-select" },
    ...TIME_RANGES.map(([v, l]) => el("option", { value: v, ...(v === searchState.earliest ? { selected: "" } : {}) }, l)));
  const runBtn = el("button", { class: "btn-primary", onclick: run }, "Search");
  const saveBtn = roleAtLeast(ME.role, "power")
    ? el("button", { class: "btn-ghost", onclick: saveCurrent }, "Save") : null;

  const meta = el("div", { class: "search-meta" });
  const fieldsPanel = el("div", { class: "fields-panel" }, el("h4", {}, "Fields"));
  const resultsPanel = el("div", { class: "results" });

  view.appendChild(pageHead("Search", "Query your logs with the Daru pipeline language"));
  view.appendChild(el("div", { class: "search-bar" },
    el("div", { class: "search-input" }, box), timeSel, runBtn, saveBtn));
  view.appendChild(meta);
  view.appendChild(el("div", { class: "search-layout" }, fieldsPanel, resultsPanel));

  async function run() {
    searchState.query = box.value.trim();
    searchState.earliest = timeSel.value;
    if (!searchState.query) return;
    resultsPanel.innerHTML = '<div class="spinner">Running search...</div>';
    fieldsPanel.innerHTML = "<h4>Fields</h4>";
    meta.innerHTML = "";
    try {
      const r = await API.post("/api/search", {
        query: searchState.query, earliest: searchState.earliest, latest: "now", max_rows: 1000,
      });
      searchState.last = r;
      renderResults(r, resultsPanel, meta, fieldsPanel, box, run);
    } catch (ex) {
      resultsPanel.innerHTML = "";
      resultsPanel.appendChild(el("div", { class: "empty", style: "color:var(--red)" }, ex.message));
    }
  }

  async function saveCurrent() {
    const name = prompt("Name this saved search:");
    if (!name) return;
    try {
      await API.post("/api/saved", { name, query: box.value.trim(), earliest: timeSel.value, latest: "now" });
      toast("Saved search created");
    } catch (ex) { toast(ex.message, "error"); }
  }

  if (searchState.query) run();
}

function renderResults(r, panel, meta, fieldsPanel, box, rerun) {
  meta.innerHTML = "";
  meta.appendChild(el("span", {}, `${fmtNum(r.count)} results`));
  meta.appendChild(el("span", {}, `${fmtNum(r.scanned_rows || 0)} scanned`));
  meta.appendChild(el("span", {}, `${(r.elapsed || 0).toFixed(3)}s`));
  meta.appendChild(el("span", {}, `view: ${r.kind}`));

  // Field sidebar (events only).
  if (r.fields && r.fields.length) {
    for (const f of r.fields) {
      fieldsPanel.appendChild(el("div", { class: "field-item", onclick: () => {
        box.value = (box.value.trim() + " " + f.name + "=").trim();
        box.focus();
      } }, el("span", { class: "fname" }, f.name), el("span", { class: "fcount" }, String(f.distinct))));
    }
  } else {
    fieldsPanel.appendChild(el("div", { class: "empty", style: "padding:14px" }, "No fields"));
  }

  panel.innerHTML = "";
  const isChart = r.kind === "timechart" || r.kind === "chart";
  const isTable = r.kind === "table" || r.kind === "chart";
  const tabs = el("div", { class: "results-tabs" });
  const body = el("div", { class: "results-body" });
  const tabDefs = [];
  if (r.kind === "events") tabDefs.push(["events", "Events"]);
  if (isChart) tabDefs.push(["viz", "Visualization"]);
  if (r.kind !== "events") tabDefs.push(["table", "Statistics"]);
  if (r.kind === "events") tabDefs.push(["table", "Table"]);

  let active = tabDefs[0][0];
  function draw() {
    body.innerHTML = "";
    if (active === "events") body.appendChild(renderEvents(r));
    else if (active === "viz") body.appendChild(renderViz(r));
    else body.appendChild(renderTable(r));
    [...tabs.children].forEach((c) => c.classList.toggle("active", c.dataset.t === active));
  }
  for (const [t, label] of tabDefs) {
    const b = el("button", { class: "results-tab", onclick: () => { active = t; draw(); } }, label);
    b.dataset.t = t;
    tabs.appendChild(b);
  }
  panel.appendChild(tabs);
  panel.appendChild(body);
  draw();
}

function renderEvents(r) {
  if (!r.rows.length) return el("div", { class: "empty" }, "No events matched.");
  const wrap = el("div", {});
  for (const row of r.rows) {
    const chips = el("div", { class: "event-fields" });
    Object.keys(row).sort().forEach((k) => {
      if (k === "_raw" || k === "_time" || k === "_id") return;
      chips.appendChild(el("span", { class: "chip", html: `<b>${esc(k)}</b>=${esc(row[k])}` }));
    });
    wrap.appendChild(el("div", { class: "event" },
      el("div", { class: "event-time" }, fmtTime(row._time)),
      el("div", { class: "event-raw" }, row._raw || JSON.stringify(row)),
      chips));
  }
  return wrap;
}

function renderTable(r) {
  if (!r.rows.length) return el("div", { class: "empty" }, "No results.");
  const cols = r.columns && r.columns.length ? r.columns : Object.keys(r.rows[0]);
  const table = el("table", { class: "grid" });
  table.appendChild(el("tr", {}, ...cols.map((c) => el("th", {}, c))));
  for (const row of r.rows) {
    table.appendChild(el("tr", {}, ...cols.map((c) => {
      const v = row[c];
      const isNum = typeof v === "number";
      return el("td", { class: isNum ? "num" : "" }, isNum ? fmtNum(v) : (c === "_time" ? fmtTime(v) : String(v == null ? "" : v)));
    })));
  }
  const w = el("div", {});
  w.appendChild(el("table", { class: "grid" }));
  w.firstChild.replaceWith(table);
  return table;
}

function renderViz(r) {
  const cols = r.columns || [];
  const series = r.series && r.series.length ? r.series : cols.filter((c) => c !== "_time" && c !== (cols[0]));
  if (!r.rows.length) return el("div", { class: "empty" }, "Nothing to chart.");
  const xKey = r.kind === "timechart" ? "_time" : cols[0];
  let max = 0;
  for (const row of r.rows) for (const s of series) max = Math.max(max, Number(row[s]) || 0);
  max = max || 1;

  const palette = ["#5e81f4", "#4bb4a0", "#d6a24b", "#c97b6a", "#8b86d4", "#5aa9d6", "#a77bbf", "#6aa86b", "#c98aa8", "#7f8ca3", "#4e9e86", "#b06f6f"];
  const chart = el("div", { class: "chart" });
  // Legend.
  const legend = el("div", { style: "display:flex;gap:14px;flex-wrap:wrap;margin-bottom:12px;font-size:12px;color:var(--muted)" });
  series.forEach((s, i) => legend.appendChild(el("span", {},
    el("span", { style: `display:inline-block;width:10px;height:10px;border-radius:2px;background:${palette[i % palette.length]};margin-right:6px` }), s)));
  chart.appendChild(legend);

  // Grouped bars per row.
  const plot = el("div", { style: "display:flex;align-items:flex-end;gap:6px;height:220px;border-bottom:1px solid var(--border);padding-bottom:0" });
  const show = r.rows.slice(0, 60);
  for (const row of show) {
    const group = el("div", { style: "flex:1;display:flex;align-items:flex-end;gap:1px;height:100%", title: String(row[xKey]) });
    for (let i = 0; i < series.length; i++) {
      const v = Number(row[series[i]]) || 0;
      group.appendChild(el("div", {
        style: `flex:1;height:${(v / max) * 100}%;background:${palette[i % palette.length]};border-radius:2px 2px 0 0;min-height:${v > 0 ? 2 : 0}px`,
        title: `${series[i]}: ${fmtNum(v)}`,
      }));
    }
    plot.appendChild(group);
  }
  chart.appendChild(plot);
  const axis = el("div", { style: "display:flex;justify-content:space-between;color:var(--muted);font-size:11px;margin-top:6px;font-family:var(--mono)" });
  if (show.length) {
    axis.appendChild(el("span", {}, fmtTime(show[0][xKey])));
    axis.appendChild(el("span", {}, fmtTime(show[show.length - 1][xKey])));
  }
  chart.appendChild(axis);
  return chart;
}

// ===================== DASHBOARDS =====================
async function renderDashboards(view) {
  view.appendChild(pageHead("Dashboards", "Saved panels of searches", roleAtLeast(ME.role, "power") ? [
    el("button", { class: "btn-ghost", onclick: () => newDashboard() }, "+ New dashboard"),
  ] : null));
  const grid = el("div", { class: "cards" }, el("div", { class: "spinner" }, "Loading..."));
  view.appendChild(grid);
  try {
    const r = await API.get("/api/dashboards");
    grid.innerHTML = "";
    if (!r.dashboards || !r.dashboards.length) { grid.appendChild(el("div", { class: "empty" }, "No dashboards yet.")); return; }
    for (const d of r.dashboards) {
      grid.appendChild(el("div", { class: "card", style: "cursor:pointer", onclick: () => openDashboard(d.id) },
        el("h3", {}, d.name), el("div", { class: "meta" }, "by " + d.owner)));
    }
  } catch (ex) { grid.innerHTML = ""; grid.appendChild(el("div", { class: "empty" }, ex.message)); }
}

async function openDashboard(id) {
  const view = document.getElementById("view");
  view.innerHTML = "";
  view.appendChild(pageHead("Dashboard", "", [el("button", { class: "btn-ghost", onclick: () => renderDashboards(view) }, "← Back")]));
  const grid = el("div", { class: "cards", style: "grid-template-columns:repeat(auto-fill,minmax(360px,1fr))" }, el("div", { class: "spinner" }, "Loading..."));
  view.appendChild(grid);
  try {
    const d = await API.get("/api/dashboards/" + id);
    const def = JSON.parse(d.definition || "{}");
    grid.innerHTML = "";
    view.querySelector("h2").textContent = d.name;
    for (const panel of def.panels || []) {
      const card = el("div", { class: "card" }, el("h3", {}, panel.title || "Panel"), el("div", { class: "spinner" }, "..."));
      grid.appendChild(card);
      API.post("/api/search", { query: panel.query, earliest: panel.earliest || "-24h", latest: "now", max_rows: 200 })
        .then((r) => { card.lastChild.replaceWith(panel.type === "table" || r.kind !== "events" ? renderTable(r) : renderEvents(r)); })
        .catch((ex) => { card.lastChild.replaceWith(el("div", { class: "empty" }, ex.message)); });
    }
    if (!(def.panels || []).length) grid.appendChild(el("div", { class: "empty" }, "This dashboard has no panels."));
  } catch (ex) { grid.innerHTML = ""; grid.appendChild(el("div", { class: "empty" }, ex.message)); }
}

async function newDashboard() {
  const name = prompt("Dashboard name:");
  if (!name) return;
  const query = prompt("First panel query (BQL):", "* | timechart span=1h count");
  if (!query) return;
  const definition = JSON.stringify({ panels: [{ title: "Panel 1", query, type: "viz", earliest: "-24h" }] });
  try { await API.post("/api/dashboards", { name, definition }); toast("Dashboard created"); renderDashboards(document.getElementById("view")); }
  catch (ex) { toast(ex.message, "error"); }
}

// ===================== ALERTS =====================
async function renderAlerts(view) {
  view.appendChild(pageHead("Alerts", "Scheduled searches and their history", roleAtLeast(ME.role, "power") ? [
    el("button", { class: "btn-ghost", onclick: () => newAlert() }, "+ New alert"),
  ] : null));
  const savedWrap = el("div", {}, el("div", { class: "spinner" }, "Loading..."));
  const histWrap = el("div", {});
  view.appendChild(el("h3", { style: "margin:18px 0 8px;font-size:15px" }, "Scheduled alerts"));
  view.appendChild(savedWrap);
  view.appendChild(el("h3", { style: "margin:22px 0 8px;font-size:15px" }, "Recent firings"));
  view.appendChild(histWrap);
  try {
    const r = await API.get("/api/saved");
    const alerts = (r.saved || []).filter((s) => s.is_alert);
    savedWrap.innerHTML = "";
    if (!alerts.length) savedWrap.appendChild(el("div", { class: "empty" }, "No scheduled alerts."));
    else {
      const t = el("table", { class: "grid" }, el("tr", {}, ...["Name", "Query", "Schedule", "Condition", ""].map((h) => el("th", {}, h))));
      for (const a of alerts) {
        t.appendChild(el("tr", {},
          el("td", {}, a.name), el("td", {}, a.query), el("td", {}, a.cron), el("td", {}, a.condition || "count > 0"),
          el("td", {}, roleAtLeast(ME.role, "power") ? el("button", { class: "btn-ghost btn-sm btn-danger", onclick: async () => { await API.del("/api/saved/" + a.id); renderAlerts(view); } }, "Delete") : null)));
      }
      savedWrap.appendChild(t);
    }
  } catch (ex) { savedWrap.innerHTML = ""; savedWrap.appendChild(el("div", { class: "empty" }, ex.message)); }
  try {
    const h = await API.get("/api/alerts/history");
    histWrap.innerHTML = "";
    if (!h.history || !h.history.length) histWrap.appendChild(el("div", { class: "empty" }, "No alerts have fired yet."));
    else {
      const t = el("table", { class: "grid" }, el("tr", {}, ...["Time", "Alert", "Severity", "Results", "Detail"].map((x) => el("th", {}, x))));
      for (const f of h.history) t.appendChild(el("tr", {},
        el("td", {}, fmtTime(f.fired_at)), el("td", {}, f.search_name),
        el("td", {}, el("span", { class: "badge sev-" + f.severity }, f.severity)),
        el("td", { class: "num" }, String(f.result_count)), el("td", {}, f.detail)));
      histWrap.appendChild(t);
    }
  } catch (ex) { histWrap.appendChild(el("div", { class: "empty" }, ex.message)); }
}

async function newAlert() {
  const name = prompt("Alert name:"); if (!name) return;
  const query = prompt("Search (BQL):", "error | stats count"); if (!query) return;
  const cron = prompt("Cron schedule (min hour dom mon dow):", "*/5 * * * *"); if (!cron) return;
  const condition = prompt("Condition:", "count > 0") || "count > 0";
  const severity = prompt("Severity (low/medium/high):", "medium") || "medium";
  const actions = JSON.stringify({ severity, actions: ["notable"] });
  try {
    await API.post("/api/saved", { name, query, earliest: "-5m", latest: "now", is_alert: true, cron, condition, actions });
    toast("Alert created"); renderAlerts(document.getElementById("view"));
  } catch (ex) { toast(ex.message, "error"); }
}

// ===================== SECURITY =====================
async function renderSecurity(view) {
  view.appendChild(pageHead("Security", "Notable events and incident triage"));
  const stats = el("div", { class: "stat-row" });
  const wrap = el("div", {}, el("div", { class: "spinner" }, "Loading..."));
  view.appendChild(stats);
  view.appendChild(wrap);
  try {
    const r = await API.get("/api/notable");
    const items = r.notable || [];
    const bySev = { high: 0, medium: 0, low: 0 };
    let open = 0;
    for (const n of items) { bySev[n.severity] = (bySev[n.severity] || 0) + 1; if (n.status !== "closed") open++; }
    stats.appendChild(statCard(items.length, "Total notable"));
    stats.appendChild(statCard(open, "Open"));
    stats.appendChild(statCard(bySev.high || 0, "High severity"));
    wrap.innerHTML = "";
    if (!items.length) { wrap.appendChild(el("div", { class: "empty" }, "No notable events. Create a security alert to populate this queue.")); return; }
    const t = el("table", { class: "grid" }, el("tr", {}, ...["Time", "Rule", "Severity", "Status", "Entity", "MITRE", ""].map((h) => el("th", {}, h))));
    for (const n of items) {
      t.appendChild(el("tr", {},
        el("td", {}, fmtTime(n.created_at)), el("td", {}, n.rule_name),
        el("td", {}, el("span", { class: "badge sev-" + n.severity }, n.severity)),
        el("td", {}, n.status), el("td", {}, n.entity || "-"), el("td", {}, n.mitre || "-"),
        el("td", {}, roleAtLeast(ME.role, "power") ? statusSelect(n, view) : null)));
    }
    wrap.appendChild(t);
  } catch (ex) { wrap.innerHTML = ""; wrap.appendChild(el("div", { class: "empty" }, ex.message)); }
}

function statusSelect(n, view) {
  const sel = el("select", { class: "time-select", style: "padding:3px 8px" },
    ...["new", "in_progress", "closed"].map((s) => el("option", { value: s, ...(s === n.status ? { selected: "" } : {}) }, s)));
  sel.addEventListener("change", async () => {
    try { await API.post("/api/notable/" + n.id + "/status", { status: sel.value }); toast("Updated"); }
    catch (ex) { toast(ex.message, "error"); }
  });
  return sel;
}

function statCard(n, label) {
  return el("div", { class: "stat" }, el("div", { class: "n" }, fmtNum(n)), el("div", { class: "l" }, label));
}

// ===================== NETWORK (devices) =====================
async function renderNetwork(view) {
  const canScan = roleAtLeast(ME.role, "power");
  const actions = [];
  if (canScan) actions.push(el("button", { class: "btn-primary", onclick: discover }, "Discover my network"));
  actions.push(el("button", { class: "btn-ghost", onclick: () => renderNetwork(view) }, "Refresh"));
  view.appendChild(pageHead("Network", "Live devices discovered on your networks", actions));

  const netLine = el("div", { class: "page-sub", style: "margin-bottom:12px" }, "Detecting local networks...");
  view.appendChild(netLine);
  const stats = el("div", { class: "stat-row" });
  view.appendChild(stats);
  const wrap = el("div", {}, el("div", { class: "spinner" }, "Loading devices..."));
  view.appendChild(wrap);

  try {
    const n = await API.get("/api/recon/networks");
    netLine.textContent = (n.networks && n.networks.length) ? "Local networks: " + n.networks.join(", ") : "No local network detected";
  } catch (_) { netLine.textContent = ""; }

  async function load() {
    try {
      const r = await API.get("/api/assets");
      const assets = r.assets || [];
      stats.innerHTML = "";
      stats.appendChild(statCard(assets.length, "Devices"));
      stats.appendChild(statCard(new Set(assets.map((a) => a.vendor).filter(Boolean)).size, "Vendors"));
      stats.appendChild(statCard(assets.filter((a) => a.status === "up").length, "Online"));
      wrap.innerHTML = "";
      if (!assets.length) {
        wrap.appendChild(el("div", { class: "empty" }, canScan ? "No devices yet. Click “Discover my network” to scan your LAN." : "No devices discovered yet."));
        return;
      }
      const t = el("table", { class: "grid" }, el("tr", {}, ...["IP", "Hostname", "MAC", "Vendor", "OS", "Open ports", "Source", "Last seen"].map((h) => el("th", {}, h))));
      for (const a of assets) {
        t.appendChild(el("tr", {},
          el("td", {}, a.ip), el("td", {}, a.hostname || "-"),
          el("td", {}, a.mac || "-"), el("td", {}, a.vendor || "-"),
          el("td", {}, a.os || "-"), el("td", {}, a.open_ports || "-"),
          el("td", {}, a.source), el("td", {}, fmtTime(a.last_seen))));
      }
      wrap.appendChild(t);
    } catch (ex) { wrap.innerHTML = ""; wrap.appendChild(el("div", { class: "empty" }, ex.message)); }
  }

  async function discover() {
    const ref = prompt("Authorization reference (you must own or be allowed to scan this network):", "home-lab");
    if (!ref) return;
    try {
      await API.post("/api/recon/scan", { connector: "netdiscover", target: "", profile: "arp", confirmed: true, authorization_ref: ref });
      toast("Discovery started; devices will appear shortly");
      let n = 0;
      const timer = setInterval(() => { if (location.hash === "#/network" && n++ < 15) load(); else clearInterval(timer); }, 3000);
    } catch (ex) { toast(ex.message, "error"); }
  }

  load();
}

// ===================== RECON =====================
let reconConnectors = [];
async function renderRecon(view) {
  view.appendChild(pageHead("Recon & scanning", "Run authorized security tools and pull results into Daru"));
  const layout = el("div", { class: "search-layout" });
  const left = el("div", { class: "fields-panel", style: "max-height:none" });
  const right = el("div", {});
  layout.appendChild(left);
  layout.appendChild(right);
  view.appendChild(layout);

  left.appendChild(el("h4", {}, "New scan"));
  const form = el("div", { class: "form", style: "max-width:none;gap:9px" });
  const canScan = roleAtLeast(ME.role, "power");

  const connSel = el("select", {});
  const profSel = el("select", {});
  const targetIn = el("input", { placeholder: "target (host, CIDR, URL, domain)" });
  const portsIn = el("input", { placeholder: "ports (optional, e.g. 1-1000)" });
  const authIn = el("input", { placeholder: "authorization reference (ticket / ROE id)" });
  const extChk = el("input", { type: "checkbox" });
  const confirmChk = el("input", { type: "checkbox" });
  const runBtn = el("button", { class: "btn-primary", onclick: submit }, "Run scan");
  const formErr = el("p", { class: "form-error" });

  function fillProfiles() {
    const c = reconConnectors.find((x) => x.name === connSel.value);
    profSel.innerHTML = "";
    (c?.profiles || []).forEach((p) => profSel.appendChild(el("option", { value: p.name }, `${p.name} - ${p.desc}`)));
    left.querySelector(".conn-hint").textContent = c ? `${c.desc}  (${c.target_kind}${c.needs_root ? ", needs root" : ""})` : "";
    targetIn.placeholder = "target: " + (c?.target_kind || "host");
  }
  connSel.addEventListener("change", fillProfiles);

  form.appendChild(el("label", {}, "Tool", connSel));
  form.appendChild(el("div", { class: "conn-hint", style: "font-size:11.5px;color:var(--muted)" }));
  form.appendChild(el("label", {}, "Profile", profSel));
  form.appendChild(el("label", {}, "Target", targetIn));
  form.appendChild(el("label", {}, "Ports", portsIn));
  form.appendChild(el("label", {}, "Authorization reference", authIn));
  form.appendChild(el("label", { style: "flex-direction:row;align-items:center;gap:8px" }, extChk, el("span", {}, "Allow external (public) target")));
  form.appendChild(el("label", { style: "flex-direction:row;align-items:center;gap:8px" }, confirmChk, el("span", {}, "I am authorized to test this target")));
  form.appendChild(runBtn);
  form.appendChild(formErr);
  if (!canScan) { form.querySelectorAll("input,select,button").forEach((e) => e.disabled = true); formErr.textContent = "Power or admin role required to run scans."; }
  left.appendChild(form);

  right.appendChild(el("h3", { style: "margin:0 0 10px;font-size:15px" }, "Scan history"));
  const histWrap = el("div", {}, el("div", { class: "spinner" }, "Loading..."));
  right.appendChild(histWrap);

  try {
    const r = await API.get("/api/recon/connectors");
    reconConnectors = r.connectors || [];
    connSel.innerHTML = "";
    for (const c of reconConnectors) {
      connSel.appendChild(el("option", { value: c.name, ...(c.available ? {} : { disabled: "" }) },
        c.name + (c.available ? "" : " (not installed)") + "  · " + c.category));
    }
    const firstAvail = reconConnectors.find((c) => c.available);
    if (firstAvail) connSel.value = firstAvail.name;
    fillProfiles();
  } catch (ex) { formErr.textContent = ex.message; }

  async function submit() {
    formErr.textContent = "";
    try {
      const r = await API.post("/api/recon/scan", {
        connector: connSel.value, target: targetIn.value.trim(), profile: profSel.value,
        ports: portsIn.value.trim(), authorization_ref: authIn.value.trim(),
        allow_external: extChk.checked, confirmed: confirmChk.checked,
      });
      toast("Scan started");
      loadHistory();
    } catch (ex) { formErr.textContent = ex.message; }
  }

  async function loadHistory() {
    try {
      const r = await API.get("/api/recon/scans");
      histWrap.innerHTML = "";
      if (!r.scans || !r.scans.length) { histWrap.appendChild(el("div", { class: "empty" }, "No scans yet.")); return; }
      const t = el("table", { class: "grid" }, el("tr", {}, ...["Started", "Tool", "Target", "Profile", "Status", "Findings", ""].map((h) => el("th", {}, h))));
      for (const sc of r.scans) {
        t.appendChild(el("tr", {},
          el("td", {}, fmtTime(sc.started_at)), el("td", {}, sc.connector), el("td", {}, sc.target),
          el("td", {}, sc.profile), el("td", {}, statusBadge(sc.status)),
          el("td", { class: "num" }, String(sc.finding_count)),
          el("td", {}, el("button", { class: "btn-ghost btn-sm", onclick: () => viewFindings(sc) }, "View"))));
      }
      histWrap.appendChild(t);
    } catch (ex) { histWrap.innerHTML = ""; histWrap.appendChild(el("div", { class: "empty" }, ex.message)); }
  }

  async function viewFindings(sc) {
    const r = await API.get(`/api/recon/scans/${sc.id}/findings`);
    const rows = r.findings || [];
    const panel = el("div", { class: "results", style: "margin-top:12px" });
    panel.appendChild(el("div", { class: "results-tabs" }, el("span", { class: "results-tab active" }, `${sc.connector} on ${sc.target} - ${rows.length} findings`)));
    const body = el("div", { class: "results-body" });
    if (!rows.length) body.appendChild(el("div", { class: "empty" }, sc.error || "No findings."));
    else {
      const t = el("table", { class: "grid" }, el("tr", {}, ...["Severity", "Port", "Service", "Title", "Detail"].map((h) => el("th", {}, h))));
      for (const f of rows) t.appendChild(el("tr", {},
        el("td", {}, el("span", { class: "badge sev-" + (f.severity || "low") }, f.severity)),
        el("td", {}, f.port || "-"), el("td", {}, f.service || "-"), el("td", {}, f.title), el("td", {}, f.detail || "")));
      body.appendChild(t);
    }
    panel.appendChild(body);
    const existing = right.querySelector(".results");
    if (existing) existing.remove();
    right.appendChild(panel);
  }

  loadHistory();
  // Auto-refresh history while scans may be running.
  const timer = setInterval(() => { if (location.hash === "#/recon") loadHistory(); else clearInterval(timer); }, 4000);
}

function statusBadge(s) {
  const cls = s === "completed" ? "sev-low" : s === "failed" ? "sev-high" : "sev-medium";
  return el("span", { class: "badge " + cls }, s);
}

// ===================== ADMIN =====================
async function renderAdmin(view) {
  view.appendChild(pageHead("Administration", "Users, indexes, and ingest tokens"));
  const tabs = el("div", { class: "results-tabs", style: "margin-bottom:16px" });
  const body = el("div", {});
  const defs = [["users", "Users"], ["indexes", "Indexes"], ["tokens", "Ingest tokens"], ["system", "System"]];
  let active = "users";
  function draw() {
    body.innerHTML = "";
    if (active === "users") adminUsers(body);
    else if (active === "indexes") adminIndexes(body);
    else if (active === "tokens") adminTokens(body);
    else adminSystem(body);
    [...tabs.children].forEach((c) => c.classList.toggle("active", c.dataset.t === active));
  }
  for (const [t, l] of defs) {
    const b = el("button", { class: "results-tab", onclick: () => { active = t; draw(); } }, l);
    b.dataset.t = t; tabs.appendChild(b);
  }
  view.appendChild(tabs); view.appendChild(body); draw();
}

async function adminSystem(body) {
  // Privilege status: works in both root and non-root mode.
  const statusWrap = el("div", { class: "notice" }, "Checking privileges...");
  body.appendChild(statusWrap);
  try {
    const sys = await API.get("/api/system");
    statusWrap.innerHTML = "";
    if (sys.running_as_root) {
      statusWrap.style.borderLeftColor = "var(--green)";
      statusWrap.appendChild(el("b", { style: "color:var(--green)" }, "Running as root. "));
      statusWrap.appendChild(document.createTextNode("All scan and capture tools work without extra setup. Keep this instance local and not exposed."));
    } else {
      statusWrap.style.borderLeftColor = "var(--amber)";
      statusWrap.appendChild(el("b", { style: "color:var(--amber)" }, "Running as a normal user. "));
      statusWrap.appendChild(document.createTextNode("Most tools work; raw-socket scans (arp-scan, nmap SYN, masscan, capture) need CAP_NET_RAW. Run scripts/grant-capabilities.sh once, or start with scripts/serve-root.sh."));
    }
    statusWrap.appendChild(el("div", { style: "color:var(--muted);font-size:12px;margin-top:6px" },
      `host ${sys.hostname || "?"} . uid ${sys.uid} . pid ${sys.pid}`));
  } catch (ex) {
    statusWrap.textContent = ex.message;
  }

  // Update-tools button.
  const btn = el("button", { class: "btn-primary" }, "Update all security tools");
  const hint = el("span", { style: "color:var(--muted);font-size:12.5px;margin-left:12px" },
    "Updates installed scanners (apt, go install, pipx) and nuclei templates. Can take a few minutes.");
  body.appendChild(el("div", { class: "toolbar", style: "margin-top:18px" }, btn, hint));
  const out = el("pre", { class: "token-reveal", style: "display:none;white-space:pre-wrap;max-height:50vh;overflow:auto" });
  body.appendChild(out);

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    const label = btn.textContent;
    btn.textContent = "Updating... (this can take several minutes)";
    out.style.display = "block";
    out.textContent = "Starting tool update. Please wait; do not close this tab...\n";
    try {
      const r = await API.post("/api/admin/update-tools", {});
      out.textContent = r.output || "(no output)";
      if (r.ok) toast("Tools updated");
      else toast(r.error || "Update finished with warnings", "error");
    } catch (ex) {
      out.textContent += "\n" + ex.message;
      toast(ex.message, "error");
    } finally {
      btn.disabled = false;
      btn.textContent = label;
      out.scrollTop = out.scrollHeight;
    }
  });
}

async function adminUsers(body) {
  body.appendChild(el("div", { class: "toolbar" }, el("button", { class: "btn-ghost", onclick: () => createUserForm(body) }, "+ Add user")));
  const wrap = el("div", {}, el("div", { class: "spinner" }, "Loading..."));
  body.appendChild(wrap);
  try {
    const r = await API.get("/api/admin/users");
    wrap.innerHTML = "";
    const t = el("table", { class: "grid" }, el("tr", {}, ...["Username", "Role", "Email", "Status", "Actions"].map((h) => el("th", {}, h))));
    for (const u of r.users) {
      t.appendChild(el("tr", {},
        el("td", {}, u.username), el("td", {}, el("span", { class: "role-badge" }, u.role)),
        el("td", {}, u.email || "-"), el("td", {}, u.disabled ? "disabled" : "active"),
        el("td", {}, el("div", { class: "row-actions" },
          el("button", { class: "btn-ghost btn-sm", onclick: () => changeRole(u) }, "Role"),
          el("button", { class: "btn-ghost btn-sm", onclick: () => resetPw(u) }, "Password"),
          u.username !== ME.username ? el("button", { class: "btn-ghost btn-sm btn-danger", onclick: () => toggleDisabled(u, body) }, u.disabled ? "Enable" : "Disable") : null))));
    }
    wrap.appendChild(t);
  } catch (ex) { wrap.innerHTML = ""; wrap.appendChild(el("div", { class: "empty" }, ex.message)); }
}

function createUserForm(body) {
  const u = prompt("New username:"); if (!u) return;
  const p = prompt("Password (min 8 chars):"); if (!p) return;
  const role = prompt("Role (user/power/admin):", "user") || "user";
  API.post("/api/admin/users", { username: u, password: p, role })
    .then(() => { toast("User created"); adminUsers((body.innerHTML = "", body)); })
    .catch((ex) => toast(ex.message, "error"));
}
function changeRole(u) {
  const role = prompt(`Role for ${u.username} (user/power/admin):`, u.role); if (!role) return;
  API.post(`/api/admin/users/${u.username}/role`, { role }).then(() => { toast("Role updated"); route(); }).catch((ex) => toast(ex.message, "error"));
}
function resetPw(u) {
  const p = prompt(`New password for ${u.username}:`); if (!p) return;
  API.post(`/api/admin/users/${u.username}/password`, { password: p }).then(() => toast("Password updated")).catch((ex) => toast(ex.message, "error"));
}
function toggleDisabled(u, body) {
  API.post(`/api/admin/users/${u.username}/disabled`, { disabled: !u.disabled }).then(() => { toast("Updated"); adminUsers((body.innerHTML = "", body)); }).catch((ex) => toast(ex.message, "error"));
}

async function adminIndexes(body) {
  body.appendChild(el("div", { class: "toolbar" }, el("button", { class: "btn-ghost", onclick: () => {
    const name = prompt("Index name:"); if (!name) return;
    const days = parseInt(prompt("Retention days:", "90") || "90", 10);
    API.post("/api/admin/indexes", { name, retention_days: days }).then(() => { toast("Index created"); adminIndexes((body.innerHTML = "", body)); }).catch((ex) => toast(ex.message, "error"));
  } }, "+ Add index")));
  const wrap = el("div", {}, el("div", { class: "spinner" }, "Loading..."));
  body.appendChild(wrap);
  try {
    const r = await API.get("/api/indexes");
    wrap.innerHTML = "";
    const t = el("table", { class: "grid" }, el("tr", {}, ...["Index", "Events", "Size (bytes)", "Retention", "Oldest", "Newest"].map((h) => el("th", {}, h))));
    for (const i of r.indexes || []) t.appendChild(el("tr", {},
      el("td", {}, i.name), el("td", { class: "num" }, fmtNum(i.events)), el("td", { class: "num" }, fmtNum(i.bytes)),
      el("td", {}, i.retention_days + "d"), el("td", {}, fmtTime(i.oldest)), el("td", {}, fmtTime(i.newest))));
    wrap.appendChild(t);
  } catch (ex) { wrap.innerHTML = ""; wrap.appendChild(el("div", { class: "empty" }, ex.message)); }
}

async function adminTokens(body) {
  body.appendChild(el("div", { class: "toolbar" }, el("button", { class: "btn-ghost", onclick: () => createToken(body) }, "+ Create token")));
  body.appendChild(el("div", { class: "notice" }, "Send logs with the Splunk HEC format to /services/collector, or raw text to /services/collector/raw, using header  Authorization: Splunk <token>"));
  const wrap = el("div", {}, el("div", { class: "spinner" }, "Loading..."));
  body.appendChild(wrap);
  try {
    const r = await API.get("/api/admin/tokens");
    wrap.innerHTML = "";
    if (!r.tokens || !r.tokens.length) { wrap.appendChild(el("div", { class: "empty" }, "No ingest tokens yet.")); return; }
    const t = el("table", { class: "grid" }, el("tr", {}, ...["Name", "Default index", "Status", ""].map((h) => el("th", {}, h))));
    for (const tok of r.tokens) t.appendChild(el("tr", {},
      el("td", {}, tok.name), el("td", {}, tok.default_index), el("td", {}, tok.disabled ? "disabled" : "active"),
      el("td", {}, !tok.disabled ? el("button", { class: "btn-ghost btn-sm btn-danger", onclick: async () => { await API.post(`/api/admin/tokens/${encodeURIComponent(tok.name)}/disable`, {}); adminTokens((body.innerHTML = "", body)); } }, "Disable") : null)));
    wrap.appendChild(t);
  } catch (ex) { wrap.innerHTML = ""; wrap.appendChild(el("div", { class: "empty" }, ex.message)); }
}

function createToken(body) {
  const name = prompt("Token name:"); if (!name) return;
  const idx = prompt("Default index:", "main") || "main";
  API.post("/api/admin/tokens", { name, default_index: idx }).then((r) => {
    const box = el("div", { class: "token-reveal" }, "Copy this token now, it will not be shown again:\n\n" + r.token);
    body.insertBefore(el("div", { class: "notice", style: "border-left-color:var(--amber)" }, box), body.children[2]);
    adminTokens((body.innerHTML = body.innerHTML, body));
  }).catch((ex) => toast(ex.message, "error"));
}

boot();
