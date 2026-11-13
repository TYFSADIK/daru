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
    const toggle = document.getElementById("nav-toggle");
    if (toggle) toggle.addEventListener("click", () => {
      const sb = document.getElementById("sidebar");
      const open = sb && sb.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
      toggle.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
    });
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
function csrfToken() {
  const m = document.cookie.match(/(?:^|; )daru_csrf=([^;]*)/);
  return m ? decodeURIComponent(m[1]) : "";
}
const API = {
  async call(method, path, body) {
    const opt = { method, headers: {} };
    if (method !== "GET" && method !== "HEAD") {
      const tok = csrfToken();
      if (tok) opt.headers["X-Daru-CSRF"] = tok;
    }
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
    // The CSP (style-src 'self') blocks style attributes, but not styles
    // set through the CSSOM, so inline styles go through n.style.
    else if (k === "style") n.style.cssText = v;
    else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) n.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null) continue;
    n.appendChild(typeof kid === "string" ? document.createTextNode(kid) : kid);
  }
  return n;
};
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"'\/]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "/": "&#x2F;" }[c]));
const fmtNum = (n) => Number(n).toLocaleString(undefined, { maximumFractionDigits: 2 });
const roleAtLeast = (r, min) => ({ user: 1, power: 2, admin: 3 }[r] || 0) >= ({ user: 1, power: 2, admin: 3 }[min] || 0);

// parseTime reads ClickHouse timestamps ("2026-11-06 12:00:00.000", UTC with
// no zone) and ISO strings. It returns null for anything else.
function parseTime(v) {
  if (v == null || v === "") return null;
  const s = String(v).trim();
  if (!/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/.test(s)) return null;
  const iso = s.replace(" ", "T");
  const d = new Date(/[zZ]|[+-]\d{2}:?\d{2}$/.test(iso) ? iso : iso + "Z");
  return isNaN(d.getTime()) || d.getUTCFullYear() < 1971 ? null : d;
}
const pad2 = (n) => String(n).padStart(2, "0");

// fmtTime shows a timestamp in the viewer's local time, to the second.
function fmtTime(v) {
  const d = parseTime(v);
  if (!d) return v == null ? "" : String(v);
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
}

// timeAgo is a short relative time: "just now", "12m ago", "3h ago", "2d ago".
function timeAgo(v) {
  const d = parseTime(v);
  if (!d) return "";
  const sec = Math.round((Date.now() - d.getTime()) / 1000);
  if (sec < 0) return "in the future";
  if (sec < 45) return "just now";
  if (sec < 3600) return Math.round(sec / 60) + "m ago";
  if (sec < 86400) return Math.round(sec / 3600) + "h ago";
  if (sec < 86400 * 30) return Math.round(sec / 86400) + "d ago";
  return fmtTime(v).slice(0, 10);
}

// timeTd is a table cell with the relative time and the exact local time on
// hover. Empty or epoch-zero values show the fallback text.
function timeTd(v, fallback = "-") {
  const d = parseTime(v);
  if (!d) return el("td", { class: "nowrap" }, fallback);
  return el("td", { class: "time-rel", title: fmtTime(v) + " (" + Intl.DateTimeFormat().resolvedOptions().timeZone + ")" },
    timeAgo(v), el("small", {}, fmtTime(v).slice(11, 16)));
}

function toast(msg, kind = "info") {
  const t = el("div", { class: "notice", style: "position:fixed;top:16px;right:16px;z-index:999;max-width:360px" }, msg);
  if (kind === "error") t.style.borderLeftColor = "var(--red)";
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}


// --- modal forms (replace prompt() so secrets are never typed in clear text) ---
function openModal(title, sub, fields, submitLabel) {
  return new Promise((resolve) => {
    const overlay = el("div", { class: "modal-overlay" });
    const dialog = el("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": title });
    dialog.appendChild(el("h3", {}, title));
    if (sub) dialog.appendChild(el("p", { class: "modal-sub" }, sub));
    const form = el("form", { class: "form" });
    const err = el("p", { class: "form-error" });
    const inputs = {};
    for (const f of fields) {
      const label = el("label", {}, f.label);
      let input;
      if (f.type === "select") {
        input = el("select", {}, ...f.options.map((o) => el("option", { value: o.value, ...(o.value === f.value ? { selected: "" } : {}) }, o.label)));
      } else if (f.type === "checkbox") {
        input = el("input", { type: "checkbox", ...(f.value ? { checked: "" } : {}) });
        label.style.flexDirection = "row"; label.style.alignItems = "center"; label.style.gap = "8px";
      } else if (f.type === "textarea") {
        input = el("textarea", { rows: f.rows || "3", placeholder: f.placeholder || "", spellcheck: "false" });
        input.value = f.value || "";
      } else {
        input = el("input", { type: f.type || "text", placeholder: f.placeholder || "", autocomplete: f.autocomplete || "off" });
        if (f.value != null) input.value = f.value;
        if (f.minlength) input.minLength = f.minlength;
      }
      if (f.required) input.required = true;
      if (f.type === "checkbox") label.appendChild(input);
      else label.appendChild(input);
      if (f.help) form.appendChild(el("div", { class: "field-help" }, f.help));
      form.appendChild(label);
      inputs[f.name] = input;
    }
    form.appendChild(err);
    const actions = el("div", { class: "modal-actions" });
    const cancel = el("button", { type: "button", class: "btn-ghost" }, "Cancel");
    const submit = el("button", { type: "submit", class: "btn-primary" }, submitLabel || "Save");
    actions.appendChild(cancel); actions.appendChild(submit);
    form.appendChild(actions);
    dialog.appendChild(form);
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
    const close = (value) => { overlay.remove(); document.removeEventListener("keydown", onKey, true); resolve(value); };
    const onKey = (e) => { if (e.key === "Escape") { e.stopPropagation(); close(null); } };
    document.addEventListener("keydown", onKey, true);
    overlay.addEventListener("click", (e) => { if (e.target === overlay) close(null); });
    cancel.addEventListener("click", () => close(null));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      err.textContent = "";
      const out = {};
      for (const f of fields) {
        const input = inputs[f.name];
        out[f.name] = f.type === "checkbox" ? input.checked : input.value.trim();
        if (f.validate) {
          const problem = f.validate(out[f.name], out);
          if (problem) { err.textContent = problem; input.focus(); return; }
        }
      }
      close(out);
    });
    const first = dialog.querySelector("input, select, textarea");
    if (first) first.focus();
  });
}

// confirmDialog replaces confirm() for destructive actions.
function confirmDialog(message, okLabel) {
  return openModal("Please confirm", message, [], okLabel || "Delete").then((v) => v !== null);
}

// validateCron checks a 5-field cron expression client side. Returns an
// error string, or "" when the value is valid.
function validateCron(v) {
  const parts = String(v || "").trim().split(/\s+/);
  if (parts.length !== 5) return "Cron needs 5 fields: minute hour day month weekday";
  const ranges = [[0, 59], [0, 23], [1, 31], [1, 12], [0, 7]];
  for (let i = 0; i < 5; i++) {
    const part = parts[i];
    if (!/^[0-9*,\/\-]+$/.test(part)) return "Cron field " + (i + 1) + " has an invalid character: " + part;
    for (const chunk of part.split(",")) {
      const step = chunk.split("/")[1];
      const base = chunk.split("/")[0];
      if (step && !/^\d+$/.test(step)) return "Cron step must be a number: " + chunk;
      if (base === "*") continue;
      for (const seg of base.split("-")) {
        if (!/^\d+$/.test(seg)) return "Cron field " + (i + 1) + " is invalid: " + part;
        const n = parseInt(seg, 10);
        if (n < ranges[i][0] || n > ranges[i][1]) return "Cron field " + (i + 1) + " is out of range: " + part;
      }
    }
  }
  return "";
}

// --- mobile navigation ---
function closeSidebar() {
  const sb = document.getElementById("sidebar");
  const btn = document.getElementById("nav-toggle");
  if (sb) sb.classList.remove("open");
  if (btn) { btn.setAttribute("aria-expanded", "false"); btn.setAttribute("aria-label", "Open navigation"); }
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

// Single sign on: the button appears only when the server has OIDC set up.
// A failed SSO attempt lands back here with ?sso=failed; the reason is
// logged server side and deliberately not shown.
let ssoChecked = false;
function setupSSO() {
  if (ssoChecked) return;
  ssoChecked = true;
  for (const [endpoint, id] of [["/api/oidc/config", "sso-btn"], ["/api/saml/config", "saml-btn"]]) {
    fetch(endpoint, { credentials: "same-origin" })
      .then((r) => r.ok ? r.json() : { enabled: false })
      .then((c) => { if (c.enabled) document.getElementById(id).classList.remove("hidden"); })
      .catch(() => {});
  }
  const params = new URLSearchParams(location.search);
  if (params.get("sso") === "failed") {
    document.getElementById("login-error").textContent = "Single sign on failed. Your account may not exist in Daru, may be disabled, or your email domain may not be allowed. Ask an administrator.";
    history.replaceState(null, "", location.pathname + location.hash);
  }
}

function showLogin() {
  setupSSO();
  document.body.classList.add("signed-out");
  document.getElementById("app").classList.add("hidden");
  document.getElementById("login").classList.remove("hidden");
}

document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const err = document.getElementById("login-error");
  err.textContent = "";
  try {
    const r = await API.post("/api/login", { username: f.username.value, password: f.password.value, totp: f.totp ? f.totp.value.trim() : "" });
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
  document.body.classList.remove("signed-out");
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
  { path: "#/live", label: "Live Monitor", icon: "⦿", min: "user", render: renderLive },
  { path: "#/recon", label: "Recon", icon: "◎", min: "user", render: renderRecon },
  { path: "#/admin", label: "Admin", icon: "⚙", min: "admin", render: renderAdmin },
  { path: "#/account", label: "Account", icon: "◔", min: "user", render: renderAccount },
];

// Sidebar icons: one stroke style, drawn as SVG through the DOM so the strict
// CSP allows them. Keys are route paths; shapes are [tag, attributes].
const NAV_ICONS = {
  "#/search": [["circle", { cx: 11, cy: 11, r: 7 }], ["path", { d: "M20 20l-4-4" }]],
  "#/dashboards": [["rect", { x: 3, y: 3, width: 7, height: 9, rx: 1.5 }], ["rect", { x: 14, y: 3, width: 7, height: 5, rx: 1.5 }], ["rect", { x: 14, y: 12, width: 7, height: 9, rx: 1.5 }], ["rect", { x: 3, y: 16, width: 7, height: 5, rx: 1.5 }]],
  "#/alerts": [["path", { d: "M6 16V11a6 6 0 1 1 12 0v5l1.5 2h-15z" }], ["path", { d: "M10 20a2 2 0 0 0 4 0" }]],
  "#/security": [["path", { d: "M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6z" }], ["path", { d: "M9 12l2 2 4-4" }]],
  "#/network": [["circle", { cx: 12, cy: 5, r: 2.2 }], ["circle", { cx: 5, cy: 19, r: 2.2 }], ["circle", { cx: 19, cy: 19, r: 2.2 }], ["path", { d: "M12 7.2v4.3M12 11.5L6.3 17M12 11.5l5.7 5.5" }]],
  "#/live": [["path", { d: "M3 12h4l3-8 4 16 3-8h4" }]],
  "#/recon": [["circle", { cx: 12, cy: 12, r: 8.5 }], ["circle", { cx: 12, cy: 12, r: 4.5 }], ["circle", { cx: 12, cy: 12, r: 0.8 }]],
  "#/admin": [["path", { d: "M4 7h10M18 7h2M4 17h2M10 17h10" }], ["circle", { cx: 16, cy: 7, r: 2 }], ["circle", { cx: 8, cy: 17, r: 2 }]],
  "#/account": [["circle", { cx: 12, cy: 8.5, r: 3.8 }], ["path", { d: "M4.5 20c1.3-3.6 4.2-5.3 7.5-5.3s6.2 1.7 7.5 5.3" }]],
};
function navIcon(path, fallback) {
  const shapes = NAV_ICONS[path];
  if (!shapes) return el("span", { class: "ic" }, fallback);
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  for (const [tag, attrs] of shapes) {
    const n = document.createElementNS(ns, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    svg.appendChild(n);
  }
  return el("span", { class: "ic" }, svg);
}

function buildNav() {
  const nav = document.getElementById("nav");
  nav.innerHTML = "";
  for (const r of ROUTES) {
    if (!roleAtLeast(ME.role, r.min)) continue;
    nav.appendChild(el("a", { href: r.path, "data-path": r.path },
      navIcon(r.path, r.icon), r.label));
  }
}

window.addEventListener("hashchange", route);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeSidebar(); });
function route() {
  closeSidebar();
  const hash = location.hash || "#/search";
  const parts = hash.split("/");
  const base = "#/" + parts[1];
  // Per-tool dashboard: #/tool/<name>
  if (base === "#/tool" && parts[2]) {
    document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.getAttribute("data-path") === "#/recon"));
    const view = document.getElementById("view");
    view.innerHTML = "";
    renderToolPage(view, decodeURIComponent(parts.slice(2).join("/")));
    return;
  }
  // Shared dashboard link: #/dashboard/<id>
  if (base === "#/dashboard" && parts[2]) {
    document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.getAttribute("data-path") === "#/dashboards"));
    const view = document.getElementById("view");
    view.innerHTML = "";
    openDashboard(decodeURIComponent(parts.slice(2).join("/")));
    return;
  }
  // Per-device intelligence: #/device/<ip>
  if (base === "#/device" && parts[2]) {
    document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.getAttribute("data-path") === "#/network"));
    const view = document.getElementById("view");
    view.innerHTML = "";
    renderDevicePage(view, decodeURIComponent(parts.slice(2).join("/")));
    return;
  }
  document.querySelectorAll("#nav a").forEach((a) => {
    const isActive = a.getAttribute("data-path") === base;
    a.classList.toggle("active", isActive);
    if (isActive) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  const main = document.getElementById("view");
  if (main) main.focus({ preventScroll: true });
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
  // Quick queries that connect the SIEM side to recon/capture data.
  const examples = [
    ["Captured packets", "search index=network sourcetype=packet | stats count by proto"],
    ["Device traffic (by destination)", "search index=network | top app_host"],
    ["Recon findings", "search index=recon | stats count by connector, severity"],
    ["Open ports found", 'search index=recon service=open-port OR title="*open*" | stats count by target'],
    ["All logs", "search index=main | stats count by sourcetype"],
  ];
  const chips = el("div", { style: "display:flex;gap:8px;flex-wrap:wrap;margin:-4px 0 12px" });
  for (const [label, q] of examples) {
    chips.appendChild(el("button", { class: "btn-ghost btn-sm", onclick: () => { box.value = q; timeSel.value = "-7d"; run(); } }, label));
  }
  view.appendChild(chips);
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
    const v = await openModal("Save search", "Save this query for reuse, or schedule it as an alert.", [
      { name: "name", label: "Name", type: "text", required: true, placeholder: "e.g. Failed logins" },
      { name: "is_alert", label: "Schedule as an alert (run on a cron schedule)", type: "checkbox", value: false },
      { name: "cron", label: "Cron schedule (minute hour day month weekday)", type: "text", value: "*/5 * * * *",
        validate: (val, all) => all.is_alert ? validateCron(val) : "",
        help: "Only used when scheduled as an alert. Example: */5 * * * * runs every 5 minutes." },
      { name: "condition", label: "Alert condition", type: "text", value: "count > 0",
        help: "Only used when scheduled as an alert." },
      { name: "severity", label: "Severity", type: "select", value: "medium",
        options: [{ value: "low", label: "low" }, { value: "medium", label: "medium" }, { value: "high", label: "high" }] },
      { name: "webhook", label: "Webhook URL (optional)", type: "text", placeholder: "https://example.com/hook",
        help: "Stored with the alert actions. The current scheduler only opens a notable event; webhook delivery is a scheduler feature, not yet implemented server side." },
    ], "Save");
    if (!v) return;
    const body = { name: v.name, query: box.value.trim(), earliest: timeSel.value, latest: "now" };
    if (v.is_alert) {
      body.is_alert = true;
      body.cron = v.cron;
      body.condition = v.condition || "count > 0";
      const actions = { severity: v.severity, actions: ["notable"] };
      if (v.webhook) { actions.actions.push("webhook"); actions.webhook = v.webhook; }
      body.actions = JSON.stringify(actions);
    }
    try {
      await API.post("/api/saved", body);
      toast(v.is_alert ? "Scheduled alert created" : "Saved search created");
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
  // Transforming searches (stats, timechart) have no field list: give the
  // results the full width instead of an empty side panel.
  if (fieldsPanel.parentElement) fieldsPanel.parentElement.classList.toggle("no-fields", !(r.fields && r.fields.length));

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
      chips.appendChild(el("span", { class: "chip" }, el("b", {}, k), "=" + String(row[k] == null ? "" : row[k])));
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
  table.appendChild(el("tr", {}, ...cols.map((c) => el("th", { scope: "col" }, c))));
  for (const row of r.rows) {
    table.appendChild(el("tr", {}, ...cols.map((c) => {
      const v = row[c];
      const isNum = typeof v === "number";
      return el("td", { class: isNum ? "num" : "" }, isNum ? fmtNum(v) : (c === "_time" ? fmtTime(v) : String(v == null ? "" : v)));
    })));
  }
  return el("div", { class: "table-scroll" }, table);
}

// niceMax rounds a chart maximum up to 1, 2, or 5 times a power of ten, so
// the axis reads 0 / 250 / 500 / 750 / 1,000 rather than odd values.
function niceMax(v) {
  if (!(v > 0)) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (v <= m * p) return m * p;
  return 10 * p;
}

function renderViz(r) {
  const cols = r.columns || [];
  const series = r.series && r.series.length ? r.series : cols.filter((c) => c !== "_time" && c !== (cols[0]));
  if (!r.rows.length) return el("div", { class: "empty" }, "Nothing to chart.");
  const xKey = r.kind === "timechart" ? "_time" : cols[0];
  const isTime = xKey === "_time";
  const xLabel = (v) => isTime ? fmtTime(v).slice(5, 16) : String(v == null ? "" : v);
  let max = 0;
  for (const row of r.rows) for (const s of series) max = Math.max(max, Number(row[s]) || 0);
  const top = niceMax(max);

  const palette = ["#5e81f4", "#4bb4a0", "#d6a24b", "#c97b6a", "#8b86d4", "#5aa9d6", "#a77bbf", "#6aa86b", "#c98aa8", "#7f8ca3", "#4e9e86", "#b06f6f"];
  const chart = el("div", { class: "chart" });
  const legend = el("div", { class: "viz-legend" });
  series.forEach((s, i) => legend.appendChild(el("span", {},
    el("span", { class: "viz-swatch", style: `background:${palette[i % palette.length]}` }), s)));
  chart.appendChild(legend);

  // Y axis labels top to bottom, and matching gridlines.
  const viz = el("div", { class: "viz" });
  const yAxis = el("div", { class: "viz-y" });
  const plot = el("div", { class: "viz-plot" });
  for (let i = 4; i >= 0; i--) {
    yAxis.appendChild(el("span", {}, fmtNum((top * i) / 4)));
    if (i > 0 && i < 4) plot.appendChild(el("div", { class: "viz-grid", style: `top:${100 - i * 25}%` }));
  }
  const bars = el("div", { class: "viz-bars" });
  const show = r.rows.slice(0, 60);
  for (const row of show) {
    const label = isTime ? fmtTime(row[xKey]) : xLabel(row[xKey]);
    const group = el("div", { style: "flex:1;display:flex;align-items:flex-end;gap:1px;height:100%;min-width:0" });
    for (let i = 0; i < series.length; i++) {
      const v = Number(row[series[i]]) || 0;
      group.appendChild(el("div", {
        style: `flex:1;height:${(v / top) * 100}%;background:${palette[i % palette.length]};border-radius:2px 2px 0 0;min-height:${v > 0 ? 2 : 0}px`,
        title: `${label}\n${series[i]}: ${fmtNum(v)}`,
      }));
    }
    bars.appendChild(group);
  }
  plot.appendChild(bars);
  viz.appendChild(yAxis);
  viz.appendChild(plot);
  // Up to five evenly spaced x labels.
  const xAxis = el("div", { class: "viz-x" });
  const ticks = Math.min(5, show.length);
  for (let t = 0; t < ticks; t++) {
    const idx = ticks === 1 ? 0 : Math.round((t * (show.length - 1)) / (ticks - 1));
    xAxis.appendChild(el("span", {}, xLabel(show[idx][xKey])));
  }
  viz.appendChild(xAxis);
  chart.appendChild(viz);
  if (r.rows.length > show.length) chart.appendChild(el("div", { class: "meta", style: "margin-top:8px" }, `Showing the first ${show.length} of ${fmtNum(r.rows.length)} rows.`));
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
  const shareLink = location.origin + location.pathname + "#/dashboard/" + encodeURIComponent(id);
  view.appendChild(pageHead("Dashboard", "", [
    el("button", { class: "btn-ghost", onclick: () => renderDashboards(view) }, "← Back"),
    el("button", { class: "btn-ghost", onclick: async () => {
      try { await navigator.clipboard.writeText(shareLink); toast("Share link copied"); }
      catch (_) { await openModal("Share link", "Copy this link:", [{ name: "link", label: "Dashboard link", type: "text", value: shareLink }], "Done"); }
    } }, "Share link"),
    el("button", { class: "btn-ghost", onclick: () => window.print() }, "Export PDF (print)"),
    el("button", { class: "btn-ghost", onclick: () => exportDashboardCSV(dCache.d, dCache.def) }, "Export CSV"),
  ]));
  const grid = el("div", { class: "cards", style: "grid-template-columns:repeat(auto-fill,minmax(360px,1fr))" }, el("div", { class: "spinner" }, "Loading..."));
  view.appendChild(grid);
  const dCache = { d: null, def: null };
  try {
    const d = await API.get("/api/dashboards/" + id);
    const def = JSON.parse(d.definition || "{}");
    dCache.d = d; dCache.def = def;
    grid.innerHTML = "";
    view.querySelector("h2").textContent = d.name;
    for (const panel of def.panels || []) {
      const card = el("div", { class: "card" }, el("h3", {}, panel.title || "Panel"), el("div", { class: "spinner" }, "..."));
      grid.appendChild(card);
      API.post("/api/search", { query: panel.query, earliest: panel.earliest || "-24h", latest: "now", max_rows: 200 })
        .then((r) => {
          // "Chart" panels (type viz) chart any aggregate; raw events stay a list.
          const body = r.kind === "events" ? (panel.type === "table" ? renderTable(r) : renderEvents(r))
            : panel.type === "table" ? renderTable(r) : renderViz(r);
          card.lastChild.replaceWith(body);
        })
        .catch((ex) => { card.lastChild.replaceWith(el("div", { class: "empty" }, ex.message)); });
    }
    if (!(def.panels || []).length) grid.appendChild(el("div", { class: "empty" }, "This dashboard has no panels."));
  } catch (ex) { grid.innerHTML = ""; grid.appendChild(el("div", { class: "empty" }, ex.message)); }
}

async function newDashboard() {
  const v = await openModal("New dashboard", "Create a dashboard with one panel. Add more panels from the dashboard view later.", [
    { name: "name", label: "Dashboard name", type: "text", required: true, placeholder: "e.g. Web errors" },
    { name: "title", label: "First panel title", type: "text", value: "Panel 1" },
    { name: "query", label: "First panel query (Daru query language)", type: "textarea", required: true, value: "* | timechart span=1h count" },
    { name: "type", label: "Panel type", type: "select", value: "viz",
      options: [{ value: "viz", label: "Chart" }, { value: "table", label: "Table" }] },
  ], "Create dashboard");
  if (!v) return;
  const definition = JSON.stringify({ panels: [{ title: v.title || "Panel 1", query: v.query, type: v.type, earliest: "-24h" }] });
  try { await API.post("/api/dashboards", { name: v.name, definition }); toast("Dashboard created"); renderDashboards(document.getElementById("view")); }
  catch (ex) { toast(ex.message, "error"); }
}

// Export a dashboard as CSV: one section per panel, with the panel query
// and its result rows. Uses the existing search API.
async function exportDashboardCSV(d, def) {
  const lines = [["dashboard", d.name], ["exported", new Date().toISOString()], []];
  const csvEsc = (v) => { const s = String(v == null ? "" : v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  for (const panel of def.panels || []) {
    lines.push(["panel", panel.title || "Panel", panel.query || ""]);
    try {
      const r = await API.post("/api/search", { query: panel.query, earliest: panel.earliest || "-24h", latest: "now", max_rows: 1000 });
      const cols = r.columns && r.columns.length ? r.columns : (r.rows[0] ? Object.keys(r.rows[0]) : []);
      if (cols.length) lines.push(cols);
      for (const row of r.rows || []) lines.push(cols.map((c) => row[c]));
    } catch (ex) { lines.push(["error", ex.message]); }
    lines.push([]);
  }
  downloadFile("daru-dashboard-" + d.name.replace(/[^0-9a-zA-Z-]/g, "_") + ".csv",
    lines.map((r) => r.map(csvEsc).join(",")).join("\n"), "text/csv");
  toast("Dashboard CSV downloaded");
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
          el("td", {}, roleAtLeast(ME.role, "power") ? el("button", { class: "btn-ghost btn-sm btn-danger", onclick: async () => { if (await confirmDialog("Delete alert \"" + a.name + "\"? This cannot be undone.")) { await API.del("/api/saved/" + a.id); renderAlerts(view); } } }, "Delete") : null)));
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
        timeTd(f.fired_at), el("td", {}, f.search_name),
        el("td", {}, el("span", { class: "badge sev-" + f.severity }, f.severity)),
        el("td", { class: "num" }, String(f.result_count)), el("td", {}, f.detail)));
      histWrap.appendChild(t);
    }
  } catch (ex) { histWrap.appendChild(el("div", { class: "empty" }, ex.message)); }
}

async function newAlert() {
  const v = await openModal("New alert", "A scheduled search that fires when its condition is met.", [
    { name: "name", label: "Alert name", type: "text", required: true, placeholder: "e.g. Failed logins spike" },
    { name: "query", label: "Search (Daru query language)", type: "textarea", required: true, value: "error | stats count" },
    { name: "cron", label: "Cron schedule (minute hour day month weekday)", type: "text", required: true, value: "*/5 * * * *",
      validate: (val) => validateCron(val), help: "Example: */5 * * * * runs every 5 minutes." },
    { name: "condition", label: "Condition", type: "text", value: "count > 0" },
    { name: "severity", label: "Severity", type: "select", value: "medium",
      options: [{ value: "low", label: "low" }, { value: "medium", label: "medium" }, { value: "high", label: "high" }] },
    { name: "webhook", label: "Webhook URL (optional)", type: "text", placeholder: "https://example.com/hook",
      help: "Stored with the alert actions. The current scheduler only opens a notable event; webhook delivery is a scheduler feature, not yet implemented server side." },
  ], "Create alert");
  if (!v) return;
  const actions = { severity: v.severity, actions: ["notable"] };
  if (v.webhook) { actions.actions.push("webhook"); actions.webhook = v.webhook; }
  try {
    await API.post("/api/saved", { name: v.name, query: v.query, earliest: "-5m", latest: "now", is_alert: true, cron: v.cron, condition: v.condition || "count > 0", actions: JSON.stringify(actions) });
    toast("Alert created"); renderAlerts(document.getElementById("view"));
  } catch (ex) { toast(ex.message, "error"); }
}

// ===================== SECURITY =====================
async function renderSecurity(view) {
  view.appendChild(pageHead("Security", "Notable events and incident triage"));
  if (ME && !ME.totp_enabled) {
    view.appendChild(el("div", { class: "notice", style: "border-left-color:var(--amber)" },
      "Two-factor authentication is off for your account. ", el("a", { href: "#/account" }, "Turn it on in Account"), "."));
  }
  const stats = el("div", { class: "stat-row" });
  const wrap = el("div", {}, el("div", { class: "spinner" }, "Loading..."));
  view.appendChild(stats);
  view.appendChild(wrap);
  try {
    const r = await API.get("/api/notable");
    const items = r.notable || [];
    const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
    let open = 0;
    for (const n of items) { bySev[n.severity] = (bySev[n.severity] || 0) + 1; if (n.status !== "closed") open++; }
    stats.appendChild(statCard(items.length, "Total notable"));
    stats.appendChild(statCard(open, "Open"));
    stats.appendChild(statCard(bySev.critical || 0, "Critical"));
    stats.appendChild(statCard(bySev.high || 0, "High"));
    view.appendChild(renderMitrePanel(items));
    wrap.innerHTML = "";
    if (!items.length) { wrap.appendChild(el("div", { class: "empty" }, "No notable events. Create a security alert to populate this queue.")); return; }
    const t = el("table", { class: "grid" }, el("tr", {}, ...["Time", "Rule", "Severity", "Status", "Entity", "MITRE", ""].map((h) => el("th", {}, h))));
    for (const n of items) {
      const tr = el("tr", { style: "cursor:pointer", title: "Open incident" },
        timeTd(n.created_at), el("td", {}, n.rule_name),
        el("td", {}, el("span", { class: "badge sev-" + n.severity }, n.severity)),
        el("td", {}, n.status), el("td", {}, n.entity || "-"), el("td", {}, n.mitre || "-"),
        el("td", {}, roleAtLeast(ME.role, "power") ? statusSelect(n, view) : null));
      tr.addEventListener("click", (e) => { if (!["SELECT", "OPTION", "BUTTON", "A"].includes(e.target.tagName)) openIncident(n.id, view); });
      t.appendChild(tr);
    }
    wrap.appendChild(t);
  } catch (ex) { wrap.innerHTML = ""; wrap.appendChild(el("div", { class: "empty" }, ex.message)); }
}


// MITRE ATT&CK tactic names. Notable events carry a free-text mitre field,
// so grouping is defensive: unknown or missing values land in "Unmapped".
const MITRE_TACTICS = {
  "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence",
  "TA0004": "Privilege Escalation", "TA0005": "Defense Evasion",
  "TA0006": "Credential Access", "TA0007": "Discovery",
  "TA0008": "Lateral Movement", "TA0009": "Collection",
  "TA0010": "Exfiltration", "TA0011": "Command and Control",
  "TA0040": "Impact", "TA0042": "Resource Development",
  "TA0043": "Reconnaissance",
};

function mitreGroup(n) {
  const raw = String((n && (n.mitre || (n.fields && n.fields.mitre))) || "").trim();
  if (!raw) return "Unmapped";
  const first = raw.split(/[\s,;]+/)[0].toUpperCase();
  if (MITRE_TACTICS[first]) return MITRE_TACTICS[first] + " (" + first + ")";
  if (/^TA\d{4}$/.test(first)) return "Other tactic (" + first + ")";
  if (/^T\d{4}(\.\d{3})?$/.test(first)) return "Technique " + first + " (tactic not recorded)";
  return raw;
}

// renderMitrePanel groups notable events by MITRE tactic. It renders from
// the existing /api/notable response and degrades to "Unmapped" when the
// mitre field is absent, so it never breaks on older data.
function renderMitrePanel(items) {
  const groups = {};
  for (const n of items || []) {
    const g = mitreGroup(n);
    (groups[g] = groups[g] || []).push(n);
  }
  const card = el("div", { class: "card", style: "margin-bottom:16px" });
  card.appendChild(el("h3", {}, "MITRE ATT&CK coverage"));
  const total = (items || []).length;
  const mapped = total - (groups["Unmapped"] || []).length;
  card.appendChild(el("div", { class: "meta", style: "margin-bottom:10px" },
    total ? mapped + " of " + total + " notable events carry a MITRE mapping." : "No notable events yet. MITRE mappings come from the mitre field on notable events."));
  if (!total) return card;
  for (const name of Object.keys(groups).sort((a, b) => groups[b].length - groups[a].length)) {
    const rows = groups[name];
    const row = el("div", { style: "margin:8px 0" });
    row.appendChild(el("div", { style: "display:flex;justify-content:space-between;font-size:12.5px" },
      el("span", {}, name), el("span", { style: "color:var(--muted)" }, rows.length + " · " + Math.round((rows.length / total) * 100) + "%")));
    const bar = el("div", { style: "height:6px;border-radius:3px;background:var(--border);margin-top:3px;overflow:hidden" },
      el("div", { style: `height:100%;width:${Math.max(2, Math.round((rows.length / total) * 100))}%;background:var(--accent)` }));
    row.appendChild(bar);
    card.appendChild(row);
  }
  return card;
}

// openIncident shows one notable event with its timeline, notes, owner, and
// status. Power users and admins can act; others see it read-only.
async function openIncident(id, view) {
  const overlay = el("div", { class: "modal-overlay", role: "dialog", "aria-modal": "true" });
  const box = el("div", { class: "modal modal-wide" }, el("div", { class: "spinner" }, "Loading incident..."));
  overlay.appendChild(box);
  const close = () => { overlay.remove(); document.removeEventListener("keydown", onKey); renderSecurity((view.innerHTML = "", view)); };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });
  document.addEventListener("keydown", onKey);
  document.body.appendChild(overlay);
  const canAct = roleAtLeast(ME.role, "power");
  async function draw() {
    let r;
    try { r = await API.get("/api/notable/" + encodeURIComponent(id)); }
    catch (ex) { box.innerHTML = ""; box.appendChild(el("div", { class: "empty" }, ex.message)); return; }
    const n = r.notable, act = r.activity || [];
    box.innerHTML = "";
    box.appendChild(el("div", { style: "display:flex;justify-content:space-between;gap:12px;align-items:flex-start" },
      el("div", {}, el("h3", {}, n.rule_name),
        el("div", { class: "modal-sub" }, el("span", { class: "badge sev-" + n.severity }, n.severity), "  opened " + timeAgo(n.created_at) + " · " + fmtTime(n.created_at))),
      el("button", { class: "btn-ghost btn-sm", onclick: close, "aria-label": "Close" }, "Close")));
    const kv = el("dl", { class: "kv", style: "margin:4px 0 14px" });
    for (const [k, v] of [["Status", n.status], ["Owner", n.owner || "unassigned"], ["Entity", n.entity || "-"], ["MITRE", n.mitre || "-"], ["Detail", n.detail || "-"]]) {
      kv.appendChild(el("dt", {}, k)); kv.appendChild(el("dd", { style: "white-space:pre-wrap" }, v));
    }
    box.appendChild(kv);
    if (n.raw) box.appendChild(el("details", { style: "margin-bottom:14px" }, el("summary", { style: "cursor:pointer;color:var(--muted)" }, "Raw event"),
      el("pre", { class: "event-raw", style: "background:var(--bg-2);padding:10px;border-radius:6px;max-height:200px;overflow:auto" }, n.raw)));
    if (canAct) {
      const actions = el("div", { class: "toolbar" });
      const st = el("select", { "aria-label": "Status" }, ...["new", "in_progress", "closed"].map((x) => el("option", { value: x, ...(x === n.status ? { selected: "" } : {}) }, x)));
      st.addEventListener("change", async () => { try { await API.post("/api/notable/" + id + "/status", { status: st.value }); toast("Status updated"); draw(); } catch (ex) { toast(ex.message, "error"); } });
      actions.appendChild(el("label", { style: "display:flex;gap:6px;align-items:center" }, "Status", st));
      if (n.owner !== ME.username) actions.appendChild(el("button", { class: "btn-ghost", onclick: async () => {
        try { await API.post("/api/notable/" + id + "/assign", { owner: ME.username }); toast("Assigned to you"); draw(); } catch (ex) { toast(ex.message, "error"); }
      } }, "Assign to me"));
      actions.appendChild(el("button", { class: "btn-ghost", onclick: async () => {
        const v = await openModal("Assign incident", "Enter the username to assign this incident to, or leave it empty to unassign.", [{ name: "owner", label: "Username", type: "text", value: n.owner || "" }], "Assign");
        if (!v) return;
        try { await API.post("/api/notable/" + id + "/assign", { owner: v.owner }); toast(v.owner ? "Assigned to " + v.owner : "Unassigned"); draw(); } catch (ex) { toast(ex.message, "error"); }
      } }, "Assign to..."));
      box.appendChild(actions);
    }
    box.appendChild(el("h4", { style: "margin:6px 0 8px;font-size:13px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted)" }, "Timeline"));
    const tl = el("ol", { class: "timeline" });
    tl.appendChild(el("li", { class: "tl-system" }, el("div", { class: "tl-meta" }, fmtTime(n.created_at) + " · Daru"), el("div", {}, "Incident opened by rule " + n.rule_name)));
    for (const a of act) {
      tl.appendChild(el("li", { class: a.kind === "note" ? "tl-note" : "tl-system" },
        el("div", { class: "tl-meta" }, fmtTime(a.time) + " · " + a.author), el("div", { style: "white-space:pre-wrap" }, a.text)));
    }
    box.appendChild(tl);
    if (canAct) {
      const note = el("textarea", { rows: "3", placeholder: "Add a note: what you checked, what you found, next steps", "aria-label": "Note", style: "width:100%" });
      box.appendChild(note);
      box.appendChild(el("div", { class: "modal-actions" }, el("button", { class: "btn-primary", onclick: async () => {
        if (!note.value.trim()) return;
        try { await API.post("/api/notable/" + id + "/notes", { text: note.value }); toast("Note added"); draw(); } catch (ex) { toast(ex.message, "error"); }
      } }, "Add note")));
    }
  }
  draw();
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
  // Numbers are locale-formatted; string labels (e.g. "Top protocol": TCP) are
  // shown as-is so they don't become NaN.
  const display = typeof n === "number" ? fmtNum(n) : (n == null || n === "" ? "-" : String(n));
  return el("div", { class: "stat" }, el("div", { class: "n", style: typeof n === "number" ? "" : "font-size:18px" }, display), el("div", { class: "l" }, label));
}

// ===================== NETWORK (devices) =====================
async function renderNetwork(view) {
  const canScan = roleAtLeast(ME.role, "power");
  const actions = [];
  if (canScan) {
    actions.push(el("button", { class: "btn-primary", onclick: discover }, "Discover my network"));
    actions.push(el("button", { class: "btn-ghost", onclick: deepScan }, "⚡ Deep scan (god mode)"));
  }
  actions.push(el("button", { class: "btn-ghost", onclick: () => exportInventoryCSV() }, "⬇ Export inventory"));
  actions.push(el("button", { class: "btn-ghost", onclick: () => renderNetwork(view) }, "Refresh"));
  view.appendChild(pageHead("Network", "Live devices discovered on your networks", actions));

  function exportInventoryCSV() {
    const rows = [["ip", "hostname", "mac", "vendor", "type_os", "open_ports", "status", "source", "first_seen", "last_seen"]];
    for (const a of lastAssets) rows.push([a.ip, a.hostname, a.mac, a.vendor, a.os, a.open_ports, a.status, a.source, a.first_seen, a.last_seen]);
    const esc = (v) => { const s = String(v == null ? "" : v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
    downloadFile("daru-inventory.csv", rows.map((r) => r.map(esc).join(",")).join("\n"), "text/csv");
    toast("Inventory CSV downloaded");
  }

  const netLine = el("div", { class: "page-sub", style: "margin-bottom:12px" }, "Detecting local networks...");
  view.appendChild(netLine);
  const stats = el("div", { class: "stat-row" });
  view.appendChild(stats);
  const filterIn = el("input", { placeholder: "filter devices (IP, hostname, MAC, vendor, OS)…", style: "margin-bottom:10px;width:100%;max-width:420px", "aria-label": "Filter devices" });
  view.appendChild(filterIn);
  const wrap = el("div", {}, el("div", { class: "spinner" }, "Loading devices..."));
  view.appendChild(wrap);
  let lastAssets = [];
  filterIn.addEventListener("input", () => render(lastAssets));

  try {
    const n = await API.get("/api/recon/networks");
    netLine.textContent = (n.networks && n.networks.length) ? "Local networks: " + n.networks.join(", ") : "No local network detected";
  } catch (_) { netLine.textContent = ""; }

  function render(assets) {
    stats.innerHTML = "";
    stats.appendChild(statCard(assets.length, "Devices"));
    stats.appendChild(statCard(new Set(assets.map((a) => a.vendor).filter(Boolean)).size, "Vendors"));
    stats.appendChild(statCard(assets.filter((a) => a.status === "up").length, "Online"));
    stats.appendChild(statCard(assets.filter((a) => a.os).length, "Typed/OS"));
    const nowMs = Date.now();
    stats.appendChild(statCard(assets.filter((a) => { const t = Date.parse((a.first_seen || "").replace(" ", "T") + "Z"); return t && (nowMs - t) < 3600 * 1000; }).length, "New (1h)"));
    wrap.innerHTML = "";
    if (!assets.length) {
      wrap.appendChild(el("div", { class: "empty" }, canScan ? "No devices yet. Click “Discover my network” to scan your LAN." : "No devices discovered yet."));
      return;
    }
    const q = filterIn.value.trim().toLowerCase();
    const shown = q ? assets.filter((a) => [a.ip, a.hostname, a.mac, a.vendor, a.os, a.open_ports].some((v) => (v || "").toLowerCase().includes(q))) : assets;
    if (!shown.length) { wrap.appendChild(el("div", { class: "empty" }, "No devices match “" + q + "”.")); return; }
    const now = Date.now();
    const isNew = (a) => { const t = Date.parse((a.first_seen || "").replace(" ", "T") + "Z"); return t && (now - t) < 3600 * 1000; };
    const isStale = (a) => { const t = Date.parse((a.last_seen || "").replace(" ", "T") + "Z"); return t && (now - t) > 24 * 3600 * 1000; };
    const t = el("table", { class: "grid" }, el("tr", {}, ...["IP", "Hostname", "MAC", "Vendor", "Type / OS", "Open ports", "Source", "Last seen"].map((h) => el("th", {}, h))));
    for (const a of shown) {
        const ipCell = el("td", {}, el("a", { href: "#/device/" + encodeURIComponent(a.ip), style: "color:var(--accent);text-decoration:none" }, a.ip));
        if (isNew(a)) ipCell.appendChild(el("span", { class: "badge sev-medium", style: "margin-left:6px;font-size:10px", title: "First seen in the last hour" }, "NEW"));
        else if (isStale(a)) ipCell.appendChild(el("span", { class: "badge", style: "margin-left:6px;font-size:10px;background:var(--border);color:var(--muted)", title: "Not seen in over 24h" }, "stale"));
        const row = el("tr", { style: "cursor:pointer", title: "Open device intelligence" },
          ipCell,
          el("td", { class: "nowrap" }, a.hostname || "-"),
          el("td", {}, a.mac || "-"), el("td", {}, a.vendor || "-"),
          el("td", {}, a.os || "-"), el("td", {}, a.open_ports || "-"),
          el("td", { class: "nowrap" }, a.source), timeTd(a.last_seen));
      row.addEventListener("click", (e) => { if (e.target.tagName !== "A") location.hash = "#/device/" + encodeURIComponent(a.ip); });
      t.appendChild(row);
    }
    wrap.appendChild(t);
  }

  async function load() {
    try {
      const r = await API.get("/api/assets");
      lastAssets = r.assets || [];
      render(lastAssets);
    } catch (ex) { wrap.innerHTML = ""; wrap.appendChild(el("div", { class: "empty" }, ex.message)); }
  }

  // Keep the inventory live.
  const refreshTimer = setInterval(() => { if (location.hash === "#/network") load(); else clearInterval(refreshTimer); }, 5000);

  async function discover() {
    try {
      await API.post("/api/recon/scan", { connector: "netdiscover", target: "", profile: "arp", confirmed: true });
      toast("Discovery started; devices will appear shortly");
      let n = 0;
      const timer = setInterval(() => { if (location.hash === "#/network" && n++ < 15) load(); else clearInterval(timer); }, 3000);
    } catch (ex) { toast(ex.message, "error"); }
  }

  async function deepScan() {
    if (!await confirmDialog("Deep scan fuses discovery + nmap OS/service detection + NetBIOS names into full device profiles for your local network. This can take a few minutes.", "Start deep scan")) return;
    try {
      await API.post("/api/recon/scan", { connector: "deep-scan", target: "", profile: "thorough", confirmed: true });
      toast("Deep scan started; device profiles will fill in as it runs");
      let n = 0;
      const timer = setInterval(() => { if (location.hash === "#/network" && n++ < 40) load(); else clearInterval(timer); }, 4000);
    } catch (ex) { toast(ex.message, "error"); }
  }

  load();
}

// ===================== RECON =====================
let reconConnectors = [];
async function renderRecon(view) {
  view.appendChild(pageHead("Recon & scanning", "Run authorized security tools and pull results into Daru"));

  // Security posture overview (aggregate across all scans).
  const posture = el("div", { style: "margin-bottom:20px" });
  view.appendChild(posture);
  renderPosture(posture);

  const layout = el("div", { class: "search-layout" });
  const left = el("div", { class: "fields-panel", style: "max-height:none" });
  const right = el("div", {});
  layout.appendChild(left);
  layout.appendChild(right);
  view.appendChild(layout);

  // Full-width tool catalog: every connector as its own card.
  const catSection = el("div", { style: "margin-top:22px" });
  const catHead = el("div", { class: "toolbar", style: "justify-content:space-between;align-items:center;margin-bottom:10px" },
    el("h3", { style: "margin:0;font-size:15px" }, "Tool catalog"),
    el("span", { class: "page-sub", id: "cat-count" }, ""));
  const catWrap = el("div", { class: "cards" });
  catSection.appendChild(catHead);
  catSection.appendChild(catWrap);
  view.appendChild(catSection);

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
    if (c && c.allow_empty) targetIn.placeholder = "optional - leave blank to scan your own network";
    else targetIn.placeholder = "target: " + (c?.target_kind || "host");
  }
  connSel.addEventListener("change", fillProfiles);

  form.appendChild(el("label", {}, "Tool", connSel));
  form.appendChild(el("div", { class: "conn-hint", style: "font-size:11.5px;color:var(--muted)" }));
  form.appendChild(el("label", {}, "Profile", profSel));
  form.appendChild(el("label", {}, "Target (optional for local and own-network scans)", targetIn));
  form.appendChild(el("label", {}, "Ports", portsIn));
  form.appendChild(el("label", {}, "Authorization reference (external targets only)", authIn));
  form.appendChild(el("label", { style: "flex-direction:row;align-items:center;gap:8px" }, extChk, el("span", {}, "Allow external (public) target")));
  form.appendChild(el("label", { style: "flex-direction:row;align-items:center;gap:8px" }, confirmChk, el("span", {}, "I am authorized (required for external targets)")));
  form.appendChild(el("div", { style: "font-size:11.5px;color:var(--muted)" }, "Scanning your own network, localhost, or private IPs needs no authorization reference."));
  form.appendChild(runBtn);
  form.appendChild(formErr);
  if (!canScan) { form.querySelectorAll("input,select,button").forEach((e) => e.disabled = true); formErr.textContent = "Power or admin role required to run scans."; }
  left.appendChild(form);

  // Scheduled scans management.
  if (canScan) {
    right.appendChild(el("div", { class: "toolbar", style: "justify-content:space-between;align-items:center;margin-bottom:8px" },
      el("h3", { style: "margin:0;font-size:15px" }, "Scheduled scans"),
      el("button", { class: "btn-ghost btn-sm", onclick: addSchedule }, "+ Schedule")));
    const schedWrap = el("div", { style: "margin-bottom:16px" }, el("div", { class: "spinner" }, "Loading..."));
    right.appendChild(schedWrap);
    loadSchedules(schedWrap);
    window.__reloadSchedules = () => loadSchedules(schedWrap);
  }

  right.appendChild(el("h3", { style: "margin:0 0 10px;font-size:15px" }, "Scan history"));
  const histWrap = el("div", {}, el("div", { class: "spinner" }, "Loading..."));
  right.appendChild(histWrap);

  async function loadSchedules(wrap) {
    try {
      const r = await API.get("/api/recon/schedules");
      const list = r.schedules || [];
      wrap.innerHTML = "";
      if (!list.length) { wrap.appendChild(el("div", { class: "empty", style: "padding:14px" }, "No scheduled scans. Click “+ Schedule” to add continuous monitoring.")); return; }
      const t = el("table", { class: "grid" }, el("tr", {}, ...["Tool", "Target", "Cron", "Last run", ""].map((h) => el("th", {}, h))));
      for (const sc of list) {
        t.appendChild(el("tr", {},
          el("td", { class: "nowrap" }, sc.connector), el("td", {}, sc.target || "local"), el("td", { class: "nowrap" }, sc.cron),
          timeTd(sc.last_run, "never"),
          el("td", {}, el("button", { class: "btn-ghost btn-sm btn-danger", onclick: async () => { if (await confirmDialog("Delete scheduled scan " + sc.connector + " on " + (sc.target || "local") + "?")) { await API.del("/api/recon/schedules/" + sc.id); loadSchedules(wrap); } } }, "Delete"))));
      }
      wrap.appendChild(t);
    } catch (ex) { wrap.innerHTML = ""; wrap.appendChild(el("div", { class: "empty" }, ex.message)); }
  }

  async function addSchedule() {
    const conn = connSel.value;
    if (!conn) { toast("Pick a tool first", "error"); return; }
    const v = await openModal("Schedule scan", "Run " + conn + " on a cron schedule for continuous monitoring.", [
      { name: "target", label: "Target (blank for local / own network)", type: "text", value: targetIn.value.trim() },
      { name: "cron", label: "Cron schedule (minute hour day month weekday)", type: "text", required: true, value: "0 * * * *",
        validate: (val) => validateCron(val), help: "Examples: */30 * * * * every 30 min, 0 * * * * hourly, 0 2 * * * daily at 02:00 UTC." },
      { name: "authorization_ref", label: "Authorization reference (ticket, ROE, or engagement id; required for public targets)", type: "text", value: "" },
      { name: "allow_external", label: "Allow public (non-private) targets", type: "checkbox", value: false },
    ], "Schedule scan");
    if (!v) return;
    try {
      await API.post("/api/recon/schedules", { connector: conn, target: v.target.trim(), profile: profSel.value, ports: portsIn.value.trim(), cron: v.cron.trim(), authorization_ref: v.authorization_ref, allow_external: v.allow_external, confirmed: !!v.authorization_ref });
      toast("Scheduled scan created");
      if (window.__reloadSchedules) window.__reloadSchedules();
    } catch (ex) { toast(ex.message, "error"); }
  }

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
    renderCatalog(catWrap, reconConnectors, (name) => {
      connSel.value = name; fillProfiles();
      left.scrollIntoView({ behavior: "smooth", block: "start" });
      targetIn.focus();
    });
    const avail = reconConnectors.filter((c) => c.available).length;
    document.getElementById("cat-count").textContent = `${avail} of ${reconConnectors.length} tools available`;
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
          timeTd(sc.started_at), el("td", { class: "nowrap" }, sc.connector), el("td", {}, sc.target),
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
    const panel = el("div", { style: "margin-top:12px" });

    // Severity summary chips.
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of rows) counts[f.severity] = (counts[f.severity] || 0) + 1;
    const summary = el("div", { class: "toolbar", style: "margin-bottom:10px;gap:8px;flex-wrap:wrap" });
    summary.appendChild(el("span", { style: "color:var(--muted);font-size:12.5px" }, `${sc.connector} on ${sc.target || "local"}, ${rows.length} findings`));
    for (const s of ["critical", "high", "medium", "low", "info"]) {
      if (counts[s]) summary.appendChild(el("span", { class: "badge sev-" + (s === "info" ? "low" : s) }, `${counts[s]} ${s}`));
    }
    if (rows.length) summary.appendChild(el("button", { class: "btn-ghost btn-sm", style: "margin-left:auto", onclick: () => exportFindingsCSV(`daru-${sc.connector}-${(sc.target || "local").replace(/[^0-9a-zA-Z.]/g, "_")}.csv`, rows) }, "⬇ CSV"));
    panel.appendChild(summary);
    if (sc.command) panel.appendChild(el("div", { class: "notice", style: "font-family:var(--mono);font-size:11.5px;word-break:break-all" }, sc.command));

    const results = el("div", { class: "results" });
    results.appendChild(el("div", { class: "results-tabs" }, el("span", { class: "results-tab active" }, toolDashboardTitle(sc.connector))));
    const body = el("div", { class: "results-body" });
    if (!rows.length) body.appendChild(el("div", { class: "empty" }, sc.error || "No findings."));
    else body.appendChild(renderToolDashboard(sc.connector, rows));
    results.appendChild(body);
    panel.appendChild(results);

    const existing = right.querySelector("#recon-results");
    if (existing) existing.remove();
    panel.id = "recon-results";
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

// renderPosture shows the aggregate security posture across all recon scans.
async function renderPosture(wrap) {
  let ov;
  try { ov = await API.get("/api/recon/overview"); } catch (_) { return; }
  if (!ov || !ov.total_findings) return;
  wrap.innerHTML = "";
  const sc = ov.severity_counts || {};
  const stats = el("div", { class: "stat-row" });
  stats.appendChild(statCard(ov.total_findings, "Total findings"));
  stats.appendChild(statCard(sc.critical || 0, "Critical"));
  stats.appendChild(statCard(sc.high || 0, "High"));
  stats.appendChild(statCard(sc.medium || 0, "Medium"));
  // Open security alerts (new devices / new ports) from the notable queue.
  try {
    const nt = await API.get("/api/notable");
    const open = (nt.notable || []).filter((n) => n.status !== "closed").length;
    const alertCard = statCard(open, "Open alerts");
    if (open > 0) { alertCard.style.cursor = "pointer"; alertCard.onclick = () => { location.hash = "#/security"; }; alertCard.title = "View in Security"; }
    stats.appendChild(alertCard);
  } catch (_) {}
  wrap.appendChild(stats);

  const cols = el("div", { class: "cards", style: "grid-template-columns:1fr 1fr" });
  // Top hosts by risk.
  const hc = el("div", { class: "card" });
  hc.appendChild(el("h3", {}, "Top hosts by risk"));
  if (!(ov.top_hosts || []).length) hc.appendChild(el("div", { class: "meta" }, "No host findings yet."));
  else {
    const t = el("table", { class: "grid" }, el("tr", {}, ...["Host", "Crit", "High", "Med", "Total"].map((h) => el("th", {}, h))));
    for (const h of ov.top_hosts) {
      t.appendChild(el("tr", { style: "cursor:pointer", onclick: () => { location.hash = "#/device/" + encodeURIComponent(h.host); } },
        el("td", {}, el("a", { href: "#/device/" + encodeURIComponent(h.host), style: "color:var(--accent);text-decoration:none" }, h.host)),
        el("td", {}, h.critical ? el("span", { class: "badge sev-critical" }, String(h.critical)) : "-"),
        el("td", {}, h.high ? el("span", { class: "badge sev-high" }, String(h.high)) : "-"),
        el("td", {}, h.medium ? el("span", { class: "badge sev-medium" }, String(h.medium)) : "-"),
        el("td", { class: "num" }, String(h.total))));
    }
    hc.appendChild(t);
  }
  cols.appendChild(hc);

  // Recent notable findings.
  const rc = el("div", { class: "card" });
  rc.appendChild(el("h3", {}, "Recent high-severity findings"));
  if (!(ov.recent_high || []).length) rc.appendChild(el("div", { class: "meta" }, "No high-severity findings yet."));
  else {
    const t = el("table", { class: "grid" }, el("tr", {}, ...["Sev", "Host", "Finding", "Tool"].map((h) => el("th", {}, h))));
    for (const f of ov.recent_high.slice(0, 12)) {
      t.appendChild(el("tr", {},
        el("td", {}, el("span", { class: "badge sev-" + f.severity }, f.severity)),
        el("td", { class: "nowrap" }, f.target || "-"),
        el("td", { style: "white-space:normal" }, f.title),
        el("td", { class: "nowrap" }, (f.fields && f.fields.connector) || "-")));
    }
    rc.appendChild(t);
  }
  cols.appendChild(rc);
  wrap.appendChild(cols);
}

// downloadFile triggers a browser download of text content.
function downloadFile(name, content, type = "text/html") {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// exportDeviceReport builds a standalone, printable HTML report for a host and
// downloads it, a shareable deliverable for an assessment.
// exportFindingsCSV downloads findings as a spreadsheet-friendly CSV.
function exportFindingsCSV(name, findings) {
  const esc = (v) => {
    const s = String(v == null ? "" : v);
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const rows = [["severity", "target", "port", "service", "title", "detail", "tool", "seen_at"]];
  for (const f of findings) {
    const fl = f.fields || {};
    rows.push([f.severity, f.target, f.port, f.service, f.title, f.detail, fl.connector || "", fl.seen_at || ""]);
  }
  const csv = rows.map((r) => r.map(esc).join(",")).join("\n");
  downloadFile(name, csv, "text/csv");
  toast("CSV downloaded");
}

function exportDeviceReport(ip, a, findings) {
  // Build the report with DOM nodes and textContent only, never by string
  // interpolation, so finding data can never inject HTML into the report.
  const now = new Date().toISOString().replace("T", " ").slice(0, 19);
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const facts = [["IP", ip], ["Hostname", a.hostname], ["MAC", a.mac], ["Vendor", a.vendor],
    ["OS", a.os], ["Open ports", a.open_ports], ["First seen", a.first_seen], ["Last seen", a.last_seen]]
    .filter(([, v]) => v);
  const sevColor = { critical: "#b91c1c", high: "#dc2626", medium: "#b45309", low: "#15803d", info: "#475569" };
  const doc = document.implementation.createHTMLDocument("Daru report - " + ip);
  const style = doc.createElement("style");
  style.textContent = "body{font:14px system-ui,Segoe UI,Roboto,sans-serif;color:#1e293b;max-width:960px;margin:32px auto;padding:0 20px}"
    + "h1{margin:0 0 2px}.sub{color:#64748b;margin-bottom:20px}"
    + ".facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px 24px;margin:14px 0 22px;padding:14px;border:1px solid #e2e8f0;border-radius:8px}"
    + ".facts div .k{color:#64748b;font-size:11px;text-transform:uppercase}.facts div .v{font-family:ui-monospace,monospace}"
    + ".sev{display:flex;gap:10px;margin:0 0 18px;flex-wrap:wrap}.chip{border:1px solid #e2e8f0;border-radius:8px;padding:8px 14px}.chip b{font-size:20px;display:block}"
    + "table{width:100%;border-collapse:collapse;font-size:12.5px}th,td{text-align:left;padding:6px 9px;border-bottom:1px solid #eef2f7;vertical-align:top}"
    + "th{background:#f8fafc;text-transform:uppercase;font-size:10.5px;color:#64748b}"
    + ".foot{margin-top:24px;color:#94a3b8;font-size:11px}@media print{body{margin:0}}";
  doc.head.appendChild(style);
  const body = doc.body;
  const h1 = doc.createElement("h1"); h1.textContent = "Device Intelligence Report"; body.appendChild(h1);
  const sub = doc.createElement("div"); sub.className = "sub";
  sub.textContent = ip + (a.hostname ? " (" + a.hostname + ")" : "") + " - generated " + now + " by Daru";
  body.appendChild(sub);
  const factsDiv = doc.createElement("div"); factsDiv.className = "facts";
  for (const [k, v] of facts) {
    const cell = doc.createElement("div");
    const key = doc.createElement("div"); key.className = "k"; key.textContent = k;
    const val = doc.createElement("div"); val.className = "v"; val.textContent = v;
    cell.appendChild(key); cell.appendChild(val); factsDiv.appendChild(cell);
  }
  body.appendChild(factsDiv);
  const sevDiv = doc.createElement("div"); sevDiv.className = "sev";
  for (const sev of ["critical", "high", "medium", "low", "info"]) {
    const chip = doc.createElement("div"); chip.className = "chip";
    const num = doc.createElement("b"); num.style.color = sevColor[sev]; num.textContent = String(counts[sev] || 0);
    chip.appendChild(num); chip.appendChild(doc.createTextNode(sev)); sevDiv.appendChild(chip);
  }
  body.appendChild(sevDiv);
  const h3 = doc.createElement("h3"); h3.textContent = "Findings (" + findings.length + ")"; body.appendChild(h3);
  const table = doc.createElement("table");
  const headRow = doc.createElement("tr");
  for (const h of ["Severity", "Tool", "Port", "Service", "Title", "Detail"]) {
    const th = doc.createElement("th"); th.textContent = h; headRow.appendChild(th);
  }
  table.appendChild(headRow);
  for (const f of findings) {
    const row = doc.createElement("tr");
    const sevCell = doc.createElement("td");
    const badge = doc.createElement("span");
    badge.style.cssText = "color:#fff;background:" + (sevColor[f.severity] || "#475569") + ";padding:1px 7px;border-radius:9px;font-size:11px";
    badge.textContent = f.severity; sevCell.appendChild(badge); row.appendChild(sevCell);
    for (const val of [(f.fields && f.fields.connector) || "", f.port || "", f.service || "", f.title, f.detail || ""]) {
      const td = doc.createElement("td"); td.textContent = val; row.appendChild(td);
    }
    table.appendChild(row);
  }
  body.appendChild(table);
  const foot = doc.createElement("div"); foot.className = "foot";
  foot.textContent = "Daru - self-hosted log analytics, SIEM and authorized recon. Report for authorized assessment only.";
  body.appendChild(foot);
  const html = "<!doctype html>\n" + doc.documentElement.outerHTML;
  downloadFile(`daru-report-${ip.replace(/[^0-9a-zA-Z.]/g, "_")}.html`, html);
  toast("Report downloaded");
}

// Common port → service names and sensitivity flags for the device services
// summary.
const PORT_SERVICES = {
  "21": "ftp", "22": "ssh", "23": "telnet", "25": "smtp", "53": "dns", "80": "http",
  "110": "pop3", "111": "rpcbind", "135": "msrpc", "139": "netbios", "143": "imap",
  "443": "https", "445": "smb", "631": "ipp", "993": "imaps", "995": "pop3s",
  "1433": "mssql", "1521": "oracle", "3306": "mysql", "3389": "rdp", "5432": "postgres",
  "5900": "vnc", "6379": "redis", "8080": "http-alt", "8443": "https-alt", "9200": "elasticsearch",
  "27017": "mongodb", "11211": "memcached",
};
const RISKY_PORTS = { "23": 1, "445": 1, "139": 1, "3389": 1, "5900": 1, "6379": 1, "3306": 1, "5432": 1, "1433": 1, "27017": 1, "11211": 1, "9200": 1 };
const RISKY_SERVICES = { telnet: 1, smb: 1, netbios: 1, rdp: 1, vnc: 1, redis: 1, mysql: 1, postgres: 1, postgresql: 1, mssql: 1, mongodb: 1, memcached: 1, elasticsearch: 1 };
function portServiceName(port) { return PORT_SERVICES[String(port)] || ""; }

// renderDevicePage aggregates everything Daru knows about one host: its
// inventory identity plus every finding from every tool that targeted it,
// a per-device "god mode" intelligence view.
async function renderDevicePage(view, ip) {
  const bar = el("div", { class: "toolbar", style: "margin-bottom:10px;justify-content:space-between" },
    el("a", { href: "#/network", class: "btn-ghost btn-sm", style: "text-decoration:none" }, "← Network"));
  view.appendChild(bar);
  let data;
  try { data = await API.get("/api/device/" + encodeURIComponent(ip)); }
  catch (ex) { view.appendChild(el("div", { class: "empty" }, ex.message)); return; }
  const a = data.asset || {};
  const findings = data.findings || [];
  const actions = el("div", { class: "toolbar", style: "margin:0;gap:8px" });
  if (roleAtLeast(ME.role, "power")) {
    actions.appendChild(el("button", { class: "btn-primary btn-sm", onclick: () => rescanHost() }, "⚡ Deep scan this host"));
  }
  actions.appendChild(el("button", { class: "btn-ghost btn-sm", onclick: () => exportFindingsCSV(`daru-${ip.replace(/[^0-9a-zA-Z.]/g, "_")}.csv`, findings) }, "⬇ CSV"));
  actions.appendChild(el("button", { class: "btn-ghost btn-sm", onclick: () => exportDeviceReport(ip, a, findings) }, "⬇ Export report"));
  bar.appendChild(actions);

  async function rescanHost() {
    try {
      await API.post("/api/recon/scan", { connector: "deep-scan", target: ip, profile: "thorough", confirmed: true });
      toast("Deep scan started for " + ip + "; this view updates automatically");
    } catch (ex) { toast(ex.message, "error"); }
  }

  // Auto-refresh: if the finding count changes (e.g. a rescan completes),
  // re-render the whole device view so it stays live.
  const curCount = findings.length;
  const devTimer = setInterval(async () => {
    if (location.hash !== "#/device/" + encodeURIComponent(ip)) { clearInterval(devTimer); return; }
    try {
      const d2 = await API.get("/api/device/" + encodeURIComponent(ip));
      if ((d2.findings || []).length !== curCount) {
        clearInterval(devTimer);
        view.innerHTML = "";
        renderDevicePage(view, ip);
      }
    } catch (_) {}
  }, 5000);

  const title = a.hostname ? `${ip} (${a.hostname})` : ip;
  view.appendChild(pageHead(title, "Device intelligence, everything Daru has observed about this host"));

  // Identity facts.
  const facts = [
    ["IP", ip], ["Hostname", a.hostname], ["MAC", a.mac], ["Vendor", a.vendor],
    ["OS", a.os], ["Open ports", a.open_ports], ["Status", a.status],
    ["First seen", fmtTime(a.first_seen)], ["Last seen", fmtTime(a.last_seen)], ["Source", a.source],
  ].filter(([, v]) => v);
  const card = el("div", { class: "card", style: "margin-bottom:16px" });
  const grid = el("div", { style: "display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px 24px" });
  for (const [k, v] of facts) {
    grid.appendChild(el("div", {},
      el("div", { style: "color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:0.4px" }, k),
      el("div", { style: "font-family:var(--mono);color:var(--text-strong);font-size:13px;word-break:break-all" }, v)));
  }
  card.appendChild(grid);
  view.appendChild(card);

  // Severity summary.
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const stats = el("div", { class: "stat-row" });
  stats.appendChild(statCard(findings.length, "Total findings"));
  for (const s of ["critical", "high", "medium"]) stats.appendChild(statCard(counts[s] || 0, s + " severity"));
  view.appendChild(stats);

  // Exposed services summary: group open ports into recognizable services.
  const portSvc = {};
  for (const f of findings) {
    const fl = f.fields || {};
    const port = (fl.port || (f.port || "").split("/")[0] || "").trim();
    if (!port) continue;
    const svc = (f.service && f.service !== "device" && f.service !== "open-port" ? f.service : "") || fl.service || portServiceName(port);
    if (svc && svc !== "tcp" && svc !== "udp") portSvc[port] = svc;
    else if (!portSvc[port]) portSvc[port] = portServiceName(port) || "";
  }
  const svcEntries = Object.entries(portSvc).sort((a, b) => (parseInt(a[0]) || 0) - (parseInt(b[0]) || 0));
  if (svcEntries.length) {
    const card = el("div", { class: "card", style: "margin-bottom:16px" });
    card.appendChild(el("h3", {}, "Exposed services (" + svcEntries.length + ")"));
    const chips = el("div", { style: "display:flex;gap:8px;flex-wrap:wrap;margin-top:8px" });
    for (const [port, svc] of svcEntries) {
      const risky = RISKY_SERVICES[svc] || RISKY_PORTS[port];
      chips.appendChild(el("span", { class: "badge " + (risky ? "sev-medium" : "sev-low"), title: risky ? "Commonly sensitive service" : "" },
        port + (svc ? " " + svc : "")));
    }
    card.appendChild(chips);
    view.appendChild(card);
  }

  // Findings grouped by tool.
  if (!findings.length) { view.appendChild(el("div", { class: "empty" }, "No scan findings for this host yet. Run a scan or deep-scan from Recon.")); return; }
  const byTool = {};
  for (const f of findings) { const c = (f.fields && f.fields.connector) || "scan"; (byTool[c] = byTool[c] || []).push(f); }
  view.appendChild(el("h3", { style: "margin:4px 0 10px;font-size:15px" }, "Findings by tool"));
  for (const tool of Object.keys(byTool).sort()) {
    const rows = byTool[tool];
    const results = el("div", { class: "results", style: "margin-bottom:14px" });
    results.appendChild(el("div", { class: "results-tabs" }, el("span", { class: "results-tab active" }, `${toolDashboardTitle(tool)} · ${rows.length}`)));
    const body = el("div", { class: "results-body" });
    const t = el("table", { class: "grid" }, el("tr", {}, ...["Severity", "Port", "Service", "Title", "Detail"].map((h) => el("th", {}, h))));
    for (const f of rows) t.appendChild(el("tr", {},
      el("td", {}, el("span", { class: "badge sev-" + (f.severity === "info" ? "low" : f.severity || "low") }, f.severity)),
      el("td", {}, f.port || "-"), el("td", {}, f.service || "-"),
      el("td", { style: "white-space:normal" }, f.title),
      el("td", { style: "white-space:normal" }, f.detail || "")));
    body.appendChild(t);
    results.appendChild(body);
    view.appendChild(results);
  }
}

// renderToolPage is a dedicated dashboard for a single tool: its description,
// capability, profiles, a run panel, and its own scan history + results.
async function renderToolPage(view, name) {
  const back = el("a", { href: "#/recon", class: "btn-ghost btn-sm", style: "text-decoration:none" }, "← All tools");
  view.appendChild(el("div", { class: "toolbar", style: "margin-bottom:10px" }, back));

  let connectors = reconConnectors;
  if (!connectors || !connectors.length) {
    try { connectors = (await API.get("/api/recon/connectors")).connectors || []; reconConnectors = connectors; } catch (_) { connectors = []; }
  }
  const c = connectors.find((x) => x.name === name);
  if (!c) { view.appendChild(el("div", { class: "empty" }, "Unknown tool: " + name)); return; }

  view.appendChild(pageHead(toolDashboardTitle(c.name).replace(/,.*/, ""), c.desc,
    [el("span", { class: "badge " + (c.available ? "badge-ok" : "sev-high"), style: "align-self:center" }, c.available ? "ready" : "not installed")]));
  view.appendChild(el("div", { class: "page-sub", style: "margin-top:-8px;margin-bottom:14px" },
    `${c.category} · target: ${c.target_kind}${c.needs_root ? " · needs capability" : ""}${c.allow_empty ? " · scans your own network with no target" : ""}`));
  if (NATIVE_FALLBACK[c.name]) {
    view.appendChild(el("div", { class: "notice", style: "border-left-color:var(--green);margin-bottom:14px" },
      "✓ Always available, " + NATIVE_FALLBACK[c.name] + "."));
  }

  const canScan = roleAtLeast(ME.role, "power");
  const layout = el("div", { class: "search-layout" });
  const left = el("div", { class: "fields-panel", style: "max-height:none" });
  const right = el("div", {});
  layout.appendChild(left); layout.appendChild(right);
  view.appendChild(layout);

  // Run panel.
  left.appendChild(el("h4", {}, "Run " + c.name));
  const form = el("div", { class: "form", style: "max-width:none;gap:9px" });
  const profSel = el("select", {});
  (c.profiles || []).forEach((p) => profSel.appendChild(el("option", { value: p.name }, `${p.name}, ${p.desc}`)));
  // Live hint describing the selected profile.
  const profHint = el("div", { style: "font-size:11.5px;color:var(--muted);margin:-4px 0 2px" });
  const updateProfHint = () => { const p = (c.profiles || []).find((x) => x.name === profSel.value); profHint.textContent = p ? p.desc : ""; };
  profSel.addEventListener("change", updateProfHint);
  updateProfHint();
  const targetIn = el("input", { placeholder: c.allow_empty ? "optional, blank scans your own network" : "target: " + c.target_kind });
  const portsIn = el("input", { placeholder: "ports (optional)" });
  const authIn = el("input", { placeholder: "authorization reference (external targets only)" });
  const extChk = el("input", { type: "checkbox" });
  const confirmChk = el("input", { type: "checkbox" });
  const err = el("p", { class: "form-error" });
  const runBtn = el("button", { class: "btn-primary", onclick: run }, "Run scan");
  form.appendChild(el("label", {}, "Profile", profSel));
  form.appendChild(profHint);
  form.appendChild(el("label", {}, "Target", targetIn));
  if (c.target_kind !== "domain" && c.target_kind !== "url" && c.target_kind !== "iface" && c.target_kind !== "pcap")
    form.appendChild(el("label", {}, "Ports", portsIn));
  form.appendChild(el("label", {}, "Authorization reference", authIn));
  form.appendChild(el("label", { style: "flex-direction:row;align-items:center;gap:8px" }, extChk, el("span", {}, "Allow external (public) target")));
  form.appendChild(el("label", { style: "flex-direction:row;align-items:center;gap:8px" }, confirmChk, el("span", {}, "I am authorized")));
  form.appendChild(runBtn);
  form.appendChild(err);
  if (!canScan) { form.querySelectorAll("input,select,button").forEach((e) => e.disabled = true); err.textContent = "Power or admin role required."; }
  if (!c.available) { runBtn.disabled = true; err.textContent = "Install this tool to run it (see install.sh --with-tools)."; }
  left.appendChild(form);

  right.appendChild(el("h3", { style: "margin:0 0 10px;font-size:15px" }, c.name + " history"));
  const hist = el("div", {}, el("div", { class: "spinner" }, "Loading..."));
  right.appendChild(hist);

  async function run() {
    err.textContent = "";
    try {
      await API.post("/api/recon/scan", {
        connector: c.name, target: targetIn.value.trim(), profile: profSel.value,
        ports: portsIn.value.trim(), authorization_ref: authIn.value.trim(),
        allow_external: extChk.checked, confirmed: confirmChk.checked,
      });
      toast("Scan started"); loadHist();
    } catch (ex) { err.textContent = ex.message; }
  }

  async function loadHist() {
    try {
      const r = await API.get("/api/recon/scans");
      const scans = (r.scans || []).filter((s) => s.connector === c.name);
      hist.innerHTML = "";
      if (!scans.length) { hist.appendChild(el("div", { class: "empty" }, "No runs of " + c.name + " yet.")); return; }
      const t = el("table", { class: "grid" }, el("tr", {}, ...["Started", "Target", "Profile", "Status", "Findings", ""].map((h) => el("th", {}, h))));
      for (const sc of scans) {
        t.appendChild(el("tr", {},
          timeTd(sc.started_at), el("td", {}, sc.target || "local"), el("td", {}, sc.profile),
          el("td", {}, statusBadge(sc.status)), el("td", { class: "num" }, String(sc.finding_count)),
          el("td", {}, el("button", { class: "btn-ghost btn-sm", onclick: () => viewFindings(sc) }, "View"))));
      }
      hist.appendChild(t);
    } catch (ex) { hist.innerHTML = ""; hist.appendChild(el("div", { class: "empty" }, ex.message)); }
  }

  async function viewFindings(sc) {
    const r = await API.get(`/api/recon/scans/${sc.id}/findings`);
    const rows = r.findings || [];
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of rows) counts[f.severity] = (counts[f.severity] || 0) + 1;
    const panel = el("div", { style: "margin-top:12px" });
    const summary = el("div", { class: "toolbar", style: "margin-bottom:10px;gap:8px;flex-wrap:wrap" },
      el("span", { style: "color:var(--muted);font-size:12.5px" }, `${sc.target || "local"}, ${rows.length} findings`));
    for (const s of ["critical", "high", "medium", "low", "info"]) if (counts[s]) summary.appendChild(el("span", { class: "badge sev-" + (s === "info" ? "low" : s) }, `${counts[s]} ${s}`));
    panel.appendChild(summary);
    if (sc.command) panel.appendChild(el("div", { class: "notice", style: "font-family:var(--mono);font-size:11.5px;word-break:break-all" }, sc.command));
    const results = el("div", { class: "results" });
    results.appendChild(el("div", { class: "results-tabs" }, el("span", { class: "results-tab active" }, toolDashboardTitle(c.name))));
    const body = el("div", { class: "results-body" });
    body.appendChild(rows.length ? renderToolDashboard(c.name, rows) : el("div", { class: "empty" }, sc.error || "No findings."));
    results.appendChild(body); panel.appendChild(results);
    const ex = right.querySelector("#tool-results"); if (ex) ex.remove();
    panel.id = "tool-results"; right.appendChild(panel);
  }

  loadHist();
  const timer = setInterval(() => { if (location.hash.startsWith("#/tool/")) loadHist(); else clearInterval(timer); }, 4000);
}

// renderCatalog shows every connector as its own card, grouped by category,
// with an availability badge and a one-click launch that selects it.
function renderCatalog(wrap, connectors, onSelect) {
  wrap.innerHTML = "";
  const byCat = {};
  for (const c of connectors) (byCat[c.category] = byCat[c.category] || []).push(c);
  for (const cat of Object.keys(byCat).sort()) {
    const group = el("div", { style: "grid-column:1/-1;margin-top:4px" },
      el("div", { style: "font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--muted);font-weight:600;margin:6px 0" }, cat));
    wrap.appendChild(group);
    for (const c of byCat[cat].sort((a, b) => a.name.localeCompare(b.name))) {
      const card = el("div", { class: "card", style: "cursor:pointer" + (c.available ? "" : ";opacity:0.6") });
      const head = el("div", { style: "display:flex;align-items:center;justify-content:space-between;gap:8px" },
        el("h3", { style: "margin:0;font-size:14px" }, c.name),
        el("span", { class: "badge " + (c.available ? "badge-ok" : "sev-high") }, c.available ? "ready" : "not installed"));
      card.appendChild(head);
      card.appendChild(el("div", { class: "meta", style: "margin-top:4px;min-height:32px" }, c.desc || ""));
      const tags = el("div", { style: "margin-top:8px;display:flex;gap:6px;flex-wrap:wrap" });
      tags.appendChild(el("span", { class: "badge sev-low" }, c.target_kind));
      if (c.needs_root) tags.appendChild(el("span", { class: "badge sev-medium" }, "needs cap"));
      if (c.allow_empty) tags.appendChild(el("span", { class: "badge sev-low" }, "local-ok"));
      // Tools that always work via a built-in engine or native fallback.
      if (NATIVE_FALLBACK[c.name]) tags.appendChild(el("span", { class: "badge badge-ok", title: NATIVE_FALLBACK[c.name] }, "always works"));
      if (ORCHESTRATORS[c.name]) tags.appendChild(el("span", { class: "badge sev-medium", title: "Runs several tools and merges the results" }, "orchestrator"));
      card.appendChild(tags);
      card.addEventListener("click", () => { location.hash = "#/tool/" + encodeURIComponent(c.name); });
      wrap.appendChild(card);
    }
  }
}

// Tools that always return results via a built-in engine or native fallback,
// even if the upstream binary is missing or can't run in this environment.
const NATIVE_FALLBACK = {
  "enum4linux": "Uses the enum4linux binary if installed, else native SMB enumeration",
  "enum4linux-ng": "Uses the enum4linux-ng binary if installed, else native SMB enumeration",
  "smb-enum": "Native SMB enumeration (smbclient + rpcclient + nmblookup)",
  "dnsx": "Uses the dnsx binary if it resolves, else Daru's native DNS resolver",
  "netdiscover": "Native LAN discovery (ARP + reverse DNS)",
  "crtsh": "Native crt.sh certificate-transparency lookup",
  "dns-records": "Native DNS resolver",
  "tls-cert": "Native TLS certificate inspection",
  "rdap": "Native RDAP lookup",
};
const ORCHESTRATORS = { "deep-scan": 1, "web-recon": 1 };

// --- per-tool result dashboards ---
const PORT_TOOLS = ["nmap", "naabu", "masscan", "zmap", "deep-scan", "netdiscover", "nbtscan", "fping", "hping3", "unicornscan"];
const TLS_TOOLS = ["tls-cert", "sslscan", "testssl", "sslyze"];
const DNS_TOOLS = ["crtsh", "subfinder", "amass", "dnsx", "dns-records", "dnsrecon", "dnsenum", "fierce", "dnstwist"];
const WEB_TOOLS = ["gobuster", "ffuf", "katana", "httpx", "whatweb", "wafw00f", "web-recon"];
const VULN_TOOLS = ["nuclei", "nikto", "sqlmap", "wapiti", "openvas"];
const TRAFFIC_TOOLS = ["tshark-capture", "tshark-pcap", "tcpdump"];
const OSINT_TOOLS = ["whois", "rdap", "theharvester", "spiderfoot", "recon-ng"];
const ENUM_TOOLS = ["smbmap", "smb-enum", "enum4linux", "enum4linux-ng", "snmpwalk", "onesixtyone", "unicornscan"];

// Each tool gets its own dashboard heading so the result view is unmistakably
// that tool's, not a generic one.
const TOOL_TITLES = {
  nmap: "Nmap, hosts, ports & service versions",
  "deep-scan": "Deep Scan, full device profiles (god mode)",
  netdiscover: "Netdiscover, live LAN devices",
  nbtscan: "NBTScan, NetBIOS names & MACs",
  naabu: "Naabu, open ports",
  masscan: "Masscan, open ports (async)",
  zmap: "ZMap, single-port sweep",
  fping: "fping, alive hosts",
  hping3: "hping3, crafted-probe responses",
  unicornscan: "Unicornscan, TCP/IP responses",
  "tls-cert": "TLS Certificate, issuer, SANs & expiry",
  sslscan: "SSLScan, protocols & ciphers",
  testssl: "testssl.sh, TLS weaknesses",
  sslyze: "SSLyze, TLS configuration",
  nuclei: "Nuclei, template matches",
  nikto: "Nikto, web server issues",
  sqlmap: "sqlmap, SQL injection",
  wapiti: "Wapiti, web vulnerabilities",
  gobuster: "Gobuster, discovered content",
  ffuf: "ffuf, fuzzed endpoints",
  katana: "Katana, crawled endpoints",
  httpx: "httpx, HTTP probes & tech",
  whatweb: "WhatWeb, technology fingerprint",
  wafw00f: "wafw00f, WAF detection",
  "web-recon": "Web Assessment, probe, fingerprint, content & vulns (god mode)",
  subfinder: "Subfinder, subdomains",
  amass: "Amass, attack surface",
  dnsx: "dnsx, DNS records",
  crtsh: "crt.sh, CT-log subdomains",
  "dns-records": "DNS Records, A/AAAA/MX/NS/TXT",
  dnsrecon: "DNSRecon, DNS enumeration",
  dnsenum: "dnsenum, DNS enumeration",
  fierce: "fierce, DNS reconnaissance",
  dnstwist: "dnstwist, lookalike domains",
  whois: "whois, registration record",
  rdap: "RDAP, registration data",
  theharvester: "theHarvester, emails & hosts",
  smbmap: "SMBMap, SMB shares",
  "smb-enum": "SMB Enumeration, shares, users, groups & NetBIOS",
  enum4linux: "enum4linux, SMB/NetBIOS enumeration",
  "enum4linux-ng": "enum4linux-ng, SMB/NetBIOS enumeration",
  snmpwalk: "snmpwalk, SNMP tree",
  onesixtyone: "onesixtyone, SNMP communities",
  traceroute: "traceroute, network path",
  "tshark-capture": "tshark, live capture summary",
  "tshark-pcap": "tshark, capture file summary",
  tcpdump: "tcpdump, packet headers",
};

function toolDashboardTitle(conn) {
  return TOOL_TITLES[conn] || (conn + ", findings");
}

function renderToolDashboard(conn, rows) {
  if (PORT_TOOLS.includes(conn)) return renderPortDashboard(rows);
  if (DNS_TOOLS.includes(conn)) return renderListDashboard(rows, "Host / record");
  if (TLS_TOOLS.includes(conn)) return renderFindingTable(rows, ["Severity", "Port", "Title", "Detail"],
    (f) => [sevCell(f), f.port || "-", f.title, f.detail || ""]);
  if (WEB_TOOLS.includes(conn)) return renderWebDashboard(rows);
  if (TRAFFIC_TOOLS.includes(conn)) return renderTrafficDashboard(rows);
  if (VULN_TOOLS.includes(conn)) return renderFindingTable(rows, ["Severity", "Title", "Detail"],
    (f) => [sevCell(f), f.title, fieldDetail(f)]);
  if (OSINT_TOOLS.includes(conn)) return renderFindingTable(rows, ["Type", "Value"],
    (f) => [(f.fields && (f.fields.record_type || f.fields.nameserver ? "ns" : "")) || f.service || "info", f.title]);
  // Default: severity-first table with any extra field hints.
  return renderFindingTable(rows, ["Severity", "Port", "Service", "Title", "Detail"],
    (f) => [sevCell(f), f.port || "-", f.service || "-", f.title, fieldDetail(f)]);
}

// Web endpoints/fingerprints: show path/URL, HTTP status, size/detail.
function renderWebDashboard(rows) {
  const t = el("table", { class: "grid" }, el("tr", {}, ...["Severity", "Path / URL", "Status", "Detail"].map((h) => el("th", {}, h))));
  for (const f of rows) {
    const fl = f.fields || {};
    t.appendChild(el("tr", {},
      el("td", {}, sevCell(f)),
      el("td", { style: "white-space:normal" }, fl.path || fl.url || f.title),
      el("td", {}, fl.status || fl.status_code || "-"),
      el("td", { style: "white-space:normal" }, f.detail || fl.title || fl.tech || "")));
  }
  return t;
}

// Traffic/packet summary: time, endpoints, protocol, port, info.
function renderTrafficDashboard(rows) {
  const t = el("table", { class: "grid" }, el("tr", {}, ...["Source", "→", "Destination", "Proto", "Port", "Info"].map((h) => el("th", {}, h))));
  for (const f of rows) {
    const fl = f.fields || {};
    t.appendChild(el("tr", {},
      el("td", {}, fl.src_ip || "-"), el("td", { style: "color:var(--muted)" }, "→"),
      el("td", {}, fl.dst_ip || "-"),
      el("td", {}, el("span", { class: "badge " + protoClass(fl.proto || f.service) }, fl.proto || f.service || "?")),
      el("td", {}, fl.dst_port || f.port || "-"),
      el("td", { style: "white-space:normal" }, f.detail || "")));
  }
  return t;
}

function sevCell(f) { return el("span", { class: "badge sev-" + (f.severity === "info" ? "low" : f.severity || "low") }, f.severity); }

function fieldDetail(f) {
  let d = f.detail || "";
  const fl = f.fields || {};
  const extra = ["version", "template", "matched_at", "url", "id"].map((k) => fl[k]).filter(Boolean);
  if (extra.length && !d) d = extra.join(" · ");
  return d;
}

function renderFindingTable(rows, headers, cells) {
  const t = el("table", { class: "grid" }, el("tr", {}, ...headers.map((h) => el("th", {}, h))));
  for (const f of rows) t.appendChild(el("tr", {}, ...cells(f).map((c) => el("td", { style: "white-space:normal" }, c))));
  return t;
}

function renderListDashboard(rows, label) {
  const t = el("table", { class: "grid" }, el("tr", {}, el("th", {}, label), el("th", {}, "Type"), el("th", {}, "Detail")));
  for (const f of rows) {
    const fl = f.fields || {};
    t.appendChild(el("tr", {},
      el("td", {}, f.title),
      el("td", {}, fl.record_type || f.service || (fl.subdomain ? "subdomain" : "-")),
      el("td", { style: "white-space:normal" }, f.detail || fl.value || "")));
  }
  return t;
}

// renderPortDashboard groups findings by host, showing a device header with
// OS/vendor/hostname and a nested list of open ports with service + version.
function renderPortDashboard(rows) {
  const hosts = {}; // ip -> { meta, ports: [] }
  const order = [];
  for (const f of rows) {
    const fl = f.fields || {};
    const ip = fl.ip || f.target || "unknown";
    if (!hosts[ip]) { hosts[ip] = { meta: null, ports: [] }; order.push(ip); }
    if (fl._kind === "host") hosts[ip].meta = f;
    else if (f.port) hosts[ip].ports.push(f);
    else hosts[ip].ports.push(f);
  }
  const wrap = el("div", { style: "padding:4px 0" });
  for (const ip of order) {
    const h = hosts[ip];
    const fl = (h.meta && h.meta.fields) || {};
    const header = el("div", { style: "padding:10px 14px;background:var(--panel-2);border-top:1px solid var(--border-soft);display:flex;gap:14px;flex-wrap:wrap;align-items:center" });
    header.appendChild(el("span", { style: "font-family:var(--mono);color:var(--text-strong);font-weight:600" }, ip));
    if (fl.hostname) header.appendChild(el("span", { class: "badge badge-ok" }, fl.hostname));
    if (fl.vendor) header.appendChild(el("span", { style: "color:var(--muted);font-size:12px" }, "🏷 " + fl.vendor));
    if (fl.os) header.appendChild(el("span", { style: "color:var(--muted);font-size:12px" }, "💻 " + fl.os));
    if (fl.mac) header.appendChild(el("span", { style: "color:var(--muted);font-size:12px;font-family:var(--mono)" }, fl.mac));
    header.appendChild(el("span", { style: "color:var(--muted);font-size:12px;margin-left:auto" }, h.ports.length + " port(s)"));
    wrap.appendChild(header);
    if (h.ports.length) {
      const t = el("table", { class: "grid" }, el("tr", {}, ...["Port", "Service", "Version / detail", "Severity"].map((x) => el("th", {}, x))));
      h.ports.sort((a, b) => (parseInt(a.port) || 0) - (parseInt(b.port) || 0));
      for (const p of h.ports) {
        const pf = p.fields || {};
        t.appendChild(el("tr", {},
          el("td", {}, p.port || "-"),
          el("td", {}, p.service || pf.service || "-"),
          el("td", { style: "white-space:normal" }, p.detail || pf.version || p.title || ""),
          el("td", {}, sevCell(p))));
      }
      wrap.appendChild(t);
    }
  }
  return wrap;
}

// ===================== LIVE MONITOR =====================
function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? 1 : 0) + " " + u[i];
}
function fmtBps(bits) {
  bits = Number(bits) || 0;
  const u = ["bps", "Kbps", "Mbps", "Gbps"];
  let i = 0;
  while (bits >= 1000 && i < u.length - 1) { bits /= 1000; i++; }
  return bits.toFixed(i ? 1 : 0) + " " + u[i];
}
function signalLabel(dbm) {
  if (!dbm) return "";
  const q = dbm >= -50 ? "excellent" : dbm >= -60 ? "good" : dbm >= -70 ? "fair" : "weak";
  return `${dbm} dBm (${q})`;
}

let liveState = { ifTimer: null, prev: {}, es: null };

async function renderLive(view) {
  // Clean up any previous stream/timers when the view is re-rendered.
  stopLiveStream();
  if (liveState.ifTimer) { clearInterval(liveState.ifTimer); liveState.ifTimer = null; }
  liveState.prev = {};

  view.appendChild(pageHead("Live Monitor",
    "Real-time interfaces, WiFi link quality, throughput, and packet capture"));

  // ---- Interfaces / WiFi ----
  view.appendChild(el("h3", { style: "margin:4px 0 10px;font-size:15px" }, "Interfaces & WiFi"));
  const ifWrap = el("div", { class: "cards" }, el("div", { class: "spinner" }, "Reading interfaces..."));
  view.appendChild(ifWrap);

  async function loadIfaces() {
    let data;
    try { data = await API.get("/api/live/interfaces"); }
    catch (ex) { ifWrap.innerHTML = ""; ifWrap.appendChild(el("div", { class: "empty" }, ex.message)); return; }
    const now = Date.now();
    const ifaces = (data.interfaces || [])
      .filter((i) => i.up && !i.name.startsWith("veth") && !i.name.startsWith("br-"))
      .sort((a, b) => (b.wireless - a.wireless) || a.name.localeCompare(b.name));
    ifWrap.innerHTML = "";
    if (!ifaces.length) { ifWrap.appendChild(el("div", { class: "empty" }, "No active interfaces.")); return; }
    for (const i of ifaces) {
      // Live throughput from counter deltas.
      let rxbps = 0, txbps = 0;
      const p = liveState.prev[i.name];
      if (p && now > p.ts) {
        const dt = (now - p.ts) / 1000;
        rxbps = Math.max(0, (i.rx_bytes - p.rx) * 8 / dt);
        txbps = Math.max(0, (i.tx_bytes - p.tx) * 8 / dt);
      }
      liveState.prev[i.name] = { rx: i.rx_bytes, tx: i.tx_bytes, ts: now };

      const rows = [];
      const addr = (i.addrs || []).find((a) => a.includes(".")) || (i.addrs || [])[0] || "-";
      rows.push(["IP", addr.split("/")[0]]);
      rows.push(["MAC", i.mac || "-"]);
      if (i.wireless) {
        rows.push(["SSID", i.ssid || "-"]);
        const band = i.band || (i.freq_mhz ? (i.freq_mhz >= 5000 ? "5 GHz" : "2.4 GHz") : "");
        rows.push(["Band", (band ? band : "-") + (i.freq_mhz ? " · " + i.freq_mhz + " MHz" : "")]);
        if (i.wifi_generation) rows.push(["Standard", i.wifi_generation + (i.channel_width ? " · " + i.channel_width : "")]);
        rows.push(["Signal", signalLabel(i.signal_dbm) || "-"]);
        rows.push(["Link rate ↓", i.rx_mbps ? i.rx_mbps + " Mbps" : (i.rx_bitrate ? i.rx_bitrate.split(" ").slice(0, 2).join(" ") : "-")]);
        rows.push(["Link rate ↑", i.tx_mbps ? i.tx_mbps + " Mbps" : (i.tx_bitrate ? i.tx_bitrate.split(" ").slice(0, 2).join(" ") : "-")]);
      } else {
        rows.push(["Link speed", i.speed_mbps ? i.speed_mbps + " Mbps" : "-"]);
        rows.push(["MTU", String(i.mtu || "-")]);
      }
      rows.push(["Throughput ↓", fmtBps(rxbps)]);
      rows.push(["Throughput ↑", fmtBps(txbps)]);
      rows.push(["Total RX/TX", fmtBytes(i.rx_bytes) + " / " + fmtBytes(i.tx_bytes)]);

      const card = el("div", { class: "card" });
      card.appendChild(el("h3", {},
        (i.wireless ? "📶 " : "🖧 ") + i.name,
        el("span", { class: "badge sev-low", style: "margin-left:8px;font-weight:600" }, i.wireless ? "WiFi" : "wired")));
      const tbl = el("table", { style: "width:100%;font-size:12.5px;margin-top:6px" });
      for (const [k, v] of rows) {
        tbl.appendChild(el("tr", {},
          el("td", { style: "color:var(--muted);padding:2px 8px 2px 0;white-space:nowrap" }, k),
          el("td", { style: "font-family:var(--mono);color:var(--text-strong);text-align:right" }, v)));
      }
      card.appendChild(tbl);
      // WiFi signal quality bar (−90 dBm = 0%, −30 dBm = 100%).
      if (i.wireless && i.signal_dbm) {
        const pct = Math.max(0, Math.min(100, Math.round((i.signal_dbm + 90) / 60 * 100)));
        const color = pct >= 66 ? "var(--green)" : pct >= 40 ? "var(--amber)" : "var(--red)";
        card.appendChild(el("div", { style: "margin-top:8px" },
          el("div", { style: "display:flex;justify-content:space-between;font-size:11px;color:var(--muted)" },
            el("span", {}, "Signal quality"), el("span", {}, pct + "%")),
          el("div", { style: "height:6px;border-radius:3px;background:var(--border);overflow:hidden;margin-top:2px" },
            el("div", { style: `height:100%;width:${pct}%;background:${color}` }))));
      }
      // Live throughput bar scaled to the interface's link speed (or 1 Gbps).
      const linkbps = (i.speed_mbps ? i.speed_mbps : 1000) * 1e6;
      const curbps = liveState.prev[i.name] ? Math.max(rxbps, txbps) : 0;
      const tpct = Math.max(0, Math.min(100, Math.round(curbps / linkbps * 100)));
      card.appendChild(el("div", { style: "margin-top:8px" },
        el("div", { style: "display:flex;justify-content:space-between;font-size:11px;color:var(--muted)" },
          el("span", {}, "Live utilization"), el("span", {}, fmtBps(curbps))),
        el("div", { style: "height:6px;border-radius:3px;background:var(--border);overflow:hidden;margin-top:2px" },
          el("div", { style: `height:100%;width:${Math.max(2, tpct)}%;background:var(--accent);transition:width .4s` }))));
      ifWrap.appendChild(card);
    }
  }
  await loadIfaces();
  liveState.ifTimer = setInterval(() => {
    if (location.hash === "#/live") loadIfaces();
    else { clearInterval(liveState.ifTimer); liveState.ifTimer = null; }
  }, 2000);

  // ---- Live packet capture ----
  const canCap = roleAtLeast(ME.role, "power");
  view.appendChild(el("h3", { style: "margin:22px 0 10px;font-size:15px" }, "Live packet capture"));
  if (!canCap) {
    view.appendChild(el("div", { class: "notice" }, "Power or admin role required to capture packets."));
    return;
  }

  // Offline PCAP analysis: upload a .pcap and decode it with tshark (DNS/SNI/
  // HTTP), no capture permission needed.
  const pcapIn = el("input", { type: "file", accept: ".pcap,.pcapng,.cap", style: "display:none" });
  const pcapBtn = el("button", { class: "btn-ghost btn-sm", onclick: () => pcapIn.click() }, "⬆ Analyze a PCAP file");
  pcapIn.addEventListener("change", async () => {
    const f = pcapIn.files[0];
    if (!f) return;
    const fd = new FormData();
    fd.append("file", f);
    pcapBtn.disabled = true; pcapBtn.textContent = "Analyzing " + f.name + "…";
    try {
      const csrf = csrfToken();
      const res = await fetch("/api/recon/pcap", { method: "POST", body: fd, headers: csrf ? { "X-Daru-CSRF": csrf } : {} });
      const d = await res.json();
      if (!res.ok) throw new Error(d.error || "upload failed");
      toast("PCAP uploaded; decoded packets appear in Recon → " + f.name);
      setTimeout(() => { location.hash = "#/tool/tshark-pcap"; }, 800);
    } catch (ex) { toast(ex.message, "error"); }
    finally { pcapBtn.disabled = false; pcapBtn.textContent = "⬆ Analyze a PCAP file"; pcapIn.value = ""; }
  });
  view.appendChild(el("div", { class: "toolbar", style: "margin-bottom:10px" }, pcapBtn, pcapIn));

  const ctrl = el("div", { class: "toolbar", style: "flex-wrap:wrap;gap:10px;margin-bottom:12px" });
  const ifSel = el("select", {});
  const filterIn = el("input", { placeholder: "capture filter (BPF), e.g. tcp port 443", style: "min-width:260px" });
  const durSel = el("select", {});
  [["60", "60s"], ["300", "5 min"], ["900", "15 min"]].forEach(([v, l]) => durSel.appendChild(el("option", { value: v }, l)));
  const startBtn = el("button", { class: "btn-primary" }, "Start capture");
  const stopBtn = el("button", { class: "btn-ghost", disabled: "" }, "Stop");
  const saveChk = el("input", { type: "checkbox" });
  ctrl.appendChild(el("label", { style: "display:flex;align-items:center;gap:6px;margin:0" }, "Interface", ifSel));
  ctrl.appendChild(filterIn);
  ctrl.appendChild(el("label", { style: "display:flex;align-items:center;gap:6px;margin:0" }, "Duration", durSel));
  ctrl.appendChild(el("label", { style: "display:flex;align-items:center;gap:6px;margin:0", title: "Store captured packets as searchable events (index=network)" }, saveChk, el("span", {}, "Save to search")));
  ctrl.appendChild(startBtn);
  ctrl.appendChild(stopBtn);
  view.appendChild(ctrl);

  // Populate interface selector (capturable physical/wireless interfaces).
  try {
    const data = await API.get("/api/live/interfaces");
    for (const i of (data.interfaces || []).filter((x) => x.up && !x.name.startsWith("veth") && !x.name.startsWith("br-"))) {
      ifSel.appendChild(el("option", { value: i.name }, i.name + (i.wireless ? " (WiFi)" : "")));
    }
  } catch (_) {}

  // Live stats row.
  const stats = el("div", { class: "stat-row" });
  view.appendChild(stats);
  const capStats = { total: 0, start: 0, proto: {}, talkers: {}, hosts: {} };
  function drawStats() {
    stats.innerHTML = "";
    const secs = capStats.start ? Math.max(1, (Date.now() - capStats.start) / 1000) : 1;
    stats.appendChild(statCard(capStats.total, "Packets"));
    stats.appendChild(statCard(Math.round(capStats.total / secs), "Packets/sec"));
    const topProto = Object.entries(capStats.proto).sort((a, b) => b[1] - a[1])[0];
    stats.appendChild(statCard(topProto ? topProto[0] : "-", "Top protocol"));
    const topTalk = Object.entries(capStats.talkers).sort((a, b) => b[1] - a[1])[0];
    stats.appendChild(statCard(topTalk ? topTalk[0] : "-", "Top talker"));
  }
  drawStats();

  // Protocol + talkers breakdown panels.
  const breakWrap = el("div", { class: "cards", style: "margin-bottom:14px" });
  view.appendChild(breakWrap);
  function drawBreakdown() {
    breakWrap.innerHTML = "";
    breakWrap.appendChild(miniBreakdown("Protocols", capStats.proto, capStats.total));
    breakWrap.appendChild(miniBreakdown("Top talkers", capStats.talkers, capStats.total));
    breakWrap.appendChild(miniBreakdown("Top destinations (Host / SNI)", capStats.hosts, Object.values(capStats.hosts).reduce((a, b) => a + b, 0)));
  }

  // Packet table (rolling, newest first, capped).
  const results = el("div", { class: "results" });
  results.appendChild(el("div", { class: "results-tabs" }, el("span", { class: "results-tab active", id: "cap-title" }, "Packet stream")));
  const body = el("div", { class: "results-body" }, el("div", { class: "empty" }, "Start a capture to see live packets."));
  results.appendChild(body);
  view.appendChild(results);

  const MAX_ROWS = 400;
  let table = null;

  function ensureTable() {
    if (table) return;
    body.innerHTML = "";
    table = el("table", { class: "grid" }, el("tr", {}, ...["Time", "Source", "→", "Destination", "Proto", "Len", "Host / SNI", "Info"].map((h) => el("th", {}, h))));
    body.appendChild(table);
  }
  function addPacket(p) {
    ensureTable();
    const t = new Date(p.time_ms).toLocaleTimeString();
    const src = p.src_ip ? p.src_ip + (p.src_port ? ":" + p.src_port : "") : (p.src_mac || "?");
    const dst = p.dst_ip ? p.dst_ip + (p.dst_port ? ":" + p.dst_port : "") : (p.dst_mac || "?");
    // Dedicated Host/SNI column: the Wireshark-grade application identity.
    const host = p.sni || p.dns_query || p.http_host || "";
    const hostCell = host
      ? el("td", { style: "white-space:normal" }, el("span", { class: "badge badge-ok", style: "font-weight:500" }, host))
      : el("td", { style: "color:var(--muted)" }, "-");
    const row = el("tr", {},
      el("td", {}, t), el("td", {}, src), el("td", { style: "color:var(--muted)" }, "→"),
      el("td", {}, dst),
      el("td", {}, el("span", { class: "badge " + protoClass(p.protocol) }, p.protocol || "?")),
      el("td", { class: "num" }, String(p.length || 0)),
      hostCell,
      el("td", { style: "white-space:normal" }, p.info || ""));
    // newest first
    if (table.rows.length > 1) table.insertBefore(row, table.rows[1]);
    else table.appendChild(row);
    while (table.rows.length > MAX_ROWS + 1) table.deleteRow(table.rows.length - 1);

    // stats
    capStats.total++;
    if (p.protocol) capStats.proto[p.protocol] = (capStats.proto[p.protocol] || 0) + 1;
    if (p.src_ip) capStats.talkers[p.src_ip] = (capStats.talkers[p.src_ip] || 0) + 1;
    if (host) capStats.hosts[host] = (capStats.hosts[host] || 0) + 1;
  }

  let statTimer = null;
  async function startCapture() {
    stopLiveStream();
    capStats.total = 0; capStats.start = Date.now(); capStats.proto = {}; capStats.talkers = {}; capStats.hosts = {};
    table = null;
    body.innerHTML = "";
    body.appendChild(el("div", { class: "spinner" }, "Starting capture on " + ifSel.value + "..."));
    let start;
    try {
      start = await API.post("/api/live/capture/start", { iface: ifSel.value, duration: parseInt(durSel.value, 10) || 60, filter: filterIn.value.trim(), save: saveChk.checked });
    } catch (ex) {
      body.innerHTML = "";
      body.appendChild(el("div", { class: "empty" }, "Capture error: " + ex.message));
      toast(ex.message, "error");
      return;
    }
    const token = start.stream_token;
    if (!token) { toast("Capture start did not return a stream token", "error"); return; }
    const es = new EventSource("/api/live/capture?stream_token=" + encodeURIComponent(token));
    liveState.es = es;
    startBtn.disabled = true; stopBtn.disabled = false;
    document.getElementById("cap-title").textContent = "Capturing on " + ifSel.value + "...";
    es.addEventListener("open", () => { ensureTable(); });
    es.addEventListener("packet", (e) => { try { addPacket(JSON.parse(e.data)); } catch (_) {} });
    es.addEventListener("end", (e) => {
      let d = {}; try { d = JSON.parse(e.data); } catch (_) {}
      if (d.error) { body.innerHTML = ""; body.appendChild(el("div", { class: "empty" }, "Capture error: " + d.error)); toast(d.error, "error"); }
      stopCapture("Capture ended (" + (d.total || capStats.total) + " packets)");
    });
    es.onerror = () => { stopCapture("Capture stopped"); };
    statTimer = setInterval(() => { drawStats(); drawBreakdown(); }, 1000);
    liveState.statTimer = statTimer;
  }
  function stopCapture(msg) {
    stopLiveStream();
    if (statTimer) { clearInterval(statTimer); statTimer = null; }
    drawStats(); drawBreakdown();
    startBtn.disabled = false; stopBtn.disabled = true;
    document.getElementById("cap-title").textContent = msg || "Packet stream";
  }
  startBtn.addEventListener("click", startCapture);
  stopBtn.addEventListener("click", () => stopCapture("Capture stopped (" + capStats.total + " packets)"));
}

function stopLiveStream() {
  if (liveState.es) { try { liveState.es.close(); } catch (_) {} liveState.es = null; }
  if (liveState.statTimer) { clearInterval(liveState.statTimer); liveState.statTimer = null; }
}

function protoClass(p) {
  p = (p || "").toUpperCase();
  if (p.includes("TLS") || p.includes("HTTPS") || p.includes("SSL")) return "sev-low";
  if (p.includes("HTTP") || p.includes("DNS")) return "sev-medium";
  if (p.includes("ARP") || p.includes("ICMP")) return "badge-ok";
  return "";
}

function miniBreakdown(title, counts, total) {
  const card = el("div", { class: "card" });
  card.appendChild(el("h3", {}, title));
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  if (!entries.length) { card.appendChild(el("div", { class: "meta" }, "No data yet.")); return card; }
  for (const [k, v] of entries) {
    const pct = total ? Math.round((v / total) * 100) : 0;
    const row = el("div", { style: "margin:7px 0" });
    row.appendChild(el("div", { style: "display:flex;justify-content:space-between;font-size:12px" },
      el("span", { style: "font-family:var(--mono)" }, k),
      el("span", { style: "color:var(--muted)" }, v + " · " + pct + "%")));
    const bar = el("div", { style: "height:5px;border-radius:3px;background:var(--border);margin-top:3px;overflow:hidden" },
      el("div", { style: `height:100%;width:${pct}%;background:var(--accent)` }));
    row.appendChild(bar);
    card.appendChild(row);
  }
  return card;
}

// ===================== ACCOUNT =====================
// describeUA turns a user agent into "Chrome on macOS" style text.
function describeUA(ua) {
  if (!ua) return "Unknown client";
  const browser = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox"
    : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : /curl\//i.test(ua) ? "curl"
    : /python/i.test(ua) ? "Python script" : ua.split(/[ /]/)[0];
  const os = /Windows/.test(ua) ? "Windows" : /iPhone|iPad/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android"
    : /Mac OS X|Macintosh/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
  return os ? browser + " on " + os : browser;
}

function sessionsCard() {
  const card = el("div", { class: "card", style: "margin-top:14px" });
  const head = el("div", { style: "display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px" },
    el("div", {}, el("h3", { style: "margin:0" }, "Active sessions"),
      el("div", { class: "meta" }, "Every browser or script signed in as you. Sign out any you do not recognize.")));
  const othersBtn = el("button", { class: "btn-ghost btn-danger", onclick: async () => {
    if (!(await confirmDialog("Sign out every other session? This one stays signed in.", "Sign out others"))) return;
    try { await API.post("/api/me/sessions/revoke-others", {}); toast("Other sessions signed out"); load(); } catch (ex) { toast(ex.message, "error"); }
  } }, "Sign out all other sessions");
  head.appendChild(othersBtn);
  card.appendChild(head);
  const body = el("div", {}, el("div", { class: "spinner" }, "Loading sessions..."));
  card.appendChild(body);
  async function load() {
    try {
      const r = await API.get("/api/me/sessions");
      const list = r.sessions || [];
      body.innerHTML = "";
      othersBtn.disabled = list.filter((x) => !x.current).length === 0;
      if (!list.length) { body.appendChild(el("div", { class: "empty" }, "No active sessions.")); return; }
      const t = el("table", { class: "grid" }, el("tr", {}, ...["Client", "IP", "Method", "Signed in", "Expires", ""].map((h) => el("th", {}, h))));
      for (const x of list) {
        t.appendChild(el("tr", {},
          el("td", { class: "nowrap", title: x.user_agent || "" }, describeUA(x.user_agent),
            x.current ? el("span", { class: "badge badge-ok", style: "margin-left:8px" }, "this session") : null),
          el("td", { class: "nowrap" }, x.ip || "-"), el("td", {}, x.method || "-"),
          timeTd(x.created_at.replace("Z", "")), el("td", { class: "nowrap", title: fmtTime(x.expires_at) }, fmtTime(x.expires_at).slice(0, 16)),
          el("td", {}, x.current ? null : el("button", { class: "btn-ghost btn-sm btn-danger", onclick: async () => {
            try { await API.post("/api/me/sessions/" + encodeURIComponent(x.id) + "/revoke", {}); toast("Session signed out"); load(); } catch (ex) { toast(ex.message, "error"); }
          } }, "Sign out"))));
      }
      body.appendChild(el("div", { class: "table-scroll" }, t));
    } catch (ex) { body.innerHTML = ""; body.appendChild(el("div", { class: "empty" }, ex.message)); }
  }
  load();
  return card;
}

async function renderAccount(view) {
  view.appendChild(pageHead("Account", "Your profile and sign-in security"));
  const grid = el("div", { class: "account-grid" });
  view.appendChild(grid);

  const profile = el("div", { class: "card" });
  profile.appendChild(el("h3", { style: "margin:0 0 12px" }, "Profile"));
  const kv = el("dl", { class: "kv" });
  for (const [k, v] of [["Username", ME.username], ["Role", ME.role], ["Two-factor", ME.totp_enabled ? "on" : "off"],
    ["Time zone", Intl.DateTimeFormat().resolvedOptions().timeZone]]) {
    kv.appendChild(el("dt", {}, k)); kv.appendChild(el("dd", {}, String(v)));
  }
  profile.appendChild(kv);
  grid.appendChild(profile);
  view.appendChild(sessionsCard());

  const totpCard = el("div", { class: "card", style: "" });
  totpCard.appendChild(el("h3", { style: "margin:0 0 6px" }, "Two-factor authentication (TOTP)"));
  totpCard.appendChild(el("div", { class: "meta" }, (ME && ME.totp_enabled ? "TOTP is enabled for your account." : "TOTP is off. Enable it with an authenticator app for a second factor at login.")));
  const totpBtns = el("div", { style: "display:flex;gap:8px;margin-top:10px;flex-wrap:wrap" });
  if (ME && ME.totp_enabled) {
    totpBtns.appendChild(el("button", { class: "btn-ghost", onclick: async () => {
      const v = await openModal("Disable TOTP", "Enter your current authenticator code to disable TOTP.", [{ name: "code", label: "Authenticator code", type: "text", required: true }], "Disable TOTP");
      if (!v) return;
      try { await API.post("/api/me/totp/disable", { code: v.code }); toast("TOTP disabled"); ME.totp_enabled = false; route(); } catch (ex) { toast(ex.message, "error"); }
    } }, "Disable TOTP"));
  } else {
    totpBtns.appendChild(el("button", { class: "btn-primary", onclick: async () => {
      try {
        const r = await API.post("/api/me/totp/enrol", {});
        const v = await openModal("Enable TOTP", "Scan this secret into your authenticator app, then enter the 6-digit code. Secret: " + (r.secret || ""), [{ name: "code", label: "Authenticator code", type: "text", required: true }], "Enable TOTP");
        if (!v) return;
        await API.post("/api/me/totp/enable", { code: v.code });
        toast("TOTP enabled"); ME.totp_enabled = true; route();
      } catch (ex) { toast(ex.message, "error"); }
    } }, "Enable TOTP"));
  }
  totpCard.appendChild(totpBtns);
  grid.appendChild(totpCard);
}

// ===================== ADMIN =====================
// adminAudit shows the stored audit trail with filters and CSV export.
const AUDIT_EVENT_GROUPS = [["", "All events"], ["login.", "Sign in"], ["logout", "Sign out"], ["user.", "Users"],
  ["token.", "Ingest tokens"], ["index.", "Indexes"], ["totp.", "Two-factor"], ["scan.", "Scans"],
  ["live.", "Live capture"], ["tools.", "Tool updates"], ["session.", "Sessions"], ["notable.", "Incidents"]];
const AUDIT_RANGES = [["24h", "Last 24 hours", 1], ["7d", "Last 7 days", 7], ["30d", "Last 30 days", 30], ["90d", "Last 90 days", 90], ["all", "All time", 0]];
function adminAudit(body) {
  const actor = el("input", { placeholder: "User", "aria-label": "Filter by user", style: "width:150px" });
  const text = el("input", { placeholder: "IP or detail text", "aria-label": "Filter by IP or detail", style: "width:200px" });
  const group = el("select", { "aria-label": "Event type" }, ...AUDIT_EVENT_GROUPS.map(([v, l]) => el("option", { value: v }, l)));
  const outcome = el("select", { "aria-label": "Outcome" }, el("option", { value: "" }, "Any outcome"), el("option", { value: "ok" }, "Succeeded"), el("option", { value: "failure" }, "Failed"));
  const range = el("select", { "aria-label": "Time range" }, ...AUDIT_RANGES.map(([v, l]) => el("option", { value: v }, l)));
  range.value = "7d";
  const out = el("div", {}, el("div", { class: "spinner" }, "Loading audit log..."));
  let last = [];
  async function load() {
    const q = new URLSearchParams({ limit: "1000" });
    if (actor.value.trim()) q.set("actor", actor.value.trim());
    if (text.value.trim()) q.set("q", text.value.trim());
    if (group.value) q.set("event", group.value);
    if (outcome.value) q.set("outcome", outcome.value);
    const days = (AUDIT_RANGES.find(([v]) => v === range.value) || [])[2];
    if (days) q.set("since", new Date(Date.now() - days * 86400000).toISOString().replace(/\.\d{3}Z$/, "Z"));
    out.innerHTML = "";
    out.appendChild(el("div", { class: "spinner" }, "Loading audit log..."));
    try {
      const r = await API.get("/api/admin/audit?" + q.toString());
      last = r.events || [];
      out.innerHTML = "";
      const fails = last.filter((e) => e.outcome === "failure").length;
      out.appendChild(el("div", { class: "meta", style: "margin-bottom:10px" },
        `${fmtNum(last.length)} events${last.length >= 1000 ? " (newest 1,000 shown; narrow the filters to see more)" : ""} · ${fmtNum(fails)} failed`));
      if (!last.length) { out.appendChild(el("div", { class: "empty" }, "No audit events match these filters.")); return; }
      const t = el("table", { class: "grid" }, el("tr", {}, ...["Time", "Event", "User", "IP", "Outcome", "Details"].map((h) => el("th", {}, h))));
      for (const e of last) {
        const details = el("td", { style: "white-space:normal" });
        for (const [k, v] of Object.entries(e.details || {})) details.appendChild(el("span", { class: "chip", style: "margin:0 4px 4px 0;display:inline-block" }, el("b", {}, k), "=" + v));
        if (!details.childNodes.length) details.appendChild(document.createTextNode("-"));
        t.appendChild(el("tr", {},
          timeTd(e.time), el("td", { class: "nowrap" }, e.event), el("td", { class: "nowrap" }, e.actor || "-"),
          el("td", { class: "nowrap" }, e.ip || "-"),
          el("td", {}, el("span", { class: "badge " + (e.outcome === "failure" ? "badge-fail" : "badge-ok") }, e.outcome === "failure" ? "failed" : "ok")),
          details));
      }
      out.appendChild(el("div", { class: "table-scroll" }, t));
    } catch (ex) { out.innerHTML = ""; out.appendChild(el("div", { class: "empty" }, ex.message)); }
  }
  function exportCsv() {
    const esc = (v) => '"' + String(v == null ? "" : v).replace(/"/g, '""') + '"';
    const rows = [["time_utc", "event", "user", "ip", "outcome", "details"]];
    for (const e of last) rows.push([e.time, e.event, e.actor, e.ip, e.outcome, Object.entries(e.details || {}).map(([k, v]) => k + "=" + v).join("; ")]);
    downloadFile("daru-audit-" + new Date().toISOString().slice(0, 10) + ".csv", rows.map((r) => r.map(esc).join(",")).join("\n"), "text/csv");
  }
  for (const c of [group, outcome, range]) c.addEventListener("change", load);
  for (const c of [actor, text]) c.addEventListener("keydown", (e) => { if (e.key === "Enter") load(); });
  body.appendChild(el("div", { class: "notice" }, "Every sign in, permission change, token, scan, and admin action is recorded here. The trail is append-only: Daru can add records but cannot change or delete them, and they are kept for two years."));
  body.appendChild(el("div", { class: "toolbar" }, actor, text, group, outcome, range,
    el("button", { class: "btn-primary", onclick: load }, "Apply"),
    el("button", { class: "btn-ghost", onclick: exportCsv }, "Export CSV")));
  body.appendChild(out);
  load();
}

async function renderAdmin(view) {
  view.appendChild(pageHead("Administration", "Users, indexes, ingest tokens, and the audit trail"));
  const tabs = el("div", { class: "results-tabs", style: "margin-bottom:16px" });
  const body = el("div", {});
  const defs = [["users", "Users"], ["indexes", "Indexes"], ["tokens", "Ingest tokens"], ["audit", "Audit log"], ["system", "System"]];
  // A tab can be linked directly: #/admin/audit.
  const wanted = (location.hash.split("/")[2] || "").toLowerCase();
  let active = defs.some(([t]) => t === wanted) ? wanted : "users";
  function draw() {
    body.innerHTML = "";
    if (active === "users") adminUsers(body);
    else if (active === "indexes") adminIndexes(body);
    else if (active === "tokens") adminTokens(body);
    else if (active === "audit") adminAudit(body);
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
    const t = el("table", { class: "grid" }, el("tr", {}, ...["Username", "Role", "Sign-in", "Email", "Index access", "Status", "Actions"].map((h) => el("th", {}, h))));
    for (const u of r.users) {
      t.appendChild(el("tr", {},
        el("td", {}, u.username), el("td", {}, el("span", { class: "role-badge" }, u.role)),
        el("td", {}, u.auth_source || "local"),
        el("td", {}, u.email || "-"), el("td", {}, indexAccessLabel(u)), el("td", {}, u.disabled ? "disabled" : "active"),
        el("td", {}, el("div", { class: "row-actions" },
          el("button", { class: "btn-ghost btn-sm", onclick: () => changeRole(u) }, "Role"),
          u.role !== "admin" ? el("button", { class: "btn-ghost btn-sm", onclick: () => changeIndexAccess(u, body) }, "Indexes") : null,
          (u.auth_source || "local") === "local" ? el("button", { class: "btn-ghost btn-sm", onclick: () => resetPw(u) }, "Password") : null,
          u.username !== ME.username ? el("button", { class: "btn-ghost btn-sm", title: "End every session this user has, on every device", onclick: async () => {
            if (!(await confirmDialog("Sign " + u.username + " out on every device? They will need to sign in again.", "Sign out everywhere"))) return;
            try { await API.post("/api/admin/users/" + encodeURIComponent(u.username) + "/sessions/revoke", {}); toast(u.username + " was signed out everywhere"); } catch (ex) { toast(ex.message, "error"); }
          } }, "Sign out everywhere") : null,
          u.username !== ME.username ? el("button", { class: "btn-ghost btn-sm btn-danger", onclick: () => toggleDisabled(u, body) }, u.disabled ? "Enable" : "Disable") : null))));
    }
    wrap.appendChild(t);
  } catch (ex) { wrap.innerHTML = ""; wrap.appendChild(el("div", { class: "empty" }, ex.message)); }
}

// indexAccessLabel describes a user's index ACL. Admins always read every
// index, whatever is stored.
function indexAccessLabel(u) {
  if (u.role === "admin" || u.index_access === "*") return "all indexes";
  if (!u.index_access) return "none";
  return u.index_access.split(",").join(", ");
}

async function changeIndexAccess(u, body) {
  let indexes = [];
  try { indexes = (await API.get("/api/indexes")).indexes.map((ix) => ix.name); }
  catch (ex) { toast(ex.message, "error"); return; }
  const current = new Set((u.index_access || "").split(",").filter(Boolean));
  const all = u.index_access === "*";
  const fields = [{ name: "__all", label: "All indexes, including ones created later", type: "checkbox", value: all }];
  for (const name of indexes) fields.push({ name: "ix_" + name, label: name, type: "checkbox", value: all || current.has(name) });
  const v = await openModal("Index access", "Indexes " + u.username + " may search. Leave everything unticked to remove search access.", fields, "Save access");
  if (!v) return;
  const payload = v.__all ? { all: true } : { indexes: indexes.filter((name) => v["ix_" + name]) };
  API.post(`/api/admin/users/${encodeURIComponent(u.username)}/indexes`, payload)
    .then(() => { toast("Index access updated"); adminUsers((body.innerHTML = "", body)); })
    .catch((ex) => toast(ex.message, "error"));
}

async function createUserForm(body) {
  const v = await openModal("Add user", "Local accounts sign in with a password, typed into a masked field and never shown back. LDAP, OIDC, and SAML accounts have no Daru password: the identity must come from that provider, with the same username.", [
    { name: "username", label: "Username", type: "text", required: true, placeholder: "e.g. alice", autocomplete: "username" },
    { name: "auth_source", label: "Sign-in method", type: "select", value: "local",
      options: [{ value: "local", label: "Daru password" }, { value: "ldap", label: "LDAP directory" }, { value: "oidc", label: "OIDC single sign on" }, { value: "saml", label: "SAML single sign on" }] },
    { name: "password", label: "Password (Daru password accounts only)", type: "password", minlength: 8, autocomplete: "new-password",
      validate: (val) => val && val.length < 8 ? "Password must be at least 8 characters." : "" },
    { name: "role", label: "Role", type: "select", value: "user",
      options: [{ value: "user", label: "user" }, { value: "power", label: "power" }, { value: "admin", label: "admin" }] },
  ], "Create user");
  if (!v) return;
  const local = v.auth_source === "local";
  if (local && v.password.length < 8) { toast("A Daru password account needs a password of at least 8 characters.", "error"); return; }
  const payload = { username: v.username, role: v.role, auth_source: v.auth_source };
  if (local) payload.password = v.password;
  API.post("/api/admin/users", payload)
    .then(() => { toast("User created"); adminUsers((body.innerHTML = "", body)); })
    .catch((ex) => toast(ex.message, "error"));
}
async function changeRole(u) {
  const v = await openModal("Change role", "Role for " + u.username + ".", [
    { name: "role", label: "Role", type: "select", value: u.role,
      options: [{ value: "user", label: "user" }, { value: "power", label: "power" }, { value: "admin", label: "admin" }] },
  ], "Update role");
  if (!v) return;
  API.post(`/api/admin/users/${u.username}/role`, { role: v.role }).then(() => { toast("Role updated"); route(); }).catch((ex) => toast(ex.message, "error"));
}
async function resetPw(u) {
  const v = await openModal("Reset password", "New password for " + u.username + ". It is typed into a masked field and is never shown back.", [
    { name: "password", label: "New password", type: "password", required: true, minlength: 8, autocomplete: "new-password",
      validate: (val) => val.length < 8 ? "Password must be at least 8 characters." : "" },
  ], "Reset password");
  if (!v) return;
  API.post(`/api/admin/users/${u.username}/password`, { password: v.password }).then(() => toast("Password updated")).catch((ex) => toast(ex.message, "error"));
}
async function toggleDisabled(u, body) {
  const action = u.disabled ? "Enable" : "Disable";
  if (!await confirmDialog(action + " user " + u.username + "?", action)) return;
  API.post(`/api/admin/users/${u.username}/disabled`, { disabled: !u.disabled }).then(() => { toast("Updated"); adminUsers((body.innerHTML = "", body)); }).catch((ex) => toast(ex.message, "error"));
}

async function adminIndexes(body) {
  body.appendChild(el("div", { class: "toolbar" }, el("button", { class: "btn-ghost", onclick: async () => {
    const v = await openModal("Add index", "Create a new log index with a retention period.", [
      { name: "name", label: "Index name", type: "text", required: true, placeholder: "e.g. web",
        validate: (val) => /^[A-Za-z0-9_-]+$/.test(val) ? "" : "Index names may only contain letters, numbers, underscore, and hyphen." },
      { name: "days", label: "Retention days", type: "text", value: "90",
        validate: (val) => { const n = parseInt(val, 10); return Number.isInteger(n) && n > 0 ? "" : "Retention days must be a positive number."; } },
    ], "Create index");
    if (!v) return;
    API.post("/api/admin/indexes", { name: v.name, retention_days: parseInt(v.days, 10) }).then(() => { toast("Index created"); adminIndexes((body.innerHTML = "", body)); }).catch((ex) => toast(ex.message, "error"));
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
      el("td", {}, !tok.disabled ? el("button", { class: "btn-ghost btn-sm btn-danger", onclick: async () => { if (await confirmDialog("Disable ingest token \"" + tok.name + "\"? Forwarders using it will stop ingesting.", "Disable")) { await API.post(`/api/admin/tokens/${encodeURIComponent(tok.name)}/disable`, {}); adminTokens((body.innerHTML = "", body)); } } }, "Disable") : null)));
    wrap.appendChild(t);
  } catch (ex) { wrap.innerHTML = ""; wrap.appendChild(el("div", { class: "empty" }, ex.message)); }
}

async function createToken(body) {
  const v = await openModal("Create ingest token", "The token is shown once after creation. Copy it then; it will not be shown again.", [
    { name: "name", label: "Token name", type: "text", required: true, placeholder: "e.g. web-servers" },
    { name: "index", label: "Default index", type: "text", value: "main",
      validate: (val) => /^[A-Za-z0-9_-]+$/.test(val) ? "" : "Index names may only contain letters, numbers, underscore, and hyphen." },
  ], "Create token");
  if (!v) return;
  API.post("/api/admin/tokens", { name: v.name, default_index: v.index }).then((r) => {
    const box = el("div", { class: "token-reveal" }, "Copy this token now, it will not be shown again:\n\n" + r.token);
    body.insertBefore(el("div", { class: "notice", style: "border-left-color:var(--amber)" }, box), body.children[2]);
    adminTokens((body.innerHTML = body.innerHTML, body));
  }).catch((ex) => toast(ex.message, "error"));
}

boot();
