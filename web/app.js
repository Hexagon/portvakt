// portvakt web UI. Plain ES module, no build step.
//
// Security rules for this file (see docs/SECURITY.md):
//  - Never use innerHTML/outerHTML/insertAdjacentHTML with data. Build DOM with h().
//  - No inline event handler strings, no eval/new Function (CSP forbids them anyway).
//  - Every non-GET request goes through api(), which adds the CSRF header.

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------

function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style") Object.assign(el.style, v);
    else if (k.startsWith("on")) el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k in el && k !== "list") el[k] = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  append(el, children);
  return el;
}
function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const clear = (el) => { el.replaceChildren(); return el; };
const fill = (el, ...children) => append(clear(el), children);

const ICONS = {
  app: "M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z",
  globe: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c2.5 2.7 3.5 5.7 3.5 9s-1 6.3-3.5 9c-2.5-2.7-3.5-5.7-3.5-9s1-6.3 3.5-9z",
  database: "M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zM4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3",
  server: "M3 4h18v6H3zM3 14h18v6H3zM7 7h.01M7 17h.01",
  box: "M12 3l8 4.5v9L12 21l-8-4.5v-9zM12 12l8-4.5M12 12v9M12 12L4 7.5",
  lock: "M6 11h12v10H6zM8 11V7a4 4 0 0 1 8 0v4",
  terminal: "M4 5h16v14H4zM7 9l3 3-3 3M12 15h5",
  pulse: "M3 12h4l3-8 4 16 3-8h4",
  graph: "M4 20V4M4 20h16M7 16l4-5 3 3 5-7",
  shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
  cog: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 0 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 0 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 0 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 0 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z",
  file: "M6 3h8l4 4v14H6zM14 3v4h4",
  log: "M5 4h14v16H5zM8 8h8M8 12h8M8 16h5",
  table: "M3 5h18v14H3zM3 10h18M3 15h18M9 5v14",
  refresh: "M20 12a8 8 0 1 1-2.3-5.7M20 4v5h-5",
  play: "M7 4l12 8-12 8z",
  stop: "M6 6h12v12H6z",
  close: "M6 6l12 12M18 6L6 18",
  chevron: "M6 9l6 6 6-6",
  search: "M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zM21 21l-5-5",
  account: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21c0-4 3.6-6 8-6s8 2 8 6",
  logout: "M15 4h4v16h-4M10 8l-4 4 4 4M6 12h10",
  layout: "M3 4h18v16H3zM3 15h18",
  sidebar: "M3 4h18v16H3zM9 4v16",
  maximize: "M8 4H4v4M16 4h4v4M8 20H4v-4M16 20h4v-4",
  trash: "M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3",
  plus: "M12 5v14M5 12h14",
  bolt: "M13 3L5 14h6l-1 7 8-11h-6z",
  save: "M5 4h11l3 3v13H5zM8 4v5h7V4M8 20v-6h8v6",
  sun: "M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4",
};
function icon(name, cls = "") {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", "i " + cls);
  const p = document.createElementNS(ns, "path");
  p.setAttribute("d", ICONS[name] || ICONS.app);
  svg.append(p);
  return svg;
}

const fmt = {
  bytes(n) {
    n = Number(n) || 0;
    const u = ["B", "KiB", "MiB", "GiB", "TiB"];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(1) : n) + " " + u[i];
  },
  rate(n) { return fmt.bytes(n) + "/s"; },
  time(t) { return new Date(t * 1000).toLocaleTimeString(); },
  datetime(t) { return new Date(t * 1000).toLocaleString(); },
};

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

const state = {
  session: null,
  apps: [],
  tabs: [],
  active: null,
  panelTab: "output",
  panelOpen: false,
  sideOpen: true,
  showUndetected: false,
  filter: "",
  collapsed: new Set(),
};

class ApiError extends Error {
  constructor(status, body) { super(body?.error || `HTTP ${status}`); this.status = status; this.body = body; }
}

async function api(method, path, body) {
  const opts = { method, credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    opts.headers["content-type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  if (method !== "GET" && state.session) opts.headers["x-portvakt-csrf"] = state.session.csrf;
  const res = await fetch("/api" + path, opts);
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (res.status === 401 && path !== "/login" && path !== "/session") {
    state.session = null;
    renderLogin("Your session expired. Please sign in again.");
    throw new ApiError(401, data);
  }
  if (!res.ok) throw new ApiError(res.status, data);
  return data;
}

// ---------------------------------------------------------------------------
// Toasts, dialogs
// ---------------------------------------------------------------------------

let toastBox;
function toast(msg, kind = "") {
  if (!toastBox) toastBox = document.body.appendChild(h("div", { class: "toasts" }));
  const t = h("div", { class: "toast " + kind, role: "status" }, msg);
  toastBox.append(t);
  setTimeout(() => t.remove(), kind === "err" ? 8000 : 4000);
}

function dialog({ title, body, ok = "OK", danger = false, cancel = "Cancel", fields = [] }) {
  return new Promise((resolve) => {
    const inputs = fields.map((f) => h("input", { class: "txt", value: f.value || "", placeholder: f.placeholder || "", "aria-label": f.label }));
    const close = (v) => { bg.remove(); resolve(v); };
    const okBtn = h("button", { class: "btn" + (danger ? " danger" : ""), type: "submit" }, ok);
    const form = h("form", { class: "modal", onsubmit: (e) => { e.preventDefault(); close(fields.length ? inputs.map((i) => i.value) : true); } },
      h("h3", {}, title),
      body ? h("div", {}, body) : null,
      fields.map((f, i) => h("label", { class: "field" }, f.label, inputs[i])),
      h("div", { class: "btns" }, cancel ? h("button", { class: "btn secondary", type: "button", onclick: () => close(null) }, cancel) : null, okBtn));
    const bg = h("div", { class: "modal-bg", onmousedown: (e) => { if (e.target === bg) close(null); } }, form);
    bg.addEventListener("keydown", (e) => { if (e.key === "Escape") close(null); });
    document.body.append(bg);
    (inputs[0] || okBtn).focus();
  });
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

const root = document.getElementById("app");

function renderLogin(message = "") {
  disposeAll();
  const err = h("div", { class: "error", role: "alert" }, message);
  const user = h("input", { class: "txt", name: "username", autocomplete: "username", required: true });
  const pass = h("input", { class: "txt", name: "password", type: "password", autocomplete: "current-password", required: true });
  const code = h("input", { class: "txt", name: "totp", inputMode: "numeric", autocomplete: "one-time-code", pattern: "[0-9]{6}", maxLength: 6 });
  const codeField = h("label", { class: "field hidden" }, "Authenticator code", code);
  const btn = h("button", { class: "btn", type: "submit", style: { justifyContent: "center" } }, "Sign in");
  const form = h("form", {
    onsubmit: async (e) => {
      e.preventDefault();
      btn.disabled = true;
      err.textContent = "";
      try {
        state.session = await api("POST", "/login", { username: user.value, password: pass.value, totp: code.value || null });
        pass.value = "";
        await startWorkbench();
      } catch (ex) {
        if (ex.body?.totp_required) {
          codeField.classList.remove("hidden");
          code.focus();
        } else {
          err.textContent = ex.message;
        }
      } finally {
        btn.disabled = false;
      }
    },
  },
    h("h1", {}, h("img", { src: "icon.svg", alt: "" }), "portvakt"),
    h("p", {}, "Sign in to manage this server."),
    h("label", { class: "field" }, "Username", user),
    h("label", { class: "field" }, "Password", pass),
    codeField, err, btn);
  fill(root, h("div", { class: "login" }, form));
  user.focus();
}

// ---------------------------------------------------------------------------
// Workbench
// ---------------------------------------------------------------------------

const ui = {};

async function startWorkbench() {
  try {
    state.apps = await api("GET", "/apps");
  } catch (e) {
    if (e.status === 401) return;
    toast(e.message, "err");
  }
  buildWorkbench();
  restoreLayout();
  renderSidebar();
  renderTabs();
  renderPanel();
  renderStatus();
  if (!state.tabs.length) openApp("system", true);
}

function buildWorkbench() {
  ui.activity = h("nav", { class: "activity", "aria-label": "Activity bar" });
  ui.side = h("aside", { class: "sidebar" });
  ui.tabs = h("div", { class: "tabs", role: "tablist" });
  ui.body = h("div", { class: "tab-body" });
  ui.editor = h("section", { class: "editor-group" }, ui.tabs, ui.body);
  ui.ptabs = h("div", { class: "ptabs" });
  ui.pbody = h("div", { class: "pbody" });
  ui.panel = h("section", { class: "panel" }, ui.ptabs, ui.pbody);
  ui.resizer = h("div", { class: "resizer", title: "Drag to resize" });
  ui.center = h("div", { class: "center" }, ui.editor, h("div", {}, ui.resizer, ui.panel));
  ui.main = h("div", { class: "main" }, ui.activity, ui.side, ui.center);
  ui.status = h("footer", { class: "statusbar" });
  const title = h("header", { class: "titlebar" },
    h("div", { class: "brand" }, h("img", { src: "icon.svg", alt: "" }), h("span", {}, "portvakt")),
    h("div", { class: "search", role: "button", tabIndex: 0, onclick: () => quickOpen(""), onkeydown: (e) => { if (e.key === "Enter") quickOpen(""); } },
      icon("search"), state.session.hostname || "Search"),
    h("div", { class: "right" },
      h("button", { class: "icon-btn", title: "Toggle sidebar (Ctrl+B)", onclick: toggleSide }, icon("sidebar")),
      h("button", { class: "icon-btn", title: "Toggle panel (Ctrl+`)", onclick: () => togglePanel() }, icon("layout")),
      h("button", { class: "icon-btn", title: "Toggle theme", onclick: toggleTheme }, icon("sun"))));
  fill(root, h("div", { class: "wb" }, title, ui.main, ui.status));
  setupResizer();
  renderActivity();
}

function renderActivity() {
  const items = [
    h("button", { class: "active", title: "Applications (Ctrl+Shift+E)", onclick: toggleSide }, icon("app")),
    h("button", { title: "Command palette (Ctrl+Shift+P)", onclick: () => quickOpen(">") }, icon("search")),
  ];
  for (const app of state.apps) {
    for (const v of app.views || []) {
      if (!v.activity) continue;
      items.push(h("button", { title: `${app.name}: ${v.label}`, onclick: () => openView(app.id, v.id) }, icon(app.icon)));
    }
  }
  if (state.session.terminal) items.push(h("button", { title: "Terminal (Ctrl+`)", onclick: () => togglePanel("terminal", true) }, icon("terminal")));
  items.push(h("div", { class: "spacer" }));
  if (state.session.role === "admin") items.push(h("button", { title: "Audit log", onclick: () => togglePanel("audit", true) }, icon("shield")));
  items.push(h("button", { title: `Signed in as ${state.session.user} — sign out`, onclick: logout }, icon("account")));
  fill(ui.activity, ...items);
}

function restoreLayout() {
  try {
    const l = JSON.parse(localStorage.getItem("portvakt.layout") || "{}");
    if (l.panelH) document.documentElement.style.setProperty("--panel-h", l.panelH + "px");
    if (l.side === false) toggleSide();
    if (l.collapsed) state.collapsed = new Set(l.collapsed);
    state.showUndetected = !!l.showUndetected;
  } catch { /* storage unavailable */ }
  if (!state.panelOpen) ui.panel.parentElement.classList.add("hidden");
}
function saveLayout(patch) {
  try {
    const l = JSON.parse(localStorage.getItem("portvakt.layout") || "{}");
    localStorage.setItem("portvakt.layout", JSON.stringify({ ...l, ...patch }));
  } catch { /* storage unavailable */ }
}

function toggleSide() {
  state.sideOpen = !state.sideOpen;
  ui.main.classList.toggle("no-side", !state.sideOpen);
  ui.activity.firstChild?.classList.toggle("active", state.sideOpen);
  saveLayout({ side: state.sideOpen });
}

function toggleTheme() {
  const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  const next = cur === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("portvakt.theme", next); } catch { /* ignore */ }
  terminal.applyTheme();
}

function setupResizer() {
  ui.resizer.addEventListener("pointerdown", (e) => {
    const startY = e.clientY, startH = ui.panel.getBoundingClientRect().height;
    ui.resizer.classList.add("drag");
    ui.resizer.setPointerCapture(e.pointerId);
    const move = (ev) => {
      const nh = Math.max(120, Math.min(window.innerHeight - 160, startH + startY - ev.clientY));
      document.documentElement.style.setProperty("--panel-h", nh + "px");
      terminal.fit();
    };
    const up = () => {
      ui.resizer.classList.remove("drag");
      ui.resizer.removeEventListener("pointermove", move);
      saveLayout({ panelH: Math.round(ui.panel.getBoundingClientRect().height) });
    };
    ui.resizer.addEventListener("pointermove", move);
    ui.resizer.addEventListener("pointerup", up, { once: true });
  });
}

async function logout() {
  if (!(await dialog({ title: "Sign out?", ok: "Sign out" }))) return;
  try { await api("POST", "/logout"); } catch { /* ignore */ }
  state.session = null;
  state.tabs = [];
  renderLogin();
}

async function refreshApps() {
  state.apps = await api("GET", "/apps");
  renderSidebar();
  renderActivity();
  renderStatus();
}

// ---------------------------------------------------------------------------
// Sidebar: detected applications grouped by category
// ---------------------------------------------------------------------------

function renderSidebar() {
  const filter = h("input", {
    class: "txt", placeholder: "Filter applications", value: state.filter, "aria-label": "Filter applications",
    oninput: (e) => { state.filter = e.target.value.toLowerCase(); renderTree(); },
  });
  ui.tree = h("div", { class: "tree", role: "tree" });
  fill(ui.side, 
    h("div", { class: "head" }, h("span", {}, "Applications"),
      h("div", { class: "tools" },
        state.session.role === "admin" ? h("button", { class: "icon-btn", title: "Rescan for installed applications", onclick: rescan }, icon("refresh")) : null,
        h("button", { class: "icon-btn", title: state.showUndetected ? "Hide not detected" : "Show not detected", onclick: () => { state.showUndetected = !state.showUndetected; saveLayout({ showUndetected: state.showUndetected }); renderSidebar(); } }, icon(state.showUndetected ? "close" : "plus")))),
    h("div", { class: "filter" }, filter),
    ui.tree);
  renderTree();
}

function renderTree() {
  const match = (a) => !state.filter || a.name.toLowerCase().includes(state.filter) || a.id.includes(state.filter);
  const groups = new Map();
  for (const a of state.apps.filter((a) => a.detected && match(a))) {
    if (!groups.has(a.category)) groups.set(a.category, []);
    groups.get(a.category).push(a);
  }
  const sections = [...groups.entries()].sort(([a], [b]) => (a === "System" ? -1 : b === "System" ? 1 : a.localeCompare(b)));
  if (state.showUndetected) {
    const nd = state.apps.filter((a) => !a.detected && match(a));
    if (nd.length) sections.push(["Not detected", nd]);
  }
  const activeApp = state.tabs.find((t) => t.id === state.active)?.app;
  fill(ui.tree, sections.map(([cat, apps]) => {
    const collapsed = state.collapsed.has(cat);
    return [
      h("div", { class: "section-h" + (collapsed ? " collapsed" : ""), role: "treeitem", "aria-expanded": String(!collapsed), onclick: () => {
        collapsed ? state.collapsed.delete(cat) : state.collapsed.add(cat);
        saveLayout({ collapsed: [...state.collapsed] });
        renderTree();
      } }, icon("chevron"), cat, h("span", { class: "count" }, apps.length)),
      collapsed ? null : apps.map((a) => h("div", {
        class: "row" + (a.detected ? "" : " undetected") + (activeApp === a.id ? " selected" : ""),
        role: "treeitem", tabIndex: 0, title: a.description,
        onclick: () => openApp(a.id), onkeydown: (e) => { if (e.key === "Enter") openApp(a.id); },
      }, icon(a.icon), h("span", { class: "name" }, a.name), a.version ? h("span", { class: "ver" }, a.version) : null,
        a.state ? h("span", { class: "dot " + a.state, title: a.state }) : null)),
    ];
  }));
  if (!sections.length) ui.tree.append(h("div", { class: "row muted" }, "No applications match."));
}

async function rescan() {
  toast("Scanning for installed applications…");
  try {
    await api("POST", "/rescan");
    await refreshApps();
    toast(`Found ${state.apps.filter((a) => a.detected).length} applications.`, "ok");
  } catch (e) { toast(e.message, "err"); }
}

// ---------------------------------------------------------------------------
// Editor tabs
// ---------------------------------------------------------------------------
// A tab: { id, title, icon, app, dirty, mount(el), unmount(), close?() }

function openTab(tab) {
  const existing = state.tabs.find((t) => t.id === tab.id);
  if (!existing) {
    const i = state.tabs.findIndex((t) => t.id === state.active);
    state.tabs.splice(i + 1, 0, tab);
  }
  activate(tab.id);
}

function activate(id) {
  const prev = state.tabs.find((t) => t.id === state.active);
  if (prev && prev.id !== id) prev.unmount?.();
  state.active = id;
  const tab = state.tabs.find((t) => t.id === id);
  clear(ui.body);
  if (tab) tab.mount(ui.body);
  else ui.body.append(welcome());
  renderTabs();
  renderTree?.();
}

async function closeTab(id) {
  const tab = state.tabs.find((t) => t.id === id);
  if (!tab) return;
  if (tab.dirty && !(await dialog({ title: "Discard unsaved changes?", body: tab.title, ok: "Discard", danger: true }))) return;
  tab.unmount?.();
  tab.dispose?.();
  const i = state.tabs.indexOf(tab);
  state.tabs.splice(i, 1);
  if (state.active === id) {
    state.active = null;
    activate(state.tabs[Math.min(i, state.tabs.length - 1)]?.id);
  } else renderTabs();
}

function renderTabs() {
  fill(ui.tabs, state.tabs.map((t) => h("div", {
    class: "tab" + (t.id === state.active ? " active" : "") + (t.dirty ? " dirty" : ""),
    role: "tab", title: t.tooltip || t.title, "aria-selected": String(t.id === state.active),
    onclick: () => activate(t.id),
    onauxclick: (e) => { if (e.button === 1) closeTab(t.id); },
  }, icon(t.icon), h("span", { class: "t" }, t.title),
    h("span", { class: "close", title: "Close", onclick: (e) => { e.stopPropagation(); closeTab(t.id); } }, icon("close")))));
}

function disposeAll() {
  for (const t of state.tabs) { t.unmount?.(); t.dispose?.(); }
  state.tabs = [];
  state.active = null;
  terminal.dispose();
}

function welcome() {
  return h("div", { class: "welcome" }, h("div", {},
    h("img", { src: "icon.svg", alt: "" }),
    h("div", { class: "keys" },
      "Show all commands", h("span", {}, h("kbd", {}, "Ctrl"), "+", h("kbd", {}, "Shift"), "+", h("kbd", {}, "P")),
      "Go to application or file", h("span", {}, h("kbd", {}, "Ctrl"), "+", h("kbd", {}, "P")),
      "Toggle terminal", h("span", {}, h("kbd", {}, "Ctrl"), "+", h("kbd", {}, "`")),
      "Toggle sidebar", h("span", {}, h("kbd", {}, "Ctrl"), "+", h("kbd", {}, "B")))));
}

// ---------------------------------------------------------------------------
// App overview tab
// ---------------------------------------------------------------------------

function openApp(id, quiet = false) {
  const app = state.apps.find((a) => a.id === id);
  if (!app) { if (!quiet) toast("Unknown application " + id, "err"); return; }
  openTab({
    id: "app:" + id, title: app.name, icon: app.icon, app: id,
    mount(el) {
      this.el = h("div", { class: "page" }, h("div", { class: "muted" }, "Loading…"));
      el.append(this.el);
      loadApp(id, this.el);
    },
  });
}

async function loadApp(id, el) {
  let d;
  try { d = await api("GET", "/apps/" + encodeURIComponent(id)); } catch (e) { fill(el, h("div", { class: "notice" }, e.message)); return; }
  const admin = state.session.role === "admin";
  const svc = d.service;
  const head = h("div", { class: "page-h" },
    h("div", { class: "big" }, icon(d.icon)),
    h("div", {},
      h("h1", {}, d.name),
      h("div", { class: "meta" },
        d.version ? h("span", {}, "v" + d.version) : null,
        svc ? h("span", { class: "pill" }, h("span", { class: "dot " + svc.active }), `${svc.active} (${svc.sub})`) : null,
        svc ? h("span", { class: "pill" }, svc.enabled || "unknown") : null,
        h("span", {}, d.category),
        d.description ? h("span", {}, d.description) : null)));
  const parts = [head];
  if (!d.detected) parts.push(h("div", { class: "notice" }, "This application was not detected on this host. Install it and press Rescan."));
  if (!admin) parts.push(h("div", { class: "notice" }, "You have read-only access."));

  if (d.views.length) {
    parts.push(h("h2", {}, "Views"), h("div", { class: "btn-row" }, d.views.map((v) =>
      h("button", { class: "btn secondary", onclick: () => v.location === "panel" ? togglePanel(v.type === "terminal" ? "terminal" : `view:${id}:${v.id}`, true) : openView(id, v.id) },
        icon(v.type === "metrics" ? "graph" : v.type === "terminal" ? "terminal" : "table"), v.label))));
  }

  if (d.info.length) {
    parts.push(h("h2", {}, "Overview"), h("div", { class: "kv" }, d.info.map(([k, v]) => [h("div", { class: "k" }, k), h("div", { class: "v" }, v)])));
  }

  const actions = d.actions.filter((a) => a.params.length === 0);
  const paramActions = d.actions.filter((a) => a.params.length > 0);
  if (d.actions.length) {
    parts.push(h("h2", {}, "Actions"));
    parts.push(h("div", { class: "btn-row" }, actions.map((a) => h("button", {
      class: "btn " + (a.confirm ? "secondary" : "secondary"), disabled: !admin || !d.detected || !a.available,
      title: (a.description || a.label) + (a.available ? "" : " (program not installed)"),
      onclick: () => runAction(id, a, {}).then(() => loadApp(id, el)),
    }, icon(actionIcon(a.id)), a.label))));
    if (paramActions.length) {
      parts.push(h("div", { class: "list", style: { marginTop: "8px" } }, paramActions.map((a) => {
        const inputs = a.params.map((p) => h("input", { class: "txt", placeholder: p.label, value: p.default || "", title: `${p.label} — must match ${p.pattern}` }));
        return h("div", { class: "item" },
          h("div", { class: "grow" }, a.label, a.description ? h("div", { class: "sub" }, a.description) : null),
          h("div", { class: "params" }, inputs,
            h("button", { class: "btn small", disabled: !admin || !d.detected || !a.available, onclick: () => {
              const vals = Object.fromEntries(a.params.map((p, i) => [p.name, inputs[i].value]));
              runAction(id, a, vals);
            } }, "Run")));
      })));
    }
  }

  if (d.files.length) {
    parts.push(h("h2", {}, "Configuration files"), h("div", { class: "list" }, d.files.map((f) =>
      h("div", { class: "item link", onclick: () => openFile(id, f.path) }, icon("file"),
        h("div", { class: "grow mono" }, f.path),
        h("span", { class: "sub" }, f.readonly ? "read-only" : f.validated ? "validated on save" : "")))));
  }
  if (d.logs.length) {
    parts.push(h("h2", {}, "Logs"), h("div", { class: "list" }, d.logs.map((l) =>
      h("div", { class: "item link", onclick: () => openLog(id, l) }, icon("log"),
        h("div", { class: "grow" }, l.label), h("span", { class: "sub mono" }, l.source)))));
  }
  parts.push(h("h2", {}, "Plugin"), h("div", { class: "kv" },
    h("div", { class: "k" }, "Id"), h("div", { class: "v" }, d.id),
    h("div", { class: "k" }, "Source"), h("div", { class: "v" }, d.source),
    h("div", { class: "k" }, "Detected by"), h("div", { class: "v" }, d.evidence.join("\n") || "—")));
  fill(el, ...parts);
}

function actionIcon(id) {
  return { start: "play", stop: "stop", restart: "refresh", reload: "refresh", enable: "plus", disable: "close" }[id] || "bolt";
}

async function runAction(appId, a, params) {
  if (a.confirm && !(await dialog({ title: `${a.label}?`, body: a.description || `Run "${a.label}" on ${appId}.`, ok: a.label, danger: true }))) return;
  output.begin(`${appId}: ${a.label}`);
  try {
    const out = await api("POST", `/apps/${encodeURIComponent(appId)}/actions/${encodeURIComponent(a.id)}`, { params });
    output.result(out);
    toast(`${a.label}: ${out.code === 0 ? "done" : "failed (exit " + out.code + ")"}`, out.code === 0 ? "ok" : "err");
    refreshApps().catch(() => {});
  } catch (e) {
    output.error(e.message);
    toast(e.message, "err");
  }
}

// ---------------------------------------------------------------------------
// File editor tab
// ---------------------------------------------------------------------------

function openFile(appId, path) {
  const name = path.split("/").pop();
  const tab = {
    id: `file:${appId}:${path}`, title: name, tooltip: path, icon: "file", app: appId, dirty: false,
    file: null,
    mount(el) {
      this.root = h("div", { class: "editor" }, h("div", { class: "muted", style: { padding: "12px" } }, "Loading…"));
      el.append(this.root);
      if (this.file) this.render(); else this.load();
    },
    unmount() { if (this.ta) this.file.draft = this.ta.value; },
    async load() {
      try {
        this.file = await api("GET", `/apps/${encodeURIComponent(appId)}/file?path=${encodeURIComponent(path)}`);
        this.file.draft = this.file.content;
        this.dirty = false;
        renderTabs();
        this.render();
      } catch (e) { fill(this.root, h("div", { class: "notice" }, e.message)); }
    },
    render() {
      const f = this.file;
      const gutter = h("div", { class: "gutter", "aria-hidden": "true" });
      const ta = h("textarea", { spellcheck: false, readOnly: f.readonly, value: f.draft, "aria-label": path, wrap: "off" });
      this.ta = ta;
      const sync = () => {
        const n = ta.value.split("\n").length;
        gutter.textContent = Array.from({ length: n }, (_, i) => i + 1).join("\n");
        ta.style.height = "auto";
        ta.style.height = ta.scrollHeight + "px";
        ta.style.width = "auto";
        ta.style.width = Math.max(ta.scrollWidth, ta.parentElement?.clientWidth - gutter.offsetWidth || 0) + "px";
        const dirty = ta.value !== f.content;
        if (dirty !== this.dirty) { this.dirty = dirty; renderTabs(); }
      };
      ta.addEventListener("input", sync);
      ta.addEventListener("keydown", (e) => {
        if (e.key === "Tab" && !f.readonly) {
          e.preventDefault();
          ta.setRangeText("    ", ta.selectionStart, ta.selectionEnd, "end");
          sync();
        }
      });
      const saveBtn = h("button", { class: "btn small", disabled: f.readonly, onclick: () => this.save() }, icon("save"), "Save");
      fill(this.root, 
        h("div", { class: "bar" }, h("span", { class: "path" }, path),
          f.language ? h("span", { class: "pill" }, f.language) : null,
          f.readonly ? h("span", { class: "pill" }, "read-only") : null,
          h("button", { class: "btn small secondary", onclick: () => this.reload() }, icon("refresh"), "Reload"),
          saveBtn),
        h("div", { class: "code" }, gutter, ta));
      requestAnimationFrame(sync);
    },
    async reload() {
      if (this.dirty && !(await dialog({ title: "Discard unsaved changes and reload from disk?", ok: "Reload", danger: true }))) return;
      this.file = null;
      this.load();
    },
    async save() {
      const f = this.file;
      if (!f || f.readonly) return;
      const content = this.ta.value;
      output.begin(`save ${path}`);
      try {
        const r = await api("PUT", `/apps/${encodeURIComponent(appId)}/file`, { path, content, sha256: f.sha256 });
        f.content = content; f.draft = content; f.sha256 = r.sha256;
        this.dirty = false;
        renderTabs();
        if (r.validation) output.result(r.validation);
        if (r.after_save) output.result(r.after_save);
        output.note(`saved; backup: ${r.backup}`);
        toast(`Saved ${name}` + (r.validation ? " (validated)" : "") + (r.after_save ? " and applied" : ""), "ok");
      } catch (e) {
        if (e.body?.validation) {
          output.result(e.body.validation);
          togglePanel("output", true);
        } else output.error(e.message);
        toast(e.message, "err");
      }
    },
  };
  openTab(state.tabs.find((t) => t.id === tab.id) || tab);
}

// ---------------------------------------------------------------------------
// Log tab
// ---------------------------------------------------------------------------

function openLog(appId, log) {
  openTab(state.tabs.find((t) => t.id === `log:${appId}:${log.index}`) || {
    id: `log:${appId}:${log.index}`, title: log.label, tooltip: log.source, icon: "log", app: appId,
    mount(el) {
      this.pre = h("pre", { class: "log" }, "Loading…");
      el.append(h("div", { class: "editor" },
        h("div", { class: "bar" }, h("span", { class: "path" }, log.source),
          h("button", { class: "btn small secondary", onclick: () => this.load() }, icon("refresh"), "Refresh")),
        h("div", { style: { overflow: "auto" } }, this.pre)));
      this.load();
    },
    async load() {
      try {
        const r = await api("GET", `/apps/${encodeURIComponent(appId)}/logs/${log.index}`);
        this.pre.textContent = r.text || "(empty)";
        this.pre.parentElement.scrollTop = this.pre.parentElement.scrollHeight;
      } catch (e) { this.pre.textContent = e.message; }
    },
  });
}

// ---------------------------------------------------------------------------
// Plugin views: table / metrics (editor) and terminal (panel)
// ---------------------------------------------------------------------------

function findView(appId, viewId) {
  const app = state.apps.find((a) => a.id === appId);
  return [app, app?.views?.find((v) => v.id === viewId)];
}

function openView(appId, viewId) {
  const [app, view] = findView(appId, viewId);
  if (!view) { toast("View not available", "err"); return; }
  if (view.location === "panel") { togglePanel(view.type === "terminal" ? "terminal" : `view:${appId}:${viewId}`, true); return; }
  const id = `view:${appId}:${viewId}`;
  openTab(state.tabs.find((t) => t.id === id) || {
    id, title: view.label, icon: app.icon, app: appId,
    mount(el) {
      this.ctl = view.type === "metrics" ? metricsView(el, appId, view) : tableView(el, appId, view);
    },
    unmount() { this.ctl?.stop(); },
  });
}

function poller(fn, seconds) {
  let timer = null, stopped = false;
  const tick = async () => {
    if (stopped) return;
    if (!document.hidden) await fn().catch(() => {});
    if (!stopped && seconds > 0) timer = setTimeout(tick, seconds * 1000);
  };
  tick();
  return { stop() { stopped = true; clearTimeout(timer); }, now: () => fn() };
}

function cell(col, value) {
  if (value == null) return "";
  switch (col.format) {
    case "bytes": return fmt.bytes(value);
    case "percent": return Number(value).toFixed(1);
    default: return typeof value === "object" ? JSON.stringify(value) : String(value);
  }
}

function tableView(el, appId, view) {
  let rows = [], sort = { key: null, dir: -1 }, filter = "", selected = null;
  const isNum = (c) => ["number", "bytes", "percent"].includes(c.format);
  const count = h("span", { class: "muted" });
  const search = h("input", { class: "txt", placeholder: "Filter", "aria-label": "Filter rows", oninput: (e) => { filter = e.target.value.toLowerCase(); draw(); } });
  const live = h("span", { class: "muted" }, view.refresh ? `auto-refresh ${view.refresh}s` : "");
  const tbody = h("tbody");
  const thead = h("thead");
  const wrap = h("div", { class: "wrap" }, h("table", { class: "grid" }, thead, tbody));
  el.append(h("div", { class: "tv" },
    h("div", { class: "bar" }, search, count, h("span", { style: { flex: 1 } }), live,
      h("button", { class: "btn small secondary", onclick: () => p.now() }, icon("refresh"), "Refresh")),
    wrap));
  const cols = view.columns.length ? view.columns : null;

  function drawHead(columns) {
    fill(thead, h("tr", {}, columns.map((c) => h("th", {
      class: (isNum(c) ? "num " : "") + (sort.key === c.key ? "sorted" : ""),
      onclick: () => { sort = { key: c.key, dir: sort.key === c.key ? -sort.dir : isNum(c) ? -1 : 1 }; draw(); },
    }, c.label, sort.key === c.key ? (sort.dir > 0 ? " ▲" : " ▼") : "")), view.row_actions.length ? h("th", {}) : null));
  }

  function draw() {
    const columns = cols || Object.keys(rows[0] || {}).map((k) => ({ key: k, label: k }));
    drawHead(columns);
    let list = rows;
    if (filter) list = list.filter((r) => columns.some((c) => String(r[c.key] ?? "").toLowerCase().includes(filter)));
    if (sort.key) {
      const k = sort.key;
      list = [...list].sort((a, b) => {
        const x = a[k], y = b[k];
        return (typeof x === "number" && typeof y === "number" ? x - y : String(x ?? "").localeCompare(String(y ?? ""), undefined, { numeric: true })) * sort.dir;
      });
    }
    count.textContent = `${list.length} of ${rows.length}`;
    const key = view.key;
    fill(tbody, list.slice(0, 1000).map((r) => h("tr", {
      class: key && selected === r[key] ? "sel" : "", onclick: () => { selected = key ? r[key] : null; draw(); },
    }, columns.map((c) => h("td", { class: isNum(c) ? "num" : "", title: String(r[c.key] ?? "") }, cell(c, r[c.key]))),
      view.row_actions.length ? h("td", { class: "acts" }, view.row_actions.map((ra) =>
        h("button", { class: "btn small " + (ra.danger ? "danger" : "secondary"), onclick: (e) => { e.stopPropagation(); rowAction(appId, view, ra, r).then(() => p.now()); } }, ra.label))) : null)));
  }

  const p = poller(async () => {
    try {
      const d = await api("GET", `/apps/${encodeURIComponent(appId)}/views/${encodeURIComponent(view.id)}`);
      rows = d.rows || [];
      draw();
    } catch (e) { count.textContent = e.message; }
  }, view.refresh);
  return p;
}

async function rowAction(appId, view, ra, row) {
  const keyVal = view.key ? row[view.key] : "";
  const what = row.name || row.Names || row.command || keyVal;
  if (ra.confirm && !(await dialog({ title: `${ra.label}?`, body: `${view.label}: ${what} (${view.key}=${keyVal})`, ok: ra.label, danger: ra.danger }))) return;
  try {
    const r = await api("POST", `/apps/${encodeURIComponent(appId)}/views/${encodeURIComponent(view.id)}/actions/${encodeURIComponent(ra.action)}`, { row });
    toast(r.message || "Done", "ok");
    output.note(`${appId}/${view.id}: ${ra.label} ${keyVal}: ${r.message}`);
  } catch (e) { toast(e.message, "err"); }
}

function metricsView(el, appId, view) {
  const grid = h("div", { class: "metrics" });
  el.append(grid);
  const charts = new Map();
  const css = () => getComputedStyle(document.documentElement);
  const fmtVal = (s, v) => (s.unit === "B/s" ? fmt.rate(v) : s.unit === "%" ? v.toFixed(1) + " %" : v.toFixed(2));
  function draw(c, s) {
    const cv = c.canvas, dpr = window.devicePixelRatio || 1;
    const w = cv.clientWidth, hgt = cv.clientHeight;
    if (!w) return;
    cv.width = w * dpr; cv.height = hgt * dpr;
    const g = cv.getContext("2d");
    g.scale(dpr, dpr);
    const pts = s.points;
    const accent = css().getPropertyValue("--accent").trim() || "#0078d4";
    const grid = css().getPropertyValue("--border").trim() || "#333";
    g.strokeStyle = grid; g.lineWidth = 1;
    for (let i = 1; i < 4; i++) { const y = Math.round((hgt * i) / 4) + 0.5; g.beginPath(); g.moveTo(0, y); g.lineTo(w, y); g.stroke(); }
    if (pts.length < 2) return;
    const max = s.max ?? Math.max(1e-9, ...pts.map((p) => p[1])) * 1.15;
    const t1 = pts[pts.length - 1][0], t0 = t1 - 600;
    const X = (t) => ((t - t0) / 600) * w, Y = (v) => hgt - (v / max) * (hgt - 4) - 1;
    g.beginPath();
    pts.forEach(([t, v], i) => (i ? g.lineTo(X(t), Y(v)) : g.moveTo(X(t), Y(v))));
    g.strokeStyle = accent; g.lineWidth = 1.5; g.stroke();
    g.lineTo(X(t1), hgt); g.lineTo(X(pts[0][0]), hgt); g.closePath();
    g.globalAlpha = 0.15; g.fillStyle = accent; g.fill(); g.globalAlpha = 1;
  }
  const p = poller(async () => {
    const d = await api("GET", `/apps/${encodeURIComponent(appId)}/views/${encodeURIComponent(view.id)}`);
    for (const s of d.series) {
      let c = charts.get(s.id);
      if (!c) {
        c = { val: h("span", { class: "val" }), canvas: h("canvas", { role: "img", "aria-label": s.label }) };
        c.el = h("div", { class: "chart" }, h("div", { class: "h" }, h("span", { class: "muted" }, s.label), c.val), c.canvas);
        grid.append(c.el);
        charts.set(s.id, c);
      }
      const last = s.points[s.points.length - 1];
      c.val.textContent = last ? fmtVal(s, last[1]) : "…";
      c.el.title = `${s.points.length} samples, last 10 minutes`;
      draw(c, s);
    }
    if (!d.series.some((s) => s.points.length)) grid.dataset.empty = "1";
  }, view.refresh || 2);
  return p;
}

// ---------------------------------------------------------------------------
// Bottom panel: Output, Terminal, Audit (+ panel views from plugins)
// ---------------------------------------------------------------------------

const output = {
  el: h("div", { class: "out", role: "log" }),
  ts() { return h("span", { class: "ts" }, `[${new Date().toLocaleTimeString()}] `); },
  push(...nodes) {
    this.el.append(h("div", { class: "entry" }, nodes));
    while (this.el.childElementCount > 200) this.el.firstChild.remove();
    this.el.parentElement && (this.el.parentElement.scrollTop = this.el.parentElement.scrollHeight);
  },
  begin(what) { this.push(this.ts(), h("span", { class: "cmd" }, what)); },
  note(msg) { this.push(this.ts(), msg); },
  error(msg) { this.push(this.ts(), h("span", { class: "bad" }, msg)); },
  result(o) {
    this.push(this.ts(), h("span", { class: "cmd" }, "$ " + o.argv.join(" ")), "\n",
      o.stdout, o.stderr ? h("span", { class: o.code === 0 ? "" : "bad" }, o.stderr) : null,
      h("span", { class: o.code === 0 ? "ok" : "bad" }, `\n→ exit ${o.code ?? "?"}${o.timed_out ? " (timed out)" : ""}${o.truncated ? " (output truncated)" : ""} in ${o.millis} ms`));
  },
};

function panelTabs() {
  const tabs = [{ id: "output", label: "Output" }];
  if (state.session.terminal) tabs.push({ id: "terminal", label: "Terminal" });
  for (const a of state.apps) for (const v of a.views || []) {
    if (v.location === "panel" && v.type !== "terminal") tabs.push({ id: `view:${a.id}:${v.id}`, label: v.label, app: a.id, view: v });
  }
  if (state.session.role === "admin") tabs.push({ id: "audit", label: "Audit" });
  return tabs;
}

function togglePanel(tab, forceOpen = false) {
  const wrap = ui.panel.parentElement;
  if (tab && tab !== state.panelTab) { state.panelTab = tab; forceOpen = true; }
  state.panelOpen = forceOpen ? true : !state.panelOpen;
  wrap.classList.toggle("hidden", !state.panelOpen);
  if (!state.panelOpen) ui.center.classList.remove("panel-max");
  renderPanel();
}

let panelCtl = null;
function renderPanel() {
  const tabs = panelTabs();
  if (!tabs.some((t) => t.id === state.panelTab)) state.panelTab = "output";
  fill(ui.ptabs, 
    tabs.map((t) => h("div", { class: "ptab" + (t.id === state.panelTab ? " active" : ""), onclick: () => togglePanel(t.id, true) }, t.label)),
    h("div", { class: "ptools" },
      state.panelTab === "terminal" ? h("button", { class: "icon-btn", title: "Restart terminal", onclick: () => terminal.restart() }, icon("refresh")) : null,
      state.panelTab === "output" ? h("button", { class: "icon-btn", title: "Clear output", onclick: () => clear(output.el) }, icon("trash")) : null,
      h("button", { class: "icon-btn", title: "Maximize panel", onclick: () => { ui.center.classList.toggle("panel-max"); terminal.fit(); } }, icon("maximize")),
      h("button", { class: "icon-btn", title: "Close panel", onclick: () => togglePanel(null) }, icon("close"))));
  panelCtl?.stop?.();
  panelCtl = null;
  if (!state.panelOpen) return;
  const host = h("div", {});
  fill(ui.pbody, host);
  const t = tabs.find((x) => x.id === state.panelTab);
  if (t.id === "output") host.append(output.el);
  else if (t.id === "terminal") terminal.mount(host);
  else if (t.id === "audit") panelCtl = auditView(host);
  else if (t.view) panelCtl = t.view.type === "metrics" ? metricsView(host, t.app, t.view) : tableView(host, t.app, t.view);
}

function auditView(el) {
  const tbody = h("tbody");
  const errs = h("div", {});
  el.append(errs, h("table", { class: "grid audit" }, h("thead", {}, h("tr", {}, ["Time", "User", "IP", "Event", "Result", "Detail"].map((c) => h("th", {}, c)))), tbody));
  return poller(async () => {
    const d = await api("GET", "/audit");
    fill(errs, d.plugin_errors.map((e) => h("div", { class: "notice mono" }, "Plugin not loaded: " + e)));
    fill(tbody, d.entries.map((e) => h("tr", {},
      h("td", {}, fmt.datetime(e.time)), h("td", {}, e.user), h("td", {}, e.ip), h("td", {}, e.event),
      h("td", { class: e.ok ? "" : "bad", style: { color: e.ok ? "var(--ok)" : "var(--err)" } }, e.ok ? "ok" : "denied/failed"),
      h("td", { title: e.detail }, e.detail))));
  }, 5);
}

// The terminal survives panel switches: the xterm element is re-parented, not recreated.
const terminal = {
  term: null, fitAddon: null, ws: null, el: null, ro: null, msg: null,
  theme() {
    const s = getComputedStyle(document.documentElement);
    const v = (n) => s.getPropertyValue(n).trim();
    return { background: v("--bg-panel"), foreground: v("--fg"), cursor: v("--fg"), selectionBackground: v("--bg-select") };
  },
  applyTheme() { if (this.term) this.term.options.theme = this.theme(); },
  mount(host) {
    host.classList.add("term");
    if (!window.Terminal) { host.append(h("div", { class: "term-msg" }, "xterm.js failed to load")); return; }
    if (!this.term) {
      this.el = h("div", { style: { height: "100%" } });
      this.term = new window.Terminal({ fontFamily: getComputedStyle(document.documentElement).getPropertyValue("--mono"), fontSize: 13, cursorBlink: true, theme: this.theme(), scrollback: 5000, allowProposedApi: false });
      this.fitAddon = new window.FitAddon.FitAddon();
      this.term.loadAddon(this.fitAddon);
      this.term.open(this.el);
      this.term.onData((d) => this.send({ type: "input", data: d }));
      this.term.onResize(({ cols, rows }) => this.send({ type: "resize", cols, rows }));
      this.ro = new ResizeObserver(() => this.fit());
    }
    host.append(this.el);
    this.ro.disconnect();
    this.ro.observe(host);
    if (!this.ws) this.connect();
    requestAnimationFrame(() => { this.fit(); this.term.focus(); });
  },
  fit() { try { this.fitAddon?.fit(); } catch { /* not visible */ } },
  send(m) { if (this.ws?.readyState === 1) this.ws.send(JSON.stringify(m)); },
  connect() {
    const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/terminal`);
    ws.binaryType = "arraybuffer";
    this.ws = ws;
    ws.onopen = () => {
      ws.send(JSON.stringify({ type: "auth", csrf: state.session.csrf }));
      this.send({ type: "resize", cols: this.term.cols, rows: this.term.rows });
    };
    ws.onmessage = (e) => {
      if (typeof e.data === "string") { if (e.data.includes('"exit"')) this.term.write("\r\n\x1b[2m[process exited — press the restart button]\x1b[0m\r\n"); return; }
      this.term.write(new Uint8Array(e.data));
    };
    ws.onclose = () => { if (this.ws === ws) { this.ws = null; this.term?.write("\r\n\x1b[2m[disconnected]\x1b[0m\r\n"); } };
  },
  restart() { const w = this.ws; this.ws = null; w?.close(); this.term?.reset(); this.connect(); },
  dispose() { const w = this.ws; this.ws = null; w?.close(); this.term?.dispose(); this.term = null; this.ro?.disconnect(); },
};

// ---------------------------------------------------------------------------
// Status bar
// ---------------------------------------------------------------------------

function renderStatus() {
  const s = state.session;
  const detected = state.apps.filter((a) => a.detected).length;
  const failed = state.apps.filter((a) => a.state === "failed");
  fill(ui.status, 
    h("div", { class: "item remote", title: "Connected host" }, icon("server"), s.hostname),
    h("div", { class: "item click", title: "Rescan", onclick: rescan }, icon("app"), `${detected} apps`),
    failed.length ? h("div", { class: "item click", style: { color: "var(--err)" }, title: failed.map((a) => a.name).join(", "), onclick: () => openApp(failed[0].id) }, icon("bolt"), `${failed.length} failed`) : null,
    h("div", { class: "spacer" }),
    s.terminal ? h("div", { class: "item click", onclick: () => togglePanel("terminal", true) }, icon("terminal"), "Terminal") : null,
    h("div", { class: "item", title: "Role: " + s.role }, icon("account"), `${s.user} (${s.role})`),
    h("div", { class: "item" }, "portvakt " + s.version));
}

// ---------------------------------------------------------------------------
// Quick open / command palette
// ---------------------------------------------------------------------------

function commands() {
  const cmds = [
    { label: "View: Toggle Terminal", run: () => togglePanel("terminal"), when: state.session.terminal },
    { label: "View: Toggle Panel", run: () => togglePanel() },
    { label: "View: Toggle Sidebar", run: toggleSide },
    { label: "View: Show Output", run: () => togglePanel("output", true) },
    { label: "View: Show Audit Log", run: () => togglePanel("audit", true), when: state.session.role === "admin" },
    { label: "Preferences: Toggle Light/Dark Theme", run: toggleTheme },
    { label: "Applications: Rescan", run: rescan, when: state.session.role === "admin" },
    { label: "Applications: Show Not Detected", run: () => { state.showUndetected = true; renderSidebar(); } },
    { label: "Account: Sign Out", run: logout },
  ].filter((c) => c.when !== false);
  for (const a of state.apps.filter((a) => a.detected)) {
    for (const v of a.views || []) cmds.push({ label: `${a.name}: Open ${v.label}`, run: () => openView(a.id, v.id) });
  }
  return cmds;
}

async function fileItems() {
  // Files are listed per app detail; fetch for detected apps lazily and cache.
  if (state.fileCache) return state.fileCache;
  if (state.session.role !== "admin") return [];
  const items = [];
  await Promise.all(state.apps.filter((a) => a.detected).map(async (a) => {
    try {
      const d = await api("GET", "/apps/" + encodeURIComponent(a.id));
      for (const f of d.files) items.push({ label: f.path.split("/").pop(), desc: f.path, icon: "file", run: () => openFile(a.id, f.path) });
      for (const act of d.actions.filter((x) => !x.params.length && x.available)) {
        items.push({ label: `${a.name}: ${act.label}`, desc: "action", icon: actionIcon(act.id), cmd: true, run: () => runAction(a.id, act, {}) });
      }
    } catch { /* ignore */ }
  }));
  state.fileCache = items;
  setTimeout(() => { state.fileCache = null; }, 60000);
  return items;
}

function score(q, text) {
  if (!q) return 1;
  text = text.toLowerCase();
  let i = 0, s = 0, last = -2;
  for (const ch of q) {
    const j = text.indexOf(ch, i);
    if (j < 0) return 0;
    s += j === last + 1 ? 3 : 1;
    if (j === 0 || " :/-_.".includes(text[j - 1])) s += 2;
    last = j; i = j + 1;
  }
  return s;
}

async function quickOpen(prefix) {
  document.querySelector(".overlay")?.remove();
  const input = h("input", { class: "txt", value: prefix, placeholder: "Search applications and files, or type > for commands", "aria-label": "Quick open" });
  const list = h("div", { class: "items", role: "listbox" });
  const overlay = h("div", { class: "overlay", onmousedown: (e) => { if (e.target === overlay) close(); } }, h("div", { class: "quick" }, input, list));
  document.body.append(overlay);
  input.focus();
  const close = () => { overlay.remove(); };
  let sel = 0, items = [];
  const extra = await fileItems();
  function update() {
    const raw = input.value;
    const isCmd = raw.startsWith(">");
    const q = raw.replace(/^>\s*/, "").toLowerCase();
    const pool = isCmd
      ? [...commands().map((c) => ({ ...c, icon: "bolt" })), ...extra.filter((x) => x.cmd)]
      : [...state.apps.filter((a) => a.detected).map((a) => ({ label: a.name, desc: a.category + (a.version ? " · " + a.version : ""), icon: a.icon, run: () => openApp(a.id) })), ...extra.filter((x) => !x.cmd)];
    items = pool.map((it) => ({ it, s: Math.max(score(q, it.label), score(q, it.desc || "") * 0.5) })).filter((x) => x.s > 0).sort((a, b) => b.s - a.s).slice(0, 50).map((x) => x.it);
    sel = Math.min(sel, Math.max(0, items.length - 1));
    fill(list, items.length ? items.map((it, i) => h("div", {
      class: "qi" + (i === sel ? " sel" : ""), role: "option", onmousemove: () => { if (sel !== i) { sel = i; update(); } },
      onclick: () => { close(); it.run(); },
    }, icon(it.icon || "app"), h("span", {}, it.label), it.desc ? h("span", { class: "d" }, it.desc) : null)) : h("div", { class: "empty" }, "No matching results"));
    list.querySelector(".sel")?.scrollIntoView({ block: "nearest" });
  }
  input.addEventListener("input", () => { sel = 0; update(); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { sel = Math.min(items.length - 1, sel + 1); update(); e.preventDefault(); }
    else if (e.key === "ArrowUp") { sel = Math.max(0, sel - 1); update(); e.preventDefault(); }
    else if (e.key === "Enter") { const it = items[sel]; close(); it?.run(); }
    else if (e.key === "Escape") close();
  });
  update();
}

// ---------------------------------------------------------------------------
// Keyboard shortcuts
// ---------------------------------------------------------------------------

document.addEventListener("keydown", (e) => {
  if (!state.session || !ui.main) return;
  const mod = e.ctrlKey || e.metaKey;
  const k = e.key.toLowerCase();
  if ((mod && e.shiftKey && k === "p") || e.key === "F1") { e.preventDefault(); quickOpen(">"); }
  else if (mod && !e.shiftKey && k === "p") { e.preventDefault(); quickOpen(""); }
  else if (mod && (e.key === "`" || e.code === "Backquote")) { e.preventDefault(); togglePanel("terminal"); }
  else if (mod && !e.shiftKey && k === "b") { e.preventDefault(); toggleSide(); }
  else if (mod && e.shiftKey && k === "e") { e.preventDefault(); if (!state.sideOpen) toggleSide(); }
  else if (mod && k === "s") {
    e.preventDefault();
    state.tabs.find((t) => t.id === state.active)?.save?.();
  } else if (e.altKey && k === "w") { e.preventDefault(); if (state.active) closeTab(state.active); }
});

window.addEventListener("beforeunload", (e) => {
  if (state.tabs.some((t) => t.dirty)) { e.preventDefault(); e.returnValue = ""; }
});

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

try { const t = localStorage.getItem("portvakt.theme"); if (t) document.documentElement.dataset.theme = t; } catch { /* ignore */ }

(async () => {
  try {
    state.session = await api("GET", "/session");
    await startWorkbench();
  } catch {
    renderLogin();
  }
})();
