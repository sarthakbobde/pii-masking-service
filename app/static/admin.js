"use strict";
/* Admin page for the PII masking service. Plain JavaScript, no build step.
   Everything shown is put on the page as text (never as HTML), and the admin key, when the server asks for one, lives in this tab's sessionStorage only. */

const root = document.getElementById("app");
const state = { key: "", overview: null, ui: {} };
try { state.key = sessionStorage.getItem("pii_admin_key") || ""; } catch (_) { /* storage blocked: sign in each visit */ }

// ---- small helpers ------------------------------------------------------------------------------------------------------
function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  const add = (k) => {
    if (k === null || k === undefined || k === false) return;
    if (Array.isArray(k)) return k.forEach(add);
    n.append(k instanceof Node ? k : document.createTextNode(String(k)));
  };
  kids.forEach(add);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") n.className = v;
    else if (k === "style") n.style.cssText = v;               // set through the style object: allowed by the page's CSP
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (["value", "checked", "disabled", "selected", "readOnly"].includes(k)) n[k] = v;
    else if (v !== false && v !== null && v !== undefined) n.setAttribute(k, v === true ? "" : v);
  }
  return n;
}

// Appending null or false to the DOM would print the word "null": skip empty values.
function put(parent, ...kids) { kids.flat(Infinity).forEach((k) => { if (k !== null && k !== undefined && k !== false) parent.append(k); }); }

const ICONS = {
  overview: '<path d="M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z"/>',
  fields: '<path d="M4 6h16M4 12h16M4 18h10"/>',
  detection: '<path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>',
  audit: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  check: '<path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5M10 14l2 2 4-4"/>',
  tryit: '<path d="M9 3h6M10 3v6l-5 9a2 2 0 002 3h10a2 2 0 002-3l-5-9V3"/>',
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
  shieldoff: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 9l6 6M15 9l-6 6"/>',
};
function icon(name) {
  const s = el("span");
  s.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ""}</svg>`;   // constant strings only
  return s.firstChild;
}

const fmt = (n) => (n ?? 0).toLocaleString();
const lines = (t) => t.split("\n").map((x) => x.trim()).filter(Boolean);
const when = (iso) => (iso ? new Date(iso.endsWith("Z") ? iso : iso + "Z").toLocaleString() : "never");
const label = (name) => (name || "").trim().toUpperCase().replace(/[\s-]+/g, "_");

function sw(checked, onchange, big, aria) {
  const i = el("input", { type: "checkbox", checked: !!checked, "aria-label": aria || "toggle" });
  i.addEventListener("change", () => onchange(i.checked, i));
  return el("label", { class: "switch" + (big ? " lg" : "") }, i, el("i"));
}

function toast(msg, bad) {
  let box = document.querySelector(".toasts");
  if (!box) { box = el("div", { class: "toasts", role: "status", "aria-live": "polite" }); document.body.append(box); }
  const t = el("div", { class: "toast" + (bad ? " bad" : "") }, msg);
  box.append(t);
  setTimeout(() => t.remove(), bad ? 7000 : 3500);
}

function detailText(d) {
  if (!d) return "";
  if (typeof d === "string") return d;
  if (Array.isArray(d)) return d.map((x) => `${(x.loc || []).slice(1).join(".")}: ${x.msg}`).join("; ");
  return JSON.stringify(d);
}

async function api(method, path, body, raw) {
  const headers = state.key ? { "X-API-Key": state.key } : {};
  let payload;
  if (body instanceof FormData) payload = body;
  else if (body !== undefined) { headers["Content-Type"] = "application/json"; payload = JSON.stringify(body); }
  const r = await fetch(path, { method, headers, body: payload });
  if (r.status === 401) { signOut(state.key ? "That admin key was not accepted." : ""); throw new Error("Signed out."); }
  if (r.status === 403 && !state.key) { renderLocalOnly(); throw new Error("Signed out."); }
  if (raw) return r;
  const data = await r.json().catch(() => null);
  if (!r.ok) throw new Error(detailText(data && data.detail) || `Request failed (${r.status}).`);
  return data;
}

function fail(e) { if (e.message !== "Signed out.") toast(e.message, true); }

function openModal({ title, body, buttons, wide, onclose }) {
  const close = () => { if (!scrim.isConnected) return; scrim.remove(); document.removeEventListener("keydown", onKey); if (onclose) onclose(); };
  const onKey = (e) => { if (e.key === "Escape" && [...document.querySelectorAll(".scrim")].pop() === scrim) close(); };   // top one only
  const foot = el("div", { class: "modal-foot" });
  (buttons || []).forEach((b) => foot.append(el("button", { class: "btn " + (b.cls || ""), type: "button", onclick: () => b.onclick(close) }, b.label)));
  const scrim = el("div", { class: "scrim", onmousedown: (e) => { if (e.target === scrim) close(); } },
    el("div", { class: "modal" + (wide ? " wide" : ""), role: "dialog", "aria-modal": "true", "aria-label": title },
      el("div", { class: "modal-head" }, el("h2", {}, title), el("button", { class: "btn small ghost", type: "button", "aria-label": "Close", onclick: close }, "✕")),
      el("div", { class: "modal-body" }, body), buttons && buttons.length ? foot : null));
  document.addEventListener("keydown", onKey);
  document.body.append(scrim);
  const first = scrim.querySelector("input[type=text], textarea, select");
  if (first) first.focus();
  return close;
}

function confirmBox({ title, message, confirm, danger }) {
  return new Promise((resolve) => {
    let answer = false;                                          // closing with Escape or by clicking outside counts as Cancel
    const finish = (v, close) => { answer = v; close(); };
    openModal({
      title, body: el("p", {}, message), onclose: () => resolve(answer),
      buttons: [{ label: "Cancel", onclick: (c) => finish(false, c) },
        { label: confirm || "Confirm", cls: danger ? "solid-danger" : "primary", onclick: (c) => finish(true, c) }],
    });
  });
}

function copy(text) {
  const done = () => toast("Copied to the clipboard.");
  if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, () => toast("Copy failed: select the text and copy it.", true));
  else toast("Select the text and copy it.", true);
}

const pill = (kind, text) => el("span", { class: "pill " + kind }, text);

// ---- sign in ---------------------------------------------------------------------------------------------------------------
function signOut(message) {
  state.key = "";
  try { sessionStorage.removeItem("pii_admin_key"); } catch (_) { /* ignore */ }
  renderLogin(message);
}

function renderLogin(message) {
  const input = el("input", { type: "password", autocomplete: "off", placeholder: "Admin key", "aria-label": "Admin key" });
  const err = el("p", { class: "hint", role: "alert" }, message || "");
  err.style.color = "var(--bad)";
  const go = async () => {
    state.key = input.value.trim();
    if (!state.key) return;
    try {
      await api("GET", "/v1/admin/overview");
      try { sessionStorage.setItem("pii_admin_key", state.key); } catch (_) { /* ignore */ }
      renderShell();
    } catch (e) { if (e.message !== "Signed out.") { err.textContent = e.message; state.key = ""; } }
  };
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
  root.replaceChildren(el("div", { class: "login" }, el("div", { class: "box" },
    el("div", { class: "brand" }, logo(), el("div", {}, el("b", {}, "PII Masking Service"), el("span", {}, "Administration"))),
    el("label", { class: "f" }, el("span", { class: "t" }, "Admin key"), input,
      el("span", { class: "h" }, "Set by whoever runs this service (PII_ADMIN_KEY). It stays in this browser tab and is cleared when you close it.")),
    err, el("button", { class: "btn primary", type: "button", style: "width:100%;justify-content:center", onclick: go }, "Sign in"))));
  input.focus();
}

function renderLocalOnly() {
  root.replaceChildren(el("div", { class: "login" }, el("div", { class: "box" },
    el("div", { class: "brand" }, logo(), el("div", {}, el("b", {}, "PII Masking Service"), el("span", {}, "Administration"))),
    el("p", {}, "The admin page is available only on the server itself."),
    el("p", { class: "hint", style: "margin-top:8px" }, "To use it from another computer, set PII_ADMIN_KEY on the server and restart it. You will then sign in here with that key. The masking API is not affected: it needs no key."))));
}

function logo() {
  const s = el("span");
  s.innerHTML = '<svg viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#12304d"/><path d="M16 5l9 3.5v7.2c0 5.4-3.7 9.5-9 11.3-5.3-1.8-9-5.9-9-11.3V8.5z" fill="none" stroke="#2bb3b1" stroke-width="2"/><rect x="11" y="13" width="10" height="2.4" rx="1.2" fill="#fff"/><rect x="11" y="17.6" width="6.5" height="2.4" rx="1.2" fill="#2bb3b1"/></svg>';
  return s.firstChild;
}

// ---- shell -----------------------------------------------------------------------------------------------------------------
const NAV = [["overview", "Overview"], ["fields", "Fields to hide"], ["detection", "Detection settings"],
  ["audit", "Audit log"], ["check", "Check a document"], ["tryit", "Try it"]];
let content, topbar;

function renderShell() {
  content = el("main", { class: "page", id: "content" });
  topbar = el("div", { class: "top" });
  const nav = el("nav", { class: "nav", "aria-label": "Sections" },
    NAV.map(([r, name]) => el("a", { href: "#/" + r, "data-r": r }, icon(r), el("span", {}, name))));
  root.replaceChildren(el("div", { class: "shell" },
    el("aside", { class: "side" },
      el("div", { class: "brand" }, logo(), el("div", {}, el("b", {}, "PII Masking"), el("span", {}, "Administration"))), nav,
      el("div", { class: "side-foot" }, state.key ? "Signed in with the admin key" : "On the server itself: no key needed",
        state.key ? el("button", { class: "btn small", type: "button", onclick: () => signOut() }, "Sign out") : null)),
    el("div", { class: "main" }, topbar, content)));
  show();
}

function updateTop() {
  const o = state.overview;
  if (!o) return;
  const h = o.health;
  topbar.replaceChildren(
    el("span", { class: "muted" }, "PII Masking Service · v" + h.version),
    el("span", { class: "spacer" }),
    pill(h.detector === "ready" ? "ok" : h.detector === "loading" ? "warn" : "bad", "Detector " + h.detector),
    o.protection_enabled ? pill("ok", "PII protection on") : pill("bad", "PII protection OFF"));
}

async function loadOverview() {
  state.overview = await api("GET", "/v1/admin/overview");
  updateTop();
  return state.overview;
}

async function show() {
  if (!content) return;
  const name = (location.hash.replace(/^#\/?/, "") || "overview").split("?")[0];
  const page = PAGES[name] || PAGES.overview;
  document.querySelectorAll(".nav a").forEach((a) => a.classList.toggle("on", a.dataset.r === (PAGES[name] ? name : "overview")));
  content.replaceChildren(el("p", { class: "muted" }, "Loading…"));
  try {
    await loadOverview();
    content.replaceChildren();
    await page(content);
  } catch (e) {
    if (e.message !== "Signed out.") content.replaceChildren(el("div", { class: "callout bad" }, e.message));
  }
  window.scrollTo(0, 0);
}
window.addEventListener("hashchange", show);

function head(title, text, ...actions) {
  return el("div", { class: "page-head" }, el("div", {}, el("h1", {}, title), text ? el("p", {}, text) : null), el("div", { class: "actions" }, actions));
}

// ---- overview --------------------------------------------------------------------------------------------------------------
async function setProtection(on) {
  if (!on) {
    const ok = await confirmBox({
      title: "Switch PII protection off?",
      message: "While it is off, text and documents sent for masking come back UNCHANGED, with nothing detected. Callers are told in the response. Use this only for testing or an emergency.",
      confirm: "Switch off", danger: true,
    });
    if (!ok) return false;
  }
  await api("PUT", "/v1/admin/settings", { protection_enabled: on });
  toast(on ? "PII protection is on." : "PII protection is off.");
  return true;
}

async function pageOverview(c) {
  const o = state.overview, d = o.last_24h, n = o.counts, h = o.health;
  const recent = await api("GET", "/v1/admin/audit?limit=8");
  const on = o.protection_enabled;
  const big = sw(on, async (v, input) => {
    input.disabled = true;
    try { if (await setProtection(v)) { show(); return; } input.checked = !v; } catch (e) { input.checked = !v; fail(e); }
    input.disabled = false;
  }, true, "PII protection");
  const bars = Object.entries(d.by_type);
  const max = Math.max(1, ...bars.map(([, v]) => v));
  put(c, 
    head("Overview", "How the service is doing and what it has hidden in the last 24 hours."),
    el("div", { class: "protect " + (on ? "on" : "off") },
      el("div", { class: "ico" }, icon(on ? "shield" : "shieldoff")),
      el("div", { class: "txt" }, el("b", {}, on ? "PII protection is on" : "PII protection is OFF"),
        el("p", {}, on ? "Masking requests hide personal data as configured." : "Masking requests return text and documents unchanged. Nothing is being hidden.")),
      big),
    el("div", { class: "tiles" },
      tile("Requests, 24 h", fmt(d.calls), `${fmt(d.errors)} failed or refused`),
      tile("Values hidden, 24 h", fmt(d.values), "across all callers"),
      tile("Fields", `${n.fields_enabled} / ${n.fields}`, `${fmt(n.field_values)} known values`),
      tile("Custom types", fmt(n.custom_types), "your own patterns")),
    el("div", { class: "grid cols-2" },
      el("div", { class: "card" }, el("div", { class: "card-head" }, el("h2", {}, "Most hidden types, 24 h")),
        el("div", { class: "card-body" }, bars.length
          ? el("div", { class: "bars" }, bars.map(([k, v]) => el("div", { class: "bar" }, el("span", { class: "k", title: k }, k),
            el("span", { class: "track" }, el("span", { class: "fill", style: `width:${Math.max(3, (v / max) * 100)}%` })), el("span", { class: "v" }, fmt(v)))))
          : el("p", { class: "muted" }, "Nothing hidden yet in the last 24 hours."))),
      el("div", { class: "card" }, el("div", { class: "card-head" }, el("h2", {}, "System health")),
        el("div", { class: "card-body" }, el("div", { class: "health" },
          hl("Detector", h.detector === "ready" ? pill("ok", "Ready") : pill(h.detector === "loading" ? "warn" : "bad", h.detector)),
          hl("Database", h.database ? pill("ok", "Connected") : pill("bad", "Down")),
          hl("OCR", h.ocr ? pill("ok", "Available") : pill("off", "Not installed"))),
        el("p", { class: "hint", style: "margin-top:12px" }, `Limits: text up to ${fmt(o.limits.max_text_chars)} characters, files up to ${o.limits.max_upload_mb} MB. The masking API needs no key.`)))),
    el("div", { class: "card" }, el("div", { class: "card-head" }, el("h2", {}, "Recent activity"), el("a", { class: "btn small", href: "#/audit" }, "Open audit log")),
      auditTable(recent)));
}
function tile(l, n, s) { return el("div", { class: "card tile" }, el("div", { class: "l" }, l), el("div", { class: "n" }, n), el("div", { class: "s" }, s)); }
function hl(l, v) { return el("div", {}, el("span", {}, l), v); }

// ---- fields ----------------------------------------------------------------------------------------------------------------
async function pageFields(c) {
  const list = await api("GET", "/v1/admin/fields");
  const search = el("input", { type: "text", placeholder: "Search fields…", "aria-label": "Search fields", value: state.ui.fieldSearch || "" });
  const tbody = el("tbody");
  const draw = () => {
    state.ui.fieldSearch = search.value;
    const q = search.value.trim().toLowerCase();
    const rows = list.filter((f) => !q || (f.name + " " + f.description + " " + f.labels.join(" ")).toLowerCase().includes(q));
    tbody.replaceChildren(...(rows.length ? rows.map((f) => el("tr", {},
      el("td", {}, el("b", {}, f.name), f.description ? el("div", { class: "muted" }, f.description) : null),
      el("td", {}, f.terms.length ? el("span", { class: "chip teal" }, fmt(f.terms.length) + " value" + (f.terms.length === 1 ? "" : "s")) : el("span", { class: "muted" }, "none yet")),
      el("td", {}, el("div", { class: "chips" }, f.labels.slice(0, 3).map((l) => el("span", { class: "chip" }, l)), f.labels.length > 3 ? el("span", { class: "chip" }, "+" + (f.labels.length - 3)) : null)),
      el("td", {}, sw(f.enabled, async (v, i) => { try { await api("PATCH", `/v1/admin/fields/${f.id}`, { enabled: v }); f.enabled = v; toast(`${f.name} ${v ? "enabled" : "paused"}.`); } catch (e) { i.checked = !v; fail(e); } }, false, "Enabled")),
      el("td", { class: "actions" }, el("button", { class: "btn small", type: "button", onclick: () => fieldModal(f) }, "Edit"))))
      : [el("tr", {}, el("td", { colspan: 5, class: "empty" }, "No fields match."))]));
  };
  search.addEventListener("input", draw);
  const needValues = list.length && list.every((f) => !f.terms.length);
  put(c, 
    head("Fields to hide", "A field is a kind of data to hide, such as a client's name or GST number. Give it the exact values to look for, and the labels (like “Client Name:”) that introduce it.",
      el("button", { class: "btn primary", type: "button", onclick: () => fieldModal(null) }, "+ Add field")),
    needValues ? el("div", { class: "callout info", style: "margin-bottom:16px" }, "These starter fields have labels but no values yet. Open a field and add the real names, numbers and addresses to hide wherever they appear. Anything after a label (for example “Client Name:”) is hidden already.") : null,
    el("div", { class: "card" },
      el("div", { class: "card-head" }, el("div", { class: "grow", style: "max-width:320px;flex:1" }, search), el("span", { class: "muted" }, `${list.length} field${list.length === 1 ? "" : "s"}`)),
      el("div", { class: "table-wrap" }, el("table", {}, el("thead", {}, el("tr", {}, ["Field", "Known values", "Labels", "On", ""].map((t) => el("th", {}, t)))), tbody))));
  draw();
}

function fieldModal(f) {
  const isNew = !f;
  const name = el("input", { type: "text", value: f ? f.name : "", placeholder: "e.g. PROJECT_NAME", maxlength: 40 });
  const preview = el("code", {}, "");
  const upd = () => { preview.textContent = name.value.trim() ? "<" + label(name.value) + ">" : "<NAME>"; };
  name.addEventListener("input", upd); upd();
  const desc = el("input", { type: "text", value: f ? f.description : "", placeholder: "What this field is (optional)", maxlength: 200 });
  const labels = el("textarea", { rows: 4, placeholder: "One per line, e.g.\nClient Name\nCustomer Name" }, f ? f.labels.join("\n") : "");
  const terms = el("textarea", { rows: 7, placeholder: "One per line, e.g.\nGlobex Retail Pvt Ltd\nGlobex Retail" }, f ? f.terms.join("\n") : "");
  const count = el("span", { class: "hint" }, "");
  const cnt = () => { count.textContent = `${lines(terms.value).length} value(s)`; };
  terms.addEventListener("input", cnt); cnt();
  let enabled = f ? f.enabled : true;
  const body = el("div", {},
    el("div", { class: "grid cols-2" },
      el("label", { class: "f" }, el("span", { class: "t" }, "Field name"), name, el("span", { class: "h" }, "Shown in the output as ", preview, ".")),
      el("label", { class: "f" }, el("span", { class: "t" }, "Description"), desc)),
    el("label", { class: "f" }, el("span", { class: "t" }, "Labels"), labels,
      el("span", { class: "h" }, "Words that introduce a value. The value after “Client Name:” (or in the cell beside it) is hidden as this field.")),
    el("label", { class: "f" }, el("span", { class: "t" }, "Known values"), terms, count,
      el("span", { class: "h" }, "Hidden wherever they appear, ignoring case and spacing: “Globex Retail Pvt Ltd” also finds “GLOBEX RETAIL PVT. LTD.”. Paste as many as you like.")),
    el("div", { class: "row" }, sw(enabled, (v) => { enabled = v; }, false, "Enabled"), el("span", {}, "Field is active")));
  const save = async (close) => {
    const payload = { name: name.value, description: desc.value, labels: lines(labels.value), terms: lines(terms.value), enabled };
    try {
      if (isNew) await api("POST", "/v1/admin/fields", payload); else await api("PATCH", `/v1/admin/fields/${f.id}`, payload);
      close(); toast(isNew ? "Field added." : "Field saved."); show();
    } catch (e) { fail(e); }
  };
  const buttons = [{ label: "Cancel", onclick: (c) => c() }, { label: isNew ? "Add field" : "Save", cls: "primary", onclick: save }];
  if (!isNew) buttons.unshift({ label: "Delete", cls: "danger", onclick: async (close) => {
    if (await confirmBox({ title: "Delete this field?", message: `${f.name} and its ${f.terms.length} known value(s) will be removed. Text it used to hide will no longer be hidden.`, confirm: "Delete", danger: true })) {
      try { await api("DELETE", `/v1/admin/fields/${f.id}`); close(); toast("Field deleted."); show(); } catch (e) { fail(e); }
    }
  } });
  openModal({ title: isNew ? "Add a field" : "Edit " + f.name, body, buttons, wide: true });
}

// ---- detection settings ----------------------------------------------------------------------------------------------------
const TYPE_INFO = {
  EMAIL_ADDRESS: "Email address", PHONE_NUMBER: "Phone number", CREDIT_CARD: "Credit or debit card", US_SSN: "US Social Security number",
  IN_AADHAAR: "Aadhaar number (India)", IN_PAN: "PAN (India)", IN_GSTIN: "GST number (India)", IN_CIN: "Company CIN (India)", IBAN_CODE: "IBAN bank account",
  IP_ADDRESS: "IP address", URL: "Web address", US_PASSPORT: "US passport", US_BANK_NUMBER: "US bank account", US_DRIVER_LICENSE: "US driver licence",
  US_ITIN: "US tax ID (ITIN)", UK_NHS: "UK NHS number", CRYPTO: "Crypto wallet", MEDICAL_LICENSE: "Medical licence",
  IN_VEHICLE_REGISTRATION: "Vehicle registration (India)", IN_VOTER: "Voter ID (India)", IN_PASSPORT: "Passport (India)",
};
const COMMON = ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "IN_AADHAAR", "IN_PAN", "IN_GSTIN", "IN_CIN", "IBAN_CODE"];

async function pageDetection(c) {
  const [view, customs] = await Promise.all([api("GET", "/v1/admin/settings"), api("GET", "/v1/admin/custom-types")]);
  const orig = view.settings;
  const d = JSON.parse(JSON.stringify(orig));
  const saveBtn = el("button", { class: "btn primary", type: "button", disabled: true }, "Save changes");
  const dirty = el("span", { class: "muted" }, "");
  const mark = () => { const changed = JSON.stringify(d) !== JSON.stringify(orig); saveBtn.disabled = !changed; dirty.textContent = changed ? "You have unsaved changes." : ""; };
  const toggleType = (t, on) => { const s = new Set(d.enabled_types); on ? s.add(t) : s.delete(t); d.enabled_types = [...s]; mark(); };
  const typeCard = (t, subtitle, extra) => {
    const card = el("div", { class: "type" + (d.enabled_types.includes(t) ? " on" : "") });
    put(card, sw(d.enabled_types.includes(t), (v) => { toggleType(t, v); card.classList.toggle("on", v); }, false, t),
      el("div", { class: "tx" }, el("b", {}, TYPE_INFO[t] || t), el("code", {}, "<" + t + ">"), subtitle ? el("div", {}, subtitle) : null), extra);
    return card;
  };
  const builtIn = view.built_in_types;
  const common = builtIn.filter((t) => COMMON.includes(t)), more = builtIn.filter((t) => !COMMON.includes(t));
  const customGrid = customs.length ? el("div", { class: "types" }, customs.map((t) => typeCard(t.name, `Pattern ${t.pattern.length > 28 ? t.pattern.slice(0, 28) + "…" : t.pattern}`,
    el("button", { class: "btn small", type: "button", onclick: () => customModal(t) }, "Edit")))) : el("p", { class: "muted" }, "No custom types yet. Add one to catch an identifier of your own, such as EMP-12345.");

  const thr = el("input", { type: "range", min: 10, max: 95, step: 5, value: d.threshold, "aria-label": "Detection confidence" });
  const thrv = el("b", {}, d.threshold + "%");
  thr.addEventListener("input", () => { d.threshold = +thr.value; thrv.textContent = d.threshold + "%"; mark(); });
  const kws = el("textarea", { rows: 5 }, d.sensitive_keywords.join("\n"));
  kws.addEventListener("input", () => { d.sensitive_keywords = lines(kws.value); mark(); });
  const allow = el("textarea", { rows: 4, placeholder: "One per line, e.g. hr@company.com" }, d.allow_list.join("\n"));
  allow.addEventListener("input", () => { d.allow_list = lines(allow.value); mark(); });
  const lang = el("input", { type: "text", value: d.ocr_language, "aria-label": "OCR language", style: "width:120px" });
  lang.addEventListener("input", () => { d.ocr_language = lang.value.trim(); mark(); });
  const row = (title, desc, ctl) => el("div", { class: "setting" }, el("div", {}, el("b", {}, title), el("div", { class: "d" }, desc)), ctl);
  const flag = (k) => sw(d[k], (v) => { d[k] = v; mark(); }, false, k);

  saveBtn.addEventListener("click", async () => {
    try {
      const { protection_enabled, ...payload } = d;       // the protection switch has its own control; don't overwrite it
      const out = await api("PUT", "/v1/admin/settings", payload);
      Object.assign(orig, out.settings); toast("Settings saved."); mark(); show();
    } catch (e) { fail(e); }
  });
  put(c, 
    head("Detection settings", "Choose what the service looks for and how strict it is. Changes apply to the next request.",
      el("button", { class: "btn", type: "button", onclick: () => customModal(null) }, "+ Custom type")),
    el("div", { class: "card" }, el("div", { class: "card-head" }, el("div", {}, el("h2", {}, "What to detect"), el("p", {}, "Switch each kind of personal data on or off."))),
      el("div", { class: "card-body" }, el("h3", { style: "margin-bottom:8px" }, "Common"),
        el("div", { class: "types" }, common.map((t) => typeCard(t))),
        el("h3", { style: "margin:18px 0 8px" }, "More types"), el("div", { class: "types" }, more.map((t) => typeCard(t))),
        el("h3", { style: "margin:18px 0 8px" }, "Your own types"), customGrid)),
    el("div", { class: "card" }, el("div", { class: "card-head" }, el("h2", {}, "How strict to be")),
      el("div", { class: "card-body" },
        row("Detection confidence", "How sure the detector must be before hiding something. Lower catches more but hides more false alarms.", el("div", { style: "width:260px" }, thr, el("div", { class: "row between" }, el("span", { class: "hint" }, "More"), thrv, el("span", { class: "hint" }, "Fewer")))),
        row("Hide people's names", "Detects names of people. Off by default: names are often needed, and detection is approximate.", flag("mask_names")),
        row("Hide values next to sensitive keywords", "The value after a keyword such as “Salary:” is hidden whatever its format.", flag("keywords_enabled")),
        el("div", { class: "setting", style: "display:block" }, el("b", {}, "Sensitive keywords"), el("div", { class: "d", style: "margin:2px 0 8px" }, "One per line."), kws),
        el("div", { class: "setting", style: "display:block" }, el("b", {}, "Never hide these (allow-list)"), el("div", { class: "d", style: "margin:2px 0 8px" }, "Exact values that may stay visible, such as a shared HR mailbox."), allow))),
    el("div", { class: "card" }, el("div", { class: "card-head" }, el("h2", {}, "Files and requests")),
      el("div", { class: "card-body" },
        row("Remove document properties", "Clears author, last editor, title and similar details from Word, PowerPoint, Excel and PDF files.", flag("scrub_metadata")),
        row("Read scanned PDF pages (OCR)", "Finds personal data in scanned pages. Needs Tesseract language data on the server.", el("div", { class: "row" }, lang, flag("ocr_enabled"))),
        row("Let callers override settings", "Allows each request to send its own types, threshold, keywords and extra field values. Switch off to enforce these settings strictly.", flag("allow_overrides")))),
    el("div", { class: "save-bar" }, dirty, el("button", { class: "btn", type: "button", onclick: show }, "Discard"), saveBtn));
}

function customModal(t) {
  const isNew = !t;
  const name = el("input", { type: "text", value: t ? t.name : "", placeholder: "EMPLOYEE_ID", maxlength: 40 });
  const pattern = el("input", { type: "text", class: "mono", value: t ? t.pattern : "", placeholder: "\\bEMP-\\d{5}\\b", maxlength: 300 });
  const context = el("input", { type: "text", value: t ? t.context.join(", ") : "", placeholder: "employee, badge (optional)" });
  const conf = el("input", { type: "number", min: 10, max: 100, value: t ? t.confidence : 85 });
  const sample = el("textarea", { rows: 2, placeholder: "Paste sample text to test the pattern" });
  const result = el("div", { class: "chips", style: "margin-top:8px" });
  const test = async () => {
    try {
      const r = await api("POST", "/v1/admin/custom-types/test", { pattern: pattern.value, text: sample.value });
      result.replaceChildren(...(r.matches.length ? r.matches.map((m) => el("span", { class: "chip teal mono" }, m)) : [el("span", { class: "muted" }, "No matches.")]));
    } catch (e) { result.replaceChildren(el("span", { style: "color:var(--bad)" }, e.message)); }
  };
  const body = el("div", {},
    el("div", { class: "grid cols-2" }, el("label", { class: "f" }, el("span", { class: "t" }, "Type name"), name, el("span", { class: "h" }, "Capital letters, digits and underscores.")),
      el("label", { class: "f" }, el("span", { class: "t" }, "Confidence (10 to 100)"), conf)),
    el("label", { class: "f" }, el("span", { class: "t" }, "Pattern (regular expression)"), pattern),
    el("label", { class: "f" }, el("span", { class: "t" }, "Context words"), context, el("span", { class: "h" }, "Comma-separated words that raise confidence when found nearby.")),
    el("label", { class: "f" }, el("span", { class: "t" }, "Test the pattern"), sample, el("div", { style: "margin-top:6px" }, el("button", { class: "btn small", type: "button", onclick: test }, "Test")), result));
  const save = async (close) => {
    const payload = { name: name.value, pattern: pattern.value, context: context.value.split(",").map((x) => x.trim()).filter(Boolean), confidence: +conf.value };
    try {
      if (isNew) await api("POST", "/v1/admin/custom-types", payload); else await api("PUT", `/v1/admin/custom-types/${t.id}`, payload);
      close(); toast("Custom type saved."); show();
    } catch (e) { fail(e); }
  };
  const buttons = [{ label: "Cancel", onclick: (c) => c() }, { label: isNew ? "Add type" : "Save", cls: "primary", onclick: save }];
  if (!isNew) buttons.unshift({ label: "Delete", cls: "danger", onclick: async (close) => {
    if (await confirmBox({ title: "Delete this type?", message: `${t.name} will no longer be detected.`, confirm: "Delete", danger: true })) {
      try { await api("DELETE", `/v1/admin/custom-types/${t.id}`); close(); toast("Type deleted."); show(); } catch (e) { fail(e); }
    }
  } });
  openModal({ title: isNew ? "Add a custom type" : "Edit " + t.name, body, buttons });
}

// ---- audit log -------------------------------------------------------------------------------------------------------------
function auditTable(rows) {
  if (!rows.length) return el("div", { class: "empty" }, "No activity yet.");
  return el("div", { class: "table-wrap" }, el("table", {},
    el("thead", {}, el("tr", {}, ["Time", "Caller", "Operation", "Result", "Hidden", "What", "ms"].map((t, i) => el("th", { class: i === 4 || i === 6 ? "num" : "" }, t)))),
    el("tbody", {}, rows.map((e) => el("tr", {},
      el("td", {}, when(e.at)), el("td", {}, e.caller || "—"), el("td", {}, el("code", {}, e.operation)),
      el("td", {}, e.status < 300 ? pill("ok", String(e.status)) : e.status < 500 ? pill("warn", String(e.status)) : pill("bad", String(e.status)), e.detail ? el("div", { class: "muted" }, e.detail) : null),
      el("td", { class: "num" }, fmt(e.total)),
      el("td", {}, el("div", { class: "chips" }, Object.entries(e.counts || {}).map(([k, v]) => el("span", { class: "chip" }, `${k} ${v}`)))),
      el("td", { class: "num" }, fmt(e.duration_ms)))))));
}

async function pageAudit(c) {
  const f = state.ui.audit || (state.ui.audit = { caller: "", operation: "", limit: "100" });
  const who = el("input", { type: "text", placeholder: "Caller address or admin", value: f.caller, "aria-label": "Caller" });
  const op = el("input", { type: "text", placeholder: "Operation, e.g. file_mask", value: f.operation, "aria-label": "Operation" });
  const lim = el("select", { "aria-label": "Rows", value: f.limit }, ["50", "100", "250", "500"].map((n) => el("option", { value: n }, n + " rows")));
  const out = el("div", { class: "card" });
  const load = async () => {
    f.caller = who.value.trim(); f.operation = op.value.trim(); f.limit = lim.value;
    const q = new URLSearchParams({ limit: f.limit });
    if (f.caller) q.set("caller", f.caller);
    if (f.operation) q.set("operation", f.operation);
    try { out.replaceChildren(auditTable(await api("GET", "/v1/admin/audit?" + q))); } catch (e) { fail(e); }
  };
  put(c, head("Audit log", "Every call: who made it, what it did, how many values of each type it hid. Values themselves are never recorded."),
    el("div", { class: "card", style: "margin-bottom:16px" }, el("div", { class: "card-body row" }, el("div", { class: "grow" }, who), el("div", { class: "grow" }, op), lim,
      el("button", { class: "btn primary", type: "button", onclick: load }, "Apply"))), out);
  await load();
}

function markup(s) {
  const re = /<[A-Z][A-Z0-9_]*(?:_[0-9a-f]{8,64})?>/g, parts = [];
  let last = 0, m;
  while ((m = re.exec(s))) { parts.push(s.slice(last, m.index), el("mark", {}, m[0])); last = m.index + m[0].length; }
  parts.push(s.slice(last));
  return parts;
}

// ---- check a document ---------------------------------------------------------------------------------------------------
async function pageCheck(c) {
  const file = el("input", { type: "file", accept: ".pdf,.docx,.pptx,.xlsx,.csv,.txt,.md", "aria-label": "Document to check" });
  const opts = el("textarea", { rows: 3, class: "mono", placeholder: '{"fields": [{"name": "CLIENT_COMPANY_NAME", "terms": ["Globex Retail"]}]}' });
  const result = el("div", {});
  const go = el("button", { class: "btn primary", type: "button" }, "Check document");
  const run = async () => {
    const f = file.files[0];
    if (!f) { toast("Choose a document first.", true); return; }
    let options;
    try { options = opts.value.trim() ? JSON.parse(opts.value) : null; } catch (_) { toast("Options must be valid JSON.", true); return; }
    go.disabled = true; go.textContent = "Checking…";
    result.replaceChildren(el("p", { class: "muted" }, "Reading the document…"));
    try {
      const form = new FormData();
      form.append("file", f);
      if (options) form.append("options", JSON.stringify(options));
      const r = await api("POST", "/v1/admin/check", form);
      result.replaceChildren(...checkResult(r));
    } catch (e) { result.replaceChildren(); fail(e); }
    go.disabled = false; go.textContent = "Check document";
  };
  go.addEventListener("click", run);
  put(c, head("Check a document", "Add a document to see what this service would hide in it, using your current fields and settings. Nothing is stored, and the file is not kept."),
    el("div", { class: "card" }, el("div", { class: "card-body" },
      el("div", { class: "dropzone" }, el("p", { style: "margin-bottom:10px" }, "PDF, Word, PowerPoint, Excel, CSV or text, up to the upload limit"), file),
      el("label", { class: "f", style: "margin-top:16px" }, el("span", { class: "t" }, "Extra options (JSON, optional)"), opts,
        el("span", { class: "h" }, "Try values for just this check, such as a client's name, without saving them as fields.")),
      go)),
    result);
}

function checkResult(r) {
  const out = [];
  const bad = r.protection === "off";
  const kinds = Object.entries(r.counts || {});
  out.push(el("div", { class: "tiles", style: "margin-top:16px" },
    tile("Values that would be hidden", fmt(r.total), kinds.length + " kind(s) of data"),
    tile("File", r.file_type.toUpperCase(), r.file),
    r.pages ? tile("Pages", fmt(r.pages), r.ocr_pages && r.ocr_pages.length ? r.ocr_pages.length + " read with OCR" : "text layer") : null));
  if (r.unprocessed_image_pages && r.unprocessed_image_pages.length)
    out.push(el("div", { class: "callout warn", style: "margin-bottom:12px" }, `Pages ${r.unprocessed_image_pages.join(", ")} are scans and were not read, because OCR is not available. Anything on them is NOT hidden.`));
  if (bad) out.push(el("div", { class: "callout bad", style: "margin-bottom:12px" }, "PII protection is off."));
  out.push(el("div", { class: "card" },
    el("div", { class: "card-head" }, el("div", {}, el("h2", {}, "What was found"), el("p", {}, kinds.length ? "Counts by kind. The values themselves are not shown." : "Nothing matched your current fields and settings.")),
      r.masked_file ? el("button", { class: "btn primary", type: "button", onclick: () => saveMasked(r) }, "Download masked file") : el("span", { class: "muted" }, "Too large to return here: use the masking endpoint.")),
    el("div", { class: "card-body" }, el("div", { class: "chips" }, kinds.map(([k, v]) => el("span", { class: "chip teal" }, `${k} ${v}`))))));
  out.push(el("div", { class: "card" },
    el("div", { class: "card-head" }, el("div", {}, el("h2", {}, "Preview of the masked document"),
      el("p", {}, r.preview_truncated ? "The start of the document. Highlighted labels mark what was hidden." : "Highlighted labels mark what was hidden."))),
    el("div", { class: "card-body" }, el("div", { class: "out" }, ...(r.preview ? markup(r.preview) : ["(No readable text to preview.)"])))));
  return out;
}

function saveMasked(r) {
  const bytes = Uint8Array.from(atob(r.masked_file), (ch) => ch.charCodeAt(0));
  const a = el("a", { href: URL.createObjectURL(new Blob([bytes], { type: r.media_type })), download: r.file.replace(/(\.[^.]+)?$/, ".masked$1") });
  document.body.append(a); a.click(); a.remove();
}

// ---- try it ----------------------------------------------------------------------------------------------------------------
const SAMPLE = "Please contact Rohan at rohan.sharma@gmail.com or +91 98450 12345. PAN BQKPS4821L. Salary: 24,50,000. Client Name: Globex Retail Pvt. Ltd.";

async function pageTry(c) {
  const optsText = el("textarea", { rows: 3, class: "mono", placeholder: '{"threshold": 60, "fields": [{"name": "CLIENT_COMPANY_NAME", "terms": ["Globex Retail"]}]}' });
  const text = el("textarea", { rows: 6 }, SAMPLE);
  const out = el("div", { class: "out", "aria-live": "polite" }, "The result appears here.");
  const meta = el("div", { class: "chips", style: "margin-top:10px" });
  const file = el("input", { type: "file", accept: ".pdf,.docx,.pptx,.xlsx,.csv,.txt,.md", "aria-label": "File" });
  const fileOut = el("div", { style: "margin-top:12px" });

  const parseOpts = () => { const t = optsText.value.trim(); if (!t) return undefined; try { return JSON.parse(t); } catch (_) { throw new Error("Options must be valid JSON."); } };
  const showMeta = (counts, extra) => meta.replaceChildren(...Object.entries(counts || {}).map(([k, v]) => el("span", { class: "chip teal" }, `${k} ${v}`)), ...(extra || []).filter(Boolean));
  const run = async () => {
    try {
      const body = { text: text.value };
      const o = parseOpts();
      if (o) body.options = o;
      const r = await api("POST", "/v1/mask", body);
      out.replaceChildren(...markup(r.text));
      showMeta(r.counts, [r.protection === "off" ? el("span", { class: "callout bad" }, "PII protection is OFF: the text was returned unchanged.") : null,
        r.unknown_tokens ? el("span", { class: "chip" }, r.unknown_tokens + " unknown token(s)") : null]);
    } catch (e) { fail(e); }
  };
  const runFile = async () => {
    if (!file.files[0]) { toast("Choose a file first.", true); return; }
    try {
      const form = new FormData();
      form.append("file", file.files[0]);
      const o = parseOpts();
      if (o) form.append("options", JSON.stringify(o));
      const r = await api("POST", "/v1/files/mask", form, true);
      if (!r.ok) { const d = await r.json().catch(() => null); throw new Error(detailText(d && d.detail) || `Request failed (${r.status}).`); }
      const summary = JSON.parse(r.headers.get("X-PII-Summary") || "{}");
      const blob = await r.blob();
      const name = (r.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/);
      const url = URL.createObjectURL(blob);
      fileOut.replaceChildren(el("div", { class: "callout info" }, `Done: ${fmt(summary.total || 0)} value(s) hidden. `,
        el("a", { class: "btn small primary", href: url, download: name ? name[1] : "result" }, "Download result")),
        el("div", { class: "chips", style: "margin-top:8px" }, Object.entries(summary.counts || {}).map(([k, v]) => el("span", { class: "chip teal" }, `${k} ${v}`)),
          summary.unprocessed_image_pages && summary.unprocessed_image_pages.length ? el("span", { class: "chip" }, "Scanned pages not read: " + summary.unprocessed_image_pages.join(", ")) : null,
          summary.protection === "off" ? el("span", { class: "callout bad" }, "PII protection is OFF: the file was returned unchanged.") : null));
    } catch (e) { fail(e); }
  };
  put(c, head("Try it", "Test your configuration on sample text or a file. Calls appear in the audit log."),
    el("div", { class: "grid cols-2" },
      el("div", { class: "card" }, el("div", { class: "card-head" }, el("h2", {}, "Input")),
        el("div", { class: "card-body" },
          el("label", { class: "f" }, el("span", { class: "t" }, "Text"), text),
          el("label", { class: "f" }, el("span", { class: "t" }, "Options (JSON, optional)"), optsText, el("span", { class: "h" }, "Per-request overrides: types, threshold, mask_names, keywords, allow_list, fields.")),
          el("button", { class: "btn primary", type: "button", onclick: run }, "Run on text"),
          el("hr", { style: "border:0;border-top:1px solid var(--line-soft);margin:18px 0" }),
          el("label", { class: "f" }, el("span", { class: "t" }, "Or a file (PDF, Word, PowerPoint, Excel, CSV, text)"), file),
          el("button", { class: "btn", type: "button", onclick: runFile }, "Run on file"), fileOut)),
      el("div", { class: "card" }, el("div", { class: "card-head" }, el("h2", {}, "Result")), el("div", { class: "card-body" }, out, meta))));
}

const PAGES = { overview: pageOverview, fields: pageFields, detection: pageDetection, audit: pageAudit, check: pageCheck, tryit: pageTry };

// ---- start -----------------------------------------------------------------------------------------------------------------
(async function start() {
  try { await api("GET", "/v1/admin/overview"); renderShell(); } catch (e) { if (e.message !== "Signed out." && e.message) renderLogin(e.message); }
})();
