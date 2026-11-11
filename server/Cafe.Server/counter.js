"use strict";
// Counter screen. Server values only ever go in as text (never HTML), so a name cannot run code here.
const $ = id => document.getElementById(id);
let token = sessionStorage.getItem("cafeToken"); // gone when the browser closes; Windows locks the PC when staff walk away
let rows = [], selected = null, panelKey = "", poll = null;

function el(tag, props = {}, ...kids) {
  const e = Object.assign(document.createElement(tag), props);
  for (const k of kids) if (k != null) e.append(k);
  return e;
}
const rupees = p => "₹" + (p % 100 ? (p / 100).toFixed(2) : p / 100);
const clock = s => { s = Math.max(0, s); const h = Math.floor(s / 3600), m = Math.floor(s / 60) % 60, x = s % 60;
  return (h ? h + ":" + String(m).padStart(2, "0") : m) + ":" + String(x).padStart(2, "0"); };
function say(text, ok = true) { $("msg").textContent = text; $("msg").className = ok ? "ok" : "err"; }

async function api(method, path, body) {
  const r = await fetch(path, { method, headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body) });
  if (r.status === 401) { signOut(); throw new Error("Please sign in again."); }
  const text = await r.text();
  const data = text ? (() => { try { return JSON.parse(text); } catch { return { error: text }; } })() : null;
  if (!r.ok) throw new Error(data?.error || "Something went wrong. Please try again.");
  return data;
}
// every button runs through here: one message line for success or the server's plain-English refusal
const act = (fn, done) => async () => { try { const r = await fn(); if (done) say(typeof done === "function" ? done(r) : done); await refresh(true); } catch (e) { say(e.message, false); } };

function status(r) {
  if (!r.online) return ["Offline", "off"];
  if (r.locked) return ["Locked by staff", "lock"];
  if (r.selfLocked) return ["Locked by customer", "lock"];
  if (r.session && r.paused) return ["Paused", "lock"];
  return r.session ? ["In use", "use"] : ["Free", "free"];
}
const timeText = r => r.session ? (r.leftSec != null ? clock(r.leftSec) + " left" : clock(r.elapsedSec) + " played") : "";

async function refresh(forcePanel = false) {
  try { rows = await api("GET", "/staff/counter"); } catch (e) { say(e.message, false); return; }
  $("pcs").replaceChildren(...rows.map(r => {
    const [label, cls] = status(r);
    return el("button", { className: "pc" + (r.pc === selected ? " sel" : ""), onclick: () => { selected = r.pc; panelKey = ""; refresh(); },
      ariaLabel: `${r.pc}, ${label}` },
      el("b", { textContent: r.pc }), el("span", { className: "chip " + cls, textContent: label }),
      el("div", { textContent: r.customer ?? "" }), el("div", { className: "small", textContent: timeText(r) }),
      r.toPay > 0 ? el("div", { textContent: "To pay " + rupees(r.toPay) }) : null);
  }));
  if (!forcePanel && (panelKey === "bill" || panelKey === "side")) return; // a bill or form is open: keep it
  const r = rows.find(x => x.pc === selected);
  if (!r) { if (forcePanel) $("panel").replaceChildren(el("p", { className: "small", textContent: "Pick a PC to see what you can do." })); return; }
  const key = [r.pc, r.session, r.locked, r.selfLocked, r.paused, r.mode, r.toPay > 0].join("|");
  if (forcePanel || key !== panelKey) { panelKey = key; showPc(r); }
  else if ($("live")) $("live").textContent = liveText(r);
}
const liveText = r => [r.customer, { prepaid: "Paid in advance", postpaid: "Pays at the end", plan: "Plan time" }[r.mode], timeText(r),
  r.toPay > 0 ? "To pay " + rupees(r.toPay) : "Nothing to pay"].filter(Boolean).join(" · ");

function minutesPick(id) {
  return el("select", { id }, ...[30, 60, 90, 120, 150, 180].map(m => el("option", { value: m, textContent: m < 60 ? m + " min" : m / 60 + " h" })));
}
function payForm(session, amount) {
  return el("div", {},
    el("h2", { textContent: "Take payment" }),
    el("label", { htmlFor: "amt", textContent: "Amount in rupees" }), el("input", { id: "amt", inputMode: "decimal", value: amount / 100 }),
    el("label", { htmlFor: "how", textContent: "How" }),
    el("select", { id: "how" }, el("option", { value: "cash", textContent: "Cash" }), el("option", { value: "upi", textContent: "UPI" })),
    el("label", { htmlFor: "last4", textContent: "UPI: last 4 digits of the payment reference" }), el("input", { id: "last4", inputMode: "numeric", maxLength: 4 }),
    el("div", { className: "row" }, el("button", { textContent: "Take payment", onclick: act(() => api("POST", `/staff/sessions/${session}/pay`,
      { method: $("how").value, amount: Math.round(parseFloat($("amt").value) * 100), upiLast4: $("last4").value || null }), "Payment saved.") })));
}

function showPc(r) {
  const [label] = status(r);
  const p = [el("h2", { textContent: `${r.pc} · ${label}` })];
  if (!r.session) {
    p.push(el("h2", { textContent: "Start a session" }),
      el("label", { htmlFor: "phone", textContent: "Customer phone number" }),
      el("div", { className: "row" }, el("input", { id: "phone", inputMode: "numeric" }), el("button", { className: "quiet", textContent: "Find", onclick: find })),
      el("p", { id: "who", className: "small" }),
      el("label", { htmlFor: "mode", textContent: "How they pay" }),
      el("select", { id: "mode", onchange: () => { $("minRow").hidden = $("mode").value !== "prepaid"; } },
        el("option", { value: "prepaid", textContent: "Pay now for set time" }), el("option", { value: "postpaid", textContent: "Pay at the end" }),
        el("option", { value: "plan", textContent: "Use plan or saved time" })),
      el("div", { id: "minRow" }, el("label", { htmlFor: "mins", textContent: "Time" }), minutesPick("mins")),
      el("div", { className: "row" }, el("button", { textContent: "Start", onclick: act(() => api("POST", "/staff/sessions",
        { pc: r.pc, phone: $("phone").value.trim(), mode: $("mode").value, minutes: +$("mins").value }), "Session started.") })),
      el("hr"), el("h2", { textContent: "New customer" }),
      el("label", { htmlFor: "nName", textContent: "Name" }), el("input", { id: "nName" }),
      el("label", { htmlFor: "nPhone", textContent: "Phone number" }), el("input", { id: "nPhone", inputMode: "numeric" }),
      el("label", { htmlFor: "nPin", textContent: "PIN the customer chooses (4 digits or more)" }), el("input", { id: "nPin", inputMode: "numeric", type: "password" }),
      el("div", { className: "row" }, el("button", { className: "quiet", textContent: "Add customer", onclick: act(() => api("POST", "/staff/users",
        { role: 2, name: $("nName").value.trim(), phone: $("nPhone").value.trim(), pin: $("nPin").value }), "Customer added.") })));
  } else {
    p.push(el("p", { id: "live", textContent: liveText(r) }));
    const row = el("div", { className: "row" });
    if (r.mode === "prepaid") p.push(el("label", { htmlFor: "addMins", textContent: "Add time" }),
      el("div", { className: "row" }, minutesPick("addMins"), el("button", { className: "quiet", textContent: "Add time",
        onclick: act(() => api("POST", `/staff/sessions/${r.session}/time`, { minutes: +$("addMins").value }), "Time added.") })));
    row.append(r.paused
      ? el("button", { className: "quiet", textContent: "Resume", onclick: act(() => api("POST", `/staff/sessions/${r.session}/resume`), "Resumed.") })
      : el("button", { className: "quiet", textContent: "Pause", onclick: act(() => api("POST", `/staff/sessions/${r.session}/pause`), "Paused. The time has stopped.") }),
      el("button", { className: "danger", textContent: "Stop and bill", onclick: () => stop(r) }));
    p.push(row);
    if (r.toPay > 0) p.push(el("hr"), payForm(r.session, r.toPay));
  }
  p.push(el("hr")); // locking is used less often, so it comes last
  if (r.locked) p.push(el("div", { className: "row" }, el("button", { textContent: "Unlock", onclick: act(() => api("POST", "/staff/unlock", { pc: r.pc }), "Unlocked.") })));
  else p.push(el("label", { htmlFor: "lockMsg", textContent: "Message on the lock screen (optional)" }), el("input", { id: "lockMsg" }),
    el("div", { className: "row" }, el("button", { className: "quiet", textContent: "Lock this PC",
      onclick: act(() => api("POST", "/staff/lock", { pc: r.pc, message: $("lockMsg").value || null }), "Locked.") })));
  $("panel").replaceChildren(...p);
}
async function find() {
  try { const c = await api("GET", "/staff/customers/" + encodeURIComponent($("phone").value.trim()));
    $("who").textContent = `${c.name} · plan or saved time ${c.planMinutes} min · wallet ${rupees(c.wallet)}`;
  } catch (e) { $("who").textContent = e.message; }
}
async function stop(r) {
  try {
    const b = await api("POST", `/staff/sessions/${r.session}/stop`);
    const due = b.due;
    panelKey = "bill";
    $("panel").replaceChildren(el("h2", { textContent: `${r.pc} · bill` }),
      el("p", { textContent: `${r.customer} played ${b.used.split(".")[0]}. Charged ${rupees(b.charged)}, paid ${rupees(b.paid)}.` }),
      el("p", { textContent: due > 0 ? "To pay now: " + rupees(due) : "Nothing more to pay." }),
      due > 0 ? payForm(b.sessionId, due) : null,
      el("div", { className: "row" }, el("button", { className: "quiet", textContent: "Done", onclick: () => { panelKey = ""; refresh(true); } })));
    say("Session stopped.");
  } catch (e) { say(e.message, false); }
}

function signOut() { sessionStorage.removeItem("cafeToken"); token = null; clearInterval(poll); $("app").hidden = true; $("login").hidden = false; }
function start() { $("login").hidden = true; $("app").hidden = false; refresh(); poll = setInterval(refresh, 3000); }

$("login").onsubmit = async e => {
  e.preventDefault();
  try {
    const r = await fetch("/staff/login", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone: $("lphone").value.trim(), pin: $("lpin").value, code: $("lcode").value.trim() || null }) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { $("lerr").textContent = d.error || (r.status === 429 ? "Too many tries. Wait a minute." : "Could not sign in."); return; }
    token = d.token; sessionStorage.setItem("cafeToken", token); $("lpin").value = $("lcode").value = ""; $("lerr").textContent = ""; start();
  } catch { $("lerr").textContent = "The counter server is not answering."; }
};
$("logout").onclick = async () => { try { await api("POST", "/staff/logout"); } catch { } signOut(); };
$("shiftOpen").onclick = act(() => api("POST", "/staff/shift/open"), "Shift open.");
$("shiftClose").onclick = () => {
  panelKey = "side";
  $("panel").replaceChildren(el("h2", { textContent: "Close shift" }),
    el("label", { htmlFor: "cash", textContent: "Cash counted in the drawer, in rupees" }), el("input", { id: "cash", inputMode: "decimal" }),
    el("div", { className: "row" }, el("button", { textContent: "Close shift", onclick: act(async () => {
      const r = await api("POST", "/staff/shift/close", { counted: Math.round(parseFloat($("cash").value) * 100) });
      panelKey = ""; return r; }, r => `Shift closed. Expected ${rupees(r.expected)}, ` + (r.difference === 0 ? "cash matches." : r.difference < 0 ? `${rupees(-r.difference)} missing.` : `${rupees(r.difference)} extra.`)) }),
      el("button", { className: "quiet", textContent: "Cancel", onclick: () => { panelKey = ""; refresh(true); } })));
};
$("reviewBtn").onclick = async () => {
  try {
    const items = await api("GET", "/staff/review");
    panelKey = "side";
    $("panel").replaceChildren(el("h2", { textContent: "For the owner to review" }),
      items.length ? el("ul", {}, ...items.map(t => el("li", { textContent: t }))) : el("p", { textContent: "Nothing to review." }),
      el("div", { className: "row" }, el("button", { className: "quiet", textContent: "Close", onclick: () => { panelKey = ""; refresh(true); } })));
  } catch (e) { say(e.message, false); }
};
if (token) start(); else $("login").hidden = false;
