"use strict";
// Counter screen. Server values only ever go in as text (never HTML), so a name cannot run code here.
const $ = id => document.getElementById(id);
let token = sessionStorage.getItem("cafeToken"); // gone when the browser closes; Windows locks the PC when staff walk away
let rows = [], selected = null, panelKey = "", poll = null, rate = null; // rate: the card in use, for the time choices

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
  if (r.locked) return [r.session ? "Paused, locked by staff" : "Locked by staff", "lock"];
  if (r.selfLocked) return ["Locked by customer", "lock"];
  return r.session ? ["In use", "use"] : ["Free", "free"];
}
const timeText = r => r.session ? (r.leftSec != null ? clock(r.leftSec) + " left" : clock(r.elapsedSec) + " played") : "";

async function refresh(forcePanel = false) {
  try { rows = await api("GET", "/staff/counter"); } catch (e) { say(e.message, false); return; }
  try {
    const alerts = await api("GET", "/staff/alerts");
    $("alerts").replaceChildren(...alerts.map(a => el("p", { textContent: "Alert: " + a })));
  } catch { $("alerts").replaceChildren(); }
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
  const key = [r.pc, r.session, r.locked, r.selfLocked, r.mode, r.toPay > 0].join("|");
  if (forcePanel || key !== panelKey) { panelKey = key; showPc(r); }
  else if ($("live")) $("live").textContent = liveText(r);
}
const liveText = r => [r.customer, { prepaid: "Paid in advance", postpaid: "Pays at the end", plan: "Plan time" }[r.mode],
  r.happyHour ? "Happy hour: " + r.happyHour : null, r.offer ? "Offer: " + r.offer : null, timeText(r),
  r.toPay > 0 ? "To pay " + rupees(r.toPay) : "Nothing to pay"].filter(Boolean).join(" · ");

const day = iso => new Date(iso).toLocaleDateString("en-IN", { day: "numeric", month: "short" });
const span = m => m < 60 ? m + " min" : Math.floor(m / 60) + " h" + (m % 60 ? " " + m % 60 + " min" : "");
function minutesPick(id) {
  const block = rate?.blockMin ?? 30;
  return el("select", { id }, ...[1, 2, 3, 4, 5, 6].map(n => n * block).map(m => el("option", { value: m, textContent: span(m) })));
}
async function loadRate() { try { rate = (await api("GET", "/staff/rate-cards")).find(c => c.inUse)?.rate ?? null; } catch { } }
// items grouped by list; loaded fresh when a form needs them
async function fillItems(id) {
  const d = await api("GET", "/staff/items");
  $(id)?.replaceChildren(el("option", { value: "", textContent: d.items.length ? "Pick an item" : "No items yet (the owner adds them under Items)" }),
    ...d.categories.filter(c => d.items.some(i => i.category === c)).map(c => el("optgroup", { label: c },
      ...d.items.filter(i => i.category === c).map(i => el("option", { value: i.id, textContent: `${i.name} · ${rupees(i.price)}` })))));
  return d;
}
function itemFields(prefix) {
  return [el("select", { id: prefix + "Item" }, el("option", { value: "", textContent: "Loading items..." })),
    el("div", { className: "row" }, el("input", { id: prefix + "Qty", inputMode: "numeric", value: 1, ariaLabel: "How many", size: 3 }),
      el("input", { id: prefix + "Note", placeholder: "Note (optional), e.g. less sugar", maxLength: 100 }))];
}
function readItem(prefix) {
  const item = +$(prefix + "Item").value, qty = parseInt($(prefix + "Qty").value, 10);
  if (!item) throw new Error("Pick an item.");
  if (!(qty >= 1)) throw new Error("Type how many.");
  return { item, qty, note: $(prefix + "Note").value.trim() || null };
}
const billLines = b => (b.lines ?? []).length ? el("ul", {}, ...b.lines.map(l => el("li", { textContent: `${l.text} · ${l.kind === "pay" ? "" : l.amount < 0 ? "-" : ""}${rupees(Math.abs(l.amount))}` }))) : null;
function payForm(session, amount) {
  return el("div", {},
    el("h2", { textContent: "Take payment" }),
    el("label", { htmlFor: "amt", textContent: "Amount in rupees" }), el("input", { id: "amt", inputMode: "decimal", value: amount / 100 }),
    el("label", { htmlFor: "how", textContent: "How" }),
    el("select", { id: "how" }, el("option", { value: "cash", textContent: "Cash" }), el("option", { value: "upi", textContent: "UPI" })),
    el("label", { htmlFor: "last4", textContent: "UPI: last 4 digits of the payment reference" }), el("input", { id: "last4", inputMode: "numeric", maxLength: 4 }),
    el("div", { className: "row" }, el("button", { textContent: "Take payment", onclick: act(() => {
      const amount = Math.round(parseFloat($("amt").value) * 100);
      if (!(amount > 0)) throw new Error("Type the amount in rupees.");
      return api("POST", `/staff/sessions/${session}/pay`, { method: $("how").value, amount, upiLast4: $("last4").value || null });
    }, "Payment saved.") })));
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
    // to pause, lock the PC below: locking stops the time and unlocking starts it again (a pause alone would leave the PC playable)
    row.append(el("button", { className: "danger", textContent: "Stop and bill", onclick: () => stop(r) }));
    p.push(row);
    if (!r.happyHour && !r.offer) p.push(el("label", { htmlFor: "offerPick", textContent: "Offer (one per bill, not with happy hour)" }),
      el("div", { className: "row" }, el("select", { id: "offerPick" }, el("option", { value: "", textContent: "Loading offers..." })),
        el("button", { className: "quiet", textContent: "Apply offer", onclick: act(() => {
          if (!$("offerPick").value) throw new Error("Pick an offer.");
          return api("POST", `/staff/sessions/${r.session}/offer`, { name: $("offerPick").value });
        }, "Offer applied.") })));
    p.push(el("label", { htmlFor: "sItem", textContent: "Add to the bill (food, drinks, merchandise)" }), ...itemFields("s"),
      el("div", { className: "row" }, el("button", { className: "quiet", textContent: "Add to bill",
        onclick: act(() => api("POST", `/staff/sessions/${r.session}/items`, readItem("s")), "Added to the bill.") })));
    // pay-at-end is charged when it stops, so only time paid in advance can be paid during the session
    if (r.toPay > 0 && r.mode === "prepaid") p.push(el("hr"), payForm(r.session, r.toPay));
  }
  p.push(el("hr")); // locking is used less often, so it comes last
  if (r.locked) p.push(el("div", { className: "row" }, el("button", { textContent: "Unlock", onclick: act(() => api("POST", "/staff/unlock", { pc: r.pc }), r.session ? "Unlocked. The time is running again." : "Unlocked.") })));
  else p.push(el("label", { htmlFor: "lockMsg", textContent: r.session ? "Lock to pause: the time stops until you unlock. Message on the lock screen (optional)" : "Message on the lock screen (optional)" }), el("input", { id: "lockMsg" }),
    el("div", { className: "row" }, el("button", { className: "quiet", textContent: r.session ? "Lock and pause" : "Lock this PC",
      onclick: act(() => api("POST", "/staff/lock", { pc: r.pc, message: $("lockMsg").value || null }), r.session ? "Locked. The time has stopped." : "Locked.") })));
  $("panel").replaceChildren(...p);
  if ($("sItem")) fillItems("sItem").catch(() => { });
  if ($("offerPick")) fillOffers("offerPick", o => !forMembership(o), "Pick an offer");
}
// offers running today, as a picker; the server checks again and says why if one does not fit
const forMembership = o => o.scope?.length > 0 && o.scope.every(x => x.startsWith("Membership: "));
const scopeText = o => o.scope?.length ? o.scope.join(", ") : "whole bill";
function fillOffers(id, keep, first) {
  api("GET", "/staff/offers").then(d => {
    const today = new Date().toLocaleDateString("en-CA"); // yyyy-mm-dd, the PC's own date
    const live = d.offers.filter(o => (!o.from || o.from <= today) && (!o.to || o.to >= today) && keep(o));
    $(id)?.replaceChildren(el("option", { value: "", textContent: live.length ? first : "No offers today" }),
      ...live.map(o => el("option", { value: o.name, textContent: `${o.name} · ${o.percent}% off ${scopeText(o)}${o.membersOnly ? " · members" : ""}` })));
  }).catch(() => { });
}
async function find() {
  try { const c = await api("GET", "/staff/customers/" + encodeURIComponent($("phone").value.trim()));
    $("who").textContent = `${c.name} · ${c.membership ? `${c.membership.plan} member until ${day(c.membership.ends)}` : "not a member"} · saved time ${c.planMinutes} min · wallet ${rupees(c.wallet)}`;
  } catch (e) { $("who").textContent = e.message; }
}
async function stop(r) {
  try {
    const b = await api("POST", `/staff/sessions/${r.session}/stop`);
    const due = b.due;
    panelKey = "bill";
    $("panel").replaceChildren(el("h2", { textContent: `${r.pc} · bill` }),
      el("p", { textContent: `${r.customer} played ${b.used.split(".")[0]}. Charged ${rupees(b.charged)}, paid ${rupees(b.paid)}.` }), billLines(b),
      el("p", { textContent: due > 0 ? "To pay now: " + rupees(due) : "Nothing more to pay." }),
      due > 0 ? payForm(b.sessionId, due) : null,
      el("div", { className: "row" }, el("button", { className: "quiet", textContent: "Done", onclick: () => { panelKey = ""; refresh(true); } })));
    say("Session stopped.");
  } catch (e) { say(e.message, false); }
}

function signOut() { sessionStorage.removeItem("cafeToken"); token = null; clearInterval(poll); $("app").hidden = true; $("login").hidden = false; }
function start() { $("login").hidden = true; $("app").hidden = false; loadRate(); refresh(); poll = setInterval(refresh, 3000); }

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
// Rate cards: everyone sees them, only the owner can change them (the server refuses anyone else).
const RATE_FIELDS = [["blockMin", "Block length in minutes", 1], ["paise30", "Price for 1 block, ₹", 100], ["paise60", "Price for 2 blocks, ₹", 100],
  ["paise90", "Price for 3 blocks, ₹", 100], ["extraBlockPaise", "Each block after that, ₹", 100], ["minimumMin", "Minimum charge in minutes", 1],
  ["graceMin", "Free if they leave within (minutes)", 1], ["blockGraceMin", "Free minutes after each block", 1], ["carryOverDays", "Unused minutes stay valid for (days)", 1]];
async function showRates(pick) {
  try {
    const cards = await api("GET", "/staff/rate-cards");
    const c = cards.find(x => x.name === pick) ?? cards.find(x => x.inUse);
    const run = (fn, msg, next) => async () => {
      const target = typeof next === "function" ? next() : next ?? c.name; // read when clicked, not when drawn
      try { await fn(); await loadRate(); say(msg); showRates(target); } catch (e) { say(e.message, false); }
    };
    const read = () => ({ ...Object.fromEntries(RATE_FIELDS.map(([k, , unit]) => {
      const n = parseFloat($("r_" + k).value);
      if (!Number.isFinite(n)) throw new Error("Fill in every box with a number.");
      return [k, Math.round(n * unit)];
    })), carryOverMembersOnly: $("r_carry").value === "members" });
    panelKey = "side";
    $("panel").replaceChildren(el("h2", { textContent: "Rate cards" }),
      el("div", { className: "row" }, ...cards.map(x => el("button", { className: x.name === c.name ? "" : "quiet", textContent: x.name + (x.inUse ? " (in use)" : ""), onclick: () => showRates(x.name) }))),
      el("hr"), el("label", { htmlFor: "r_name", textContent: "Name (type a new name to make a new card)" }), el("input", { id: "r_name", value: c.name }),
      ...RATE_FIELDS.flatMap(([k, label, unit]) => [el("label", { htmlFor: "r_" + k, textContent: label }), el("input", { id: "r_" + k, inputMode: "decimal", value: c.rate[k] / unit })]),
      el("label", { htmlFor: "r_carry", textContent: "Who keeps unused time" }),
      el("select", { id: "r_carry" }, el("option", { value: "members", textContent: "Members only (until their membership ends)", selected: c.rate.carryOverMembersOnly }),
        el("option", { value: "everyone", textContent: "Everyone (for the days above)", selected: !c.rate.carryOverMembersOnly })),
      el("div", { className: "row" },
        el("button", { textContent: "Save", onclick: run(() => api("POST", "/staff/rate-cards", { name: $("r_name").value.trim(), rate: read() }), "Rate card saved.", () => $("r_name").value.trim()) }),
        c.inUse ? null : el("button", { className: "quiet", textContent: "Put in use", onclick: run(() => api("POST", "/staff/rate-cards/use", { name: c.name }), `"${c.name}" is now in use.`) }),
        c.inUse ? null : el("button", { className: "danger", textContent: "Delete", onclick: run(() => api("DELETE", "/staff/rate-cards/" + encodeURIComponent(c.name)), `"${c.name}" deleted.`, "") }),
        el("button", { className: "quiet", textContent: "Close", onclick: () => { panelKey = ""; refresh(true); } })));
  } catch (e) { say(e.message, false); }
}
$("ratesBtn").onclick = () => showRates();

async function showOwnerSecurity() {
  try {
    const [settings, people, pcs] = await Promise.all([
      api("GET", "/staff/settings/offline-unlock"),
      api("GET", "/staff/offline-unlock-people"),
      api("GET", "/staff/pcs")
    ]);
    panelKey = "side";
    const run = async (fn, message) => {
      try { const result = await fn(); say(typeof message === "function" ? message(result) : message); await showOwnerSecurity(); }
      catch (e) { say(e.message, false); }
    };
    const personOptions = people.map(p => el("option", { value: p.phone, textContent: p.name + " · " + p.phone }));
    $("panel").replaceChildren(
      el("h2", { textContent: "Owner security" }),
      el("p", { className: "small", textContent: "Offline unlock stops working on a PC after seven days without a counter refresh." }),
      el("label", { htmlFor: "offlineMax", textContent: "Most minutes per offline unlock" }),
      el("input", { id: "offlineMax", inputMode: "numeric", value: settings.maxOfflineUnlockMinutes }),
      el("button", { textContent: "Save limit", onclick: () => run(
        () => api("POST", "/staff/settings/offline-unlock", { minutes: parseInt($("offlineMax").value, 10) }),
        r => "Offline unlock limit saved: " + r.maxOfflineUnlockMinutes + " minutes.") }),
      el("hr"),
      el("h3", { textContent: "People allowed to unlock offline" }),
      people.length ? el("ul", {}, ...people.map(p => el("li", {},
        p.name + " · " + p.phone + " · " + (p.HasSecret ?? p.hasSecret
          ? ((p.Enabled ?? p.enabled) ? "offline unlock on" : "offline unlock off")
          : "not set up"),
        p.hasSecret ? el("button", { className: "quiet", textContent: p.enabled ? "Turn off" : "Turn on",
          onclick: () => run(() => api("POST", "/staff/offline-unlock-person", { phone: p.phone, enabled: !p.enabled }),
            p.enabled ? "Offline unlock switched off." : "Offline unlock switched on.") }) : null))) : el("p", { textContent: "No owner or staff accounts yet." }),
      el("hr"),
      el("h3", { textContent: "End counter logins" }),
      el("p", { className: "small", textContent: "End every counter login except the one you are using now." }),
      el("button", { className: "danger", textContent: "End all other logins", onclick: () => run(
        () => api("POST", "/staff/logins/end-others"), r => "Ended " + r.ended + " other counter logins.") }),
      el("label", { htmlFor: "endPerson", textContent: "End every login for one person" }),
      el("select", { id: "endPerson" }, ...personOptions),
      el("button", { className: "danger", textContent: "End this person's logins", disabled: people.length === 0, onclick: () => run(
        () => api("POST", "/staff/logins/end-person", { phone: $("endPerson").value }),
        r => "Ended " + r.ended + " logins for " + $("endPerson").selectedOptions[0].textContent + ".") }),
      el("hr"),
      el("h3", { textContent: "PC keys" }),
      pcs.length ? el("ul", {}, ...pcs.map(pc => el("li", {},
        pc.name + (pc.inUse ? " · in use" : ""),
        el("button", { className: "danger", textContent: "Remove PC", disabled: pc.inUse,
          onclick: () => run(() => api("DELETE", "/staff/pcs/" + encodeURIComponent(pc.name)),
            pc.name + " removed. Add it again to issue a new key.") })))) : el("p", { textContent: "No PCs are registered." }),
      el("label", { htmlFor: "newPcName", textContent: "Add or re-add a PC" }),
      el("input", { id: "newPcName", maxLength: 40, placeholder: "PC name" }),
      el("button", { textContent: "Add PC and show its key", onclick: async () => {
        const name = $("newPcName").value.trim();
        if (!name) { say("Type the PC name.", false); return; }
        try {
          const key = await api("POST", "/staff/pcs", { pc: name });
          $("panel").append(el("p", { textContent: "Save this token now. It is shown only once." }),
            el("pre", { textContent: "PC token: " + key.token + "\nServer pin: " + key.pin }));
          say("New PC key created. Copy it into that PC's install setup.");
        } catch (e) { say(e.message, false); }
      } }),
      el("button", { className: "quiet", textContent: "Close", onclick: () => { panelKey = ""; refresh(true); } }));
  } catch (e) { say(e.message, false); }
}
$("ownerSecurityBtn").onclick = () => showOwnerSecurity();

// Memberships: the owner sets the plans, staff sell them at the counter. One membership at a time per customer.
async function showMembers(pick) {
  try {
    const plans = await api("GET", "/staff/membership-plans");
    const p = plans.find(x => x.name === pick) ?? plans[0] ?? { name: "Monthly", days: 30, price: 0 };
    const run = (fn, msg, next) => async () => {
      const target = typeof next === "function" ? next() : next ?? p.name;
      try { const r = await fn(); say(typeof msg === "function" ? msg(r) : msg); showMembers(target); } catch (e) { say(e.message, false); }
    };
    const num = id => { const n = parseFloat($(id).value); if (!Number.isFinite(n)) throw new Error("Fill in every box with a number."); return n; };
    panelKey = "side";
    $("panel").replaceChildren(el("h2", { textContent: "Sell a membership" }),
      el("label", { htmlFor: "m_phone", textContent: "Customer phone number" }), el("input", { id: "m_phone", inputMode: "numeric" }),
      el("label", { htmlFor: "m_plan", textContent: "Membership" }),
      el("select", { id: "m_plan" }, ...plans.map(x => el("option", { value: x.name, textContent: `${x.name} · ${x.days} days · ${rupees(x.price)}` }))),
      el("label", { htmlFor: "m_offer", textContent: "Offer" }), el("select", { id: "m_offer" }),
      el("label", { htmlFor: "m_how", textContent: "How" }),
      el("select", { id: "m_how" }, el("option", { value: "cash", textContent: "Cash" }), el("option", { value: "upi", textContent: "UPI" })),
      el("label", { htmlFor: "m_last4", textContent: "UPI: last 4 digits of the payment reference" }), el("input", { id: "m_last4", inputMode: "numeric", maxLength: 4 }),
      el("div", { className: "row" }, el("button", { textContent: "Sell", disabled: !plans.length, onclick: run(() => api("POST", "/staff/memberships",
        { phone: $("m_phone").value.trim(), plan: $("m_plan").value, method: $("m_how").value, upiLast4: $("m_last4").value || null, offer: $("m_offer").value || null }), r => `Member until ${day(r.ends)}.`) })),
      el("hr"), el("h2", { textContent: "Membership plans (owner)" }),
      el("div", { className: "row" }, ...plans.map(x => el("button", { className: x.name === p.name ? "" : "quiet", textContent: x.name, onclick: () => showMembers(x.name) }))),
      el("label", { htmlFor: "m_name", textContent: "Name (type a new name to make a new plan)" }), el("input", { id: "m_name", value: p.name }),
      el("label", { htmlFor: "m_days", textContent: "Days it lasts" }), el("input", { id: "m_days", inputMode: "numeric", value: p.days }),
      el("label", { htmlFor: "m_price", textContent: "Price, ₹" }), el("input", { id: "m_price", inputMode: "decimal", value: p.price / 100 }),
      el("div", { className: "row" },
        el("button", { textContent: "Save plan", onclick: run(() => api("POST", "/staff/membership-plans",
          { name: $("m_name").value.trim(), days: Math.round(num("m_days")), price: Math.round(num("m_price") * 100) }), "Membership plan saved.", () => $("m_name").value.trim()) }),
        plans.some(x => x.name === p.name) ? el("button", { className: "danger", textContent: "Delete plan",
          onclick: run(() => api("DELETE", "/staff/membership-plans/" + encodeURIComponent(p.name)), `"${p.name}" deleted. Members who paid keep their time.`, "") }) : null,
        el("button", { className: "quiet", textContent: "Close", onclick: () => { panelKey = ""; refresh(true); } })));
    fillOffers("m_offer", o => o.scope?.some(x => x.startsWith("Membership: ")), "No offer");
  } catch (e) { say(e.message, false); }
}
$("membersBtn").onclick = () => showMembers();

// Offers: the owner sets happy hours (a rate card for set days and times) and named offers (% off, members only, dates).
const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const hhmm = m => String(Math.floor(m / 60)).padStart(2, "0") + ":" + String(m % 60).padStart(2, "0");
const mins = id => { const [h, m] = ($(id).value || "").split(":").map(Number); if (!Number.isFinite(h) || !Number.isFinite(m)) throw new Error("Fill in both times."); return h * 60 + m; };
async function showOffers() {
  try {
    const [d, cards, items, plans] = await Promise.all([api("GET", "/staff/offers"), api("GET", "/staff/rate-cards"), api("GET", "/staff/items"), api("GET", "/staff/membership-plans")]);
    const block = rate?.blockMin ?? 30;
    const groups = [["Play time", ["Play time", "Pay at the end", "Extra time", ...[1, 2, 3, 4, 5, 6].map(n => `Package: ${n * block} min`)]],
      ["Item lists", items.categories.map(c => "List: " + c)], ["Single items", items.items.map(i => `Item: ${i.category} / ${i.name}`)],
      ["Memberships", plans.map(p => "Membership: " + p.name)]].filter(g => g[1].length);
    const scopes = groups.flatMap(g => g[1]);
    const short = x => x === "Play time" ? "All play time" : x.replace(/^Package: (.*)$/, "$1 package").replace(/^(List|Item|Membership): /, "");
    const run = (fn, msg) => async () => { try { await fn(); say(msg); showOffers(); } catch (e) { say(e.message, false); } };
    const check = (id, label, checked = false) => el("label", { className: "check" }, el("input", { type: "checkbox", id, checked }), label);
    panelKey = "side";
    $("panel").replaceChildren(el("h2", { textContent: "Happy hours" }),
      el("p", { className: "small", textContent: "A visit that starts inside the time is billed on that rate card to the end. No offer can be added on top." }),
      d.happyHours.length ? el("ul", {}, ...d.happyHours.map(h => el("li", {}, `${h.card} · ${h.days.map(x => DAYS[x - 1]).join(" ")} · ${hhmm(h.fromMin)}-${hhmm(h.toMin)}${h.membersOnly ? " · members" : ""} `,
        el("button", { className: "quiet", textContent: "Delete", onclick: run(() => api("DELETE", "/staff/happy-hours/" + h.id), "Happy hour deleted.") })))) : el("p", { textContent: "No happy hours yet." }),
      el("label", { htmlFor: "h_card", textContent: "Rate card" }), el("select", { id: "h_card" }, ...cards.map(c => el("option", { value: c.name, textContent: c.name }))),
      el("div", { className: "row" }, ...DAYS.map((x, i) => check("h_d" + (i + 1), x, i < 5))),
      el("div", { className: "row" }, el("div", {}, el("label", { htmlFor: "h_from", textContent: "From" }), el("input", { id: "h_from", type: "time", value: "11:00" })),
        el("div", {}, el("label", { htmlFor: "h_to", textContent: "To" }), el("input", { id: "h_to", type: "time", value: "15:00" }))),
      check("h_members", "Members only"),
      el("div", { className: "row" }, el("button", { textContent: "Add happy hour", onclick: run(() => api("POST", "/staff/happy-hours", {
        card: $("h_card").value, days: DAYS.map((_, i) => i + 1).filter(n => $("h_d" + n).checked), fromMin: mins("h_from"), toMin: mins("h_to"), membersOnly: $("h_members").checked }), "Happy hour added.") })),
      el("hr"), el("h2", { textContent: "Offers" }),
      el("p", { className: "small", textContent: "Staff put one offer on a bill. It takes the % off the parts of the bill you tick, or the whole bill." }),
      d.offers.length ? el("ul", {}, ...d.offers.map(o => el("li", {}, `${o.name} · ${o.percent}% off ${scopeText(o)}${o.membersOnly ? " · members" : ""}${o.from || o.to ? ` · ${o.from ?? "..."} to ${o.to ?? "..."}` : ""} `,
        el("button", { className: "quiet", textContent: "Delete", onclick: run(() => api("DELETE", "/staff/offers/" + encodeURIComponent(o.name)), "Offer deleted.") })))) : el("p", { textContent: "No offers yet." }),
      el("label", { htmlFor: "o_name", textContent: "Name (an existing name changes that offer)" }), el("input", { id: "o_name" }),
      el("label", { htmlFor: "o_pct", textContent: "Discount, %" }), el("input", { id: "o_pct", inputMode: "numeric" }),
      check("o_members", "Members only"),
      el("label", { textContent: "Takes % off (tick nothing for the whole bill of a visit or counter sale)" }),
      ...groups.map(([title, list]) => el("div", {}, el("div", { className: "small", textContent: title }),
        el("div", { className: "row" }, ...list.map(x => check("o_s" + scopes.indexOf(x), short(x)))))),
      el("div", { className: "row" }, el("div", {}, el("label", { htmlFor: "o_from", textContent: "From (optional)" }), el("input", { id: "o_from", type: "date" })),
        el("div", {}, el("label", { htmlFor: "o_to", textContent: "To (optional)" }), el("input", { id: "o_to", type: "date" }))),
      el("div", { className: "row" }, el("button", { textContent: "Save offer", onclick: run(() => {
          const percent = parseInt($("o_pct").value, 10);
          if (!Number.isFinite(percent)) throw new Error("Type the discount in %.");
          return api("POST", "/staff/offers", { name: $("o_name").value.trim(), percent, membersOnly: $("o_members").checked, from: $("o_from").value || null, to: $("o_to").value || null,
            scope: scopes.filter((_, i) => $("o_s" + i).checked) });
        }, "Offer saved.") }),
        el("button", { className: "quiet", textContent: "Close", onclick: () => { panelKey = ""; refresh(true); } })));
  } catch (e) { say(e.message, false); }
}
$("offersBtn").onclick = () => showOffers();
if (token) start(); else $("login").hidden = false;

// Items: staff sell at the counter; the owner keeps the lists and prices and sees what sold today.
async function showItems() {
  try {
    const d = await api("GET", "/staff/items");
    const run = (fn, msg) => async () => { try { const r = await fn(); say(typeof msg === "function" ? msg(r) : msg); showItems(); } catch (e) { say(e.message, false); } };
    const today = new Date().toLocaleDateString("en-CA");
    panelKey = "side";
    $("panel").replaceChildren(el("h2", { textContent: "Counter sale (not on a PC)" }), ...itemFields("c"),
      el("label", { htmlFor: "c_offer", textContent: "Offer" }), el("select", { id: "c_offer" }),
      el("label", { htmlFor: "c_how", textContent: "How" }),
      el("select", { id: "c_how" }, el("option", { value: "cash", textContent: "Cash" }), el("option", { value: "upi", textContent: "UPI" })),
      el("label", { htmlFor: "c_last4", textContent: "UPI: last 4 digits of the payment reference" }), el("input", { id: "c_last4", inputMode: "numeric", maxLength: 4 }),
      el("div", { className: "row" }, el("button", { textContent: "Sell", onclick: run(() => api("POST", "/staff/counter-sales",
        { ...readItem("c"), method: $("c_how").value, upiLast4: $("c_last4").value || null, offer: $("c_offer").value || null }), r => `Sold. ${rupees(r.amount)} taken.`) })),
      el("div", { id: "report" }),
      el("hr"), el("h2", { textContent: "Lists and prices (owner)" }),
      ...d.categories.map(c => el("div", {}, el("h3", { textContent: c }),
        el("ul", {}, ...d.items.filter(i => i.category === c).map(i => el("li", {}, `${i.name} · ${rupees(i.price)} `,
          el("button", { className: "quiet", textContent: "Delete", onclick: run(() => api("DELETE", "/staff/items/" + i.id), `"${i.name}" deleted.`) })))),
        d.items.some(i => i.category === c) ? null : el("button", { className: "quiet", textContent: `Delete the list "${c}"`,
          onclick: run(() => api("DELETE", "/staff/item-categories/" + encodeURIComponent(c)), `"${c}" deleted.`) }))),
      el("label", { htmlFor: "i_cat", textContent: "List" }), el("select", { id: "i_cat" }, ...d.categories.map(c => el("option", { value: c, textContent: c }))),
      el("label", { htmlFor: "i_name", textContent: "Item name (an existing name changes its price)" }), el("input", { id: "i_name", maxLength: 40 }),
      el("label", { htmlFor: "i_price", textContent: "Price, ₹" }), el("input", { id: "i_price", inputMode: "decimal" }),
      el("div", { className: "row" }, el("button", { textContent: "Save item", onclick: run(() => {
        const price = Math.round(parseFloat($("i_price").value) * 100);
        if (!(price > 0)) throw new Error("Type the price in rupees.");
        return api("POST", "/staff/items", { category: $("i_cat").value, name: $("i_name").value.trim(), price });
      }, "Item saved.") })),
      el("label", { htmlFor: "i_new", textContent: "New list (for example Combos)" }), el("input", { id: "i_new", maxLength: 30 }),
      el("div", { className: "row" }, el("button", { className: "quiet", textContent: "Add list", onclick: run(() => api("POST", "/staff/item-categories", { name: $("i_new").value.trim() }), "List added.") }),
        el("button", { className: "quiet", textContent: "Close", onclick: () => { panelKey = ""; refresh(true); } })));
    fillItems("cItem").catch(() => { });
    fillOffers("c_offer", o => !forMembership(o), "No offer");
    // only the owner may see the report; staff simply do not get this part
    api("GET", `/staff/reports/items?from=${today}&to=${today}`).then(rows => $("report")?.replaceChildren(el("hr"), el("h2", { textContent: "Sold today (before offers)" }),
      rows.length ? el("ul", {}, ...rows.map(x => el("li", { textContent: `${x.category} · ${x.item} · ${x.qty} sold · ${rupees(x.amount)}` }))) : el("p", { textContent: "Nothing sold yet today." }))).catch(() => { });
  } catch (e) { say(e.message, false); }
}
$("itemsBtn").onclick = () => showItems();
