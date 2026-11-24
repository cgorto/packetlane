"use strict";
// One page, no build step, no libraries. State lives in S; every change ends
// in draw() and, when the view moved, a debounced fetch.

const $ = (id) => document.getElementById(id);
const token = new URLSearchParams(location.search).get("t") || "";
const ROW = 22;
const ITEM_LIMIT = 1500;
const COLORS = { tm: "#5aa9ff", tc: "#ffb454", log: "#9ad17a", other: "#b48ef0",
  problem: "#ff5d5d", info: "#6fb3ff", hit: "#ffd84a", line: "#2a2f38", dim: "#8a919e", text: "#d7dae0" };
const TIME_KEY = { receive: "receive", packet: "packetTime", order: "order" };

const S = {
  runs: [], run: null, meta: null, clock: "receive", view: [0, 1],
  dens: null, items: null, over: null, rows: [], hidden: new Set(), pinned: new Set(),
  sel: null, finding: null, hits: [], q: "", tab: "problems", drag: null, measure: null,
  focus: 0, seq: 0, runSeq: 0, askSeq: 0, cwd: null,
};

// ---- server ----------------------------------------------------------------

async function api(path, params, body) {
  const qs = params ? "?" + new URLSearchParams(params) : "";
  const init = { headers: { "X-Packetlane-Token": token } };
  if (body) { init.method = "POST"; init.body = JSON.stringify(body); }
  const res = await fetch("/api/" + path + qs, init);
  const data = await res.json().catch(() => ({ error: String(res.status) }));
  if (!res.ok) throw new Error(data.error || String(res.status));
  return data;
}

// ---- time ------------------------------------------------------------------

const clockInfo = () => (S.meta ? S.meta.clocks[S.clock] : null);
const origin = () => BigInt((clockInfo() && clockInfo().origin) || "0");
const pad = (n, w) => String(n).padStart(w, "0");

function absParts(t) {
  const ns = origin() + BigInt(Math.round(t));
  let ms = ns / 1000000n, sub = ns % 1000000n;
  if (sub < 0n) { sub += 1000000n; ms -= 1n; }
  return { d: new Date(Number(ms)), sub: Number(sub) };
}

// A time on the current clock as text. `step` is the tick spacing in ns and
// sets how much precision is worth showing.
function formatTime(t, step) {
  if (S.clock === "order") return "#" + (Math.round(t) || 0).toLocaleString("en-US");
  const { d, sub } = absParts(t);
  const hms = pad(d.getUTCHours(), 2) + ":" + pad(d.getUTCMinutes(), 2) + ":" + pad(d.getUTCSeconds(), 2);
  const day = pad(d.getUTCMonth() + 1, 2) + "-" + pad(d.getUTCDate(), 2);
  if (step >= 86400e9) return day;
  if (step >= 3600e9) return d.getUTCHours() === 0 ? day : pad(d.getUTCHours(), 2) + ":00";
  if (step >= 1e9) return hms;
  if (step >= 1e6) return hms + "." + pad(d.getUTCMilliseconds(), 3);
  return hms + "." + pad(d.getUTCMilliseconds(), 3) + pad(Math.floor(sub / 1000), 3);
}

function formatSpan(ns) {
  const a = Math.abs(ns);
  if (S.clock === "order") return Math.round(a).toLocaleString("en-US");
  if (a >= 3600e9) return (a / 3600e9).toFixed(2) + " h";
  if (a >= 60e9) return (a / 60e9).toFixed(2) + " min";
  if (a >= 1e9) return (a / 1e9).toFixed(3) + " s";
  if (a >= 1e6) return (a / 1e6).toFixed(3) + " ms";
  return (a / 1e3).toFixed(1) + " µs";
}

function tickStep(span, width) {
  const target = span / Math.max(2, width / 110);
  const units = S.clock === "order" ? [1] : [1e3, 1e6, 1e9, 60e9, 3600e9, 86400e9];
  const decimal = [1, 2, 5, 10, 20, 50, 100, 200, 500], sixty = [1, 2, 5, 10, 15, 30], hours = [1, 2, 3, 6, 12];
  let best = 86400e9 * 3650;
  for (const u of units) for (const m of u === 1e9 || u === 60e9 ? sixty : u === 3600e9 ? hours : u === 86400e9 ? [1, 2, 5, 10, 30, 100, 365] : decimal) {
    const s = u * m;
    if (s >= target && s < best) best = s;
  }
  if (S.clock === "order") { let s = 1; while (s < target && s < 1e15) s *= 10; return s; }
  return best;
}

// ---- layout ----------------------------------------------------------------

const laneColor = (l) => l.kind === "log" ? COLORS.log : l.kind === "other" ? COLORS.other : l.command ? COLORS.tc : COLORS.tm;
const apidText = (a) => String(a);

function laneName(l) {
  if (l.kind === "log") return l.file.split("/").pop();
  if (l.kind === "other") return "Other";
  return l.name || apidText(l.apid);
}
function laneSub(l) {
  if (l.kind !== "packet") return "";
  return (l.name ? apidText(l.apid) : "") + (l.command ? " TC" : "");
}

function layout() {
  S.rows = [];
  if (!S.meta) return;
  const usable = S.meta.lanes.filter((l) => l[S.clock] && !S.hidden.has(l.id));
  const pinned = usable.filter((l) => S.pinned.has(l.id));
  for (const lane of pinned) S.rows.push({ lane });
  let source = null;
  for (const lane of usable) {
    if (S.pinned.has(lane.id)) continue;
    if (lane.source !== source) { source = lane.source; S.rows.push({ group: source }); }
    S.rows.push({ lane });
  }
  S.rows.forEach((r, i) => { r.y = i * ROW; });

  const q = S.q.toLowerCase();
  const labels = $("labels");
  labels.textContent = "";
  for (const r of S.rows) {
    const div = document.createElement("div");
    if (r.group !== undefined) {
      div.className = "group";
      div.textContent = r.group;
    } else {
      const l = r.lane;
      const label = (laneName(l) + " " + laneSub(l) + " " + l.source).toLowerCase();
      div.className = "lane" + (S.pinned.has(l.id) ? " pinned" : "") + (q && label.includes(q) ? " match" : "");
      const dot = document.createElement("span");
      dot.className = "dot";
      dot.style.background = laneColor(l);
      const name = document.createElement("span");
      name.className = "name";
      name.textContent = laneName(l);
      const sub = document.createElement("span");
      sub.className = "sub";
      sub.textContent = laneSub(l) + (S.pinned.has(l.id) ? " " + l.source : "");
      const count = document.createElement("span");
      count.className = "count";
      count.textContent = l.count.toLocaleString("en-US");
      const pin = document.createElement("button");
      pin.textContent = S.pinned.has(l.id) ? "●" : "○";
      pin.setAttribute("aria-label", S.pinned.has(l.id) ? "Unpin" : "Pin");
      pin.onclick = () => { toggle(S.pinned, l.id); layout(); draw(); saveHash(); };
      const hide = document.createElement("button");
      hide.textContent = "✕";
      hide.setAttribute("aria-label", "Hide");
      hide.onclick = () => { S.hidden.add(l.id); layout(); draw(); saveHash(); };
      div.append(dot, name, sub, count, pin, hide);
    }
    labels.append(div);
  }
  const unhide = $("unhide");
  unhide.hidden = S.hidden.size === 0;
  unhide.textContent = "+" + S.hidden.size;
  sizeCanvases();
}

function toggle(set, v) { if (set.has(v)) set.delete(v); else set.add(v); }

function fitCanvas(canvas, cssHeight) {
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth;
  if (cssHeight !== undefined) canvas.style.height = cssHeight + "px";
  const h = cssHeight !== undefined ? cssHeight : canvas.clientHeight;
  canvas.width = Math.max(1, Math.round(w * dpr));
  canvas.height = Math.max(1, Math.round(h * dpr));
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, w, h };
}

let G = { tl: null, axis: null, over: null };
function sizeCanvases() {
  G.tl = fitCanvas($("tl"), Math.max(ROW, S.rows.length * ROW));
  G.axis = fitCanvas($("axis"));
  G.over = fitCanvas($("over"));
}

const X = (t) => (t - S.view[0]) / (S.view[1] - S.view[0]) * G.tl.w;
const T = (x) => S.view[0] + x / G.tl.w * (S.view[1] - S.view[0]);

// ---- drawing ---------------------------------------------------------------

function draw() {
  if (!G.tl) return;
  drawAxis();
  drawLanes();
  drawOverview();
}

function drawAxis() {
  const { ctx, w, h } = G.axis;
  ctx.clearRect(0, 0, w, h);
  if (!S.meta) return;
  const span = S.view[1] - S.view[0];
  const step = tickStep(span, w);
  ctx.fillStyle = COLORS.dim;
  ctx.strokeStyle = COLORS.line;
  ctx.font = "11px system-ui, sans-serif";
  ctx.textBaseline = "middle";
  if (!(step > 0) || span / step > 2000) return;
  const first = Math.ceil(S.view[0] / step) * step;
  // Ticks sit on round values of the clock itself, not of the offset.
  const shift = S.clock === "order" ? 0 : Number(origin() % BigInt(Math.max(1, Math.round(step))));
  for (let t = first - shift; t <= S.view[1]; t += step) {
    const x = X(t);
    if (x < -60) continue;
    ctx.beginPath(); ctx.moveTo(x + 0.5, h - 5); ctx.lineTo(x + 0.5, h); ctx.stroke();
    ctx.fillText(formatTime(t, step), x + 4, h / 2 - 1);
  }
  if (S.clock === "order") { $("date").textContent = ""; return; }
  const d = absParts(S.view[0] + span / 2).d;
  $("date").textContent = d.getUTCFullYear() + "-" + pad(d.getUTCMonth() + 1, 2) + "-" + pad(d.getUTCDate(), 2) + " UTC";
}

function drawLanes() {
  const { ctx, w, h } = G.tl;
  ctx.clearRect(0, 0, w, h);
  if (!S.meta) return;
  const dens = S.dens, items = S.items;
  let peak = 1;
  if (dens) for (const id in dens.lanes) for (const b of dens.lanes[id]) if (b[1] > peak) peak = b[1];

  for (const r of S.rows) {
    ctx.fillStyle = COLORS.line;
    ctx.fillRect(0, r.y + ROW - 0.5, w, 0.5);
    if (!r.lane) continue;
    const l = r.lane, color = laneColor(l);
    ctx.fillStyle = color;
    const lane = items && items.lanes[l.id];
    if (items) {
      if (lane) for (const it of lane) {
        const x = X(it.t);
        if (x < -2 || x > w + 2) continue;
        if (l.kind === "log") {
          ctx.beginPath(); ctx.moveTo(x, r.y + 5); ctx.lineTo(x + 4, r.y + 11); ctx.lineTo(x, r.y + 17); ctx.lineTo(x - 4, r.y + 11); ctx.fill();
        } else ctx.fillRect(x - 1, r.y + 4, 2, ROW - 8);
      }
    } else if (dens && dens.lanes[l.id]) {
      const bw = Math.max(1.5, X(dens.width) - X(0));
      for (const [b, c] of dens.lanes[l.id]) {
        const x = X(dens.from + b * dens.width);
        if (x + bw < 0 || x > w) continue;
        const bar = Math.max(2, Math.log1p(c) / Math.log1p(peak) * (ROW - 5));
        ctx.globalAlpha = 0.35 + 0.65 * Math.log1p(c) / Math.log1p(peak);
        ctx.fillRect(x, r.y + ROW - 2 - bar, bw, bar);
      }
      ctx.globalAlpha = 1;
    }
  }

  const rowOf = new Map(S.rows.filter((r) => r.lane).map((r) => [r.lane.id, r]));
  for (const hit of S.hits) {
    const r = rowOf.get(hit.lane);
    if (!r || hit.t === null) continue;
    ctx.fillStyle = COLORS.hit;
    ctx.beginPath(); ctx.arc(X(hit.t), r.y + 4, 3, 0, 7); ctx.fill();
  }
  for (const f of S.meta.findings) {
    const r = rowOf.get(f.lane), t = f[TIME_KEY[S.clock]];
    if (!r || t === null || t === undefined) continue;
    const x = X(t);
    if (x < -8 || x > w + 8) continue;
    ctx.fillStyle = f.severity === "problem" ? COLORS.problem : COLORS.info;
    ctx.beginPath(); ctx.moveTo(x - 5, r.y + 1); ctx.lineTo(x + 5, r.y + 1); ctx.lineTo(x, r.y + 9); ctx.fill();
    if (S.finding === f.id) { ctx.strokeStyle = COLORS.text; ctx.lineWidth = 1.5; ctx.stroke(); ctx.lineWidth = 1; }
  }
  if (S.sel && rowOf.has(S.sel.lane) && S.sel.t !== null) {
    const r = rowOf.get(S.sel.lane), x = X(S.sel.t);
    ctx.strokeStyle = COLORS.text;
    ctx.lineWidth = 1.5;
    ctx.strokeRect(x - 4, r.y + 2, 8, ROW - 4);
    ctx.lineWidth = 1;
  }
  const band = S.drag && (S.drag.mode === "zoom" || S.drag.mode === "measure") ? S.drag : S.measure;
  if (band) {
    const a = X(band.t0), b = X(band.t1);
    ctx.fillStyle = band.mode === "zoom" ? "#5aa9ff33" : "#ffd84a22";
    ctx.fillRect(Math.min(a, b), 0, Math.abs(b - a), h);
    if (band.mode === "measure") {
      ctx.fillStyle = COLORS.hit;
      ctx.font = "12px system-ui, sans-serif";
      ctx.textBaseline = "top";
      const top = $("scroll").scrollTop + 4;
      ctx.fillText(formatSpan(band.t1 - band.t0), Math.min(a, b) + 4, top);
    }
  }
}

function drawOverview() {
  const { ctx, w, h } = G.over;
  ctx.clearRect(0, 0, w, h);
  const info = clockInfo();
  if (!info || info.span === null) return;
  const span = Math.max(1, info.span);
  const ox = (t) => t / span * w;
  if (S.over) {
    let peak = 1;
    for (const c of S.over.sum) if (c > peak) peak = c;
    ctx.fillStyle = "#4a5364";
    const bw = Math.max(1, ox(S.over.width));
    S.over.sum.forEach((c, b) => {
      if (!c) return;
      const bar = Math.max(1, Math.log1p(c) / Math.log1p(peak) * (h - 6));
      ctx.fillRect(ox(S.over.from + b * S.over.width), h - bar, bw, bar);
    });
  }
  for (const f of S.meta.findings) {
    const t = f[TIME_KEY[S.clock]];
    if (t === null || t === undefined || f.severity !== "problem") continue;
    ctx.fillStyle = COLORS.problem;
    ctx.fillRect(ox(t) - 1, 0, 2, 5);
  }
  const a = Math.max(0, ox(S.view[0])), b = Math.min(w, ox(S.view[1]));
  ctx.fillStyle = "#ffffff18";
  ctx.fillRect(a, 0, Math.max(2, b - a), h);
  ctx.strokeStyle = COLORS.dim;
  ctx.strokeRect(a + 0.5, 0.5, Math.max(2, b - a) - 1, h - 1);
}

// ---- data ------------------------------------------------------------------

let fetchTimer = 0;
// Keeps the view finite, no narrower than a few packets could need and no
// wider than a small multiple of the run, wherever it was set from.
function clampView() {
  const info = clockInfo();
  const span = info && info.span !== null ? Math.max(1, info.span) : 1;
  let [a, b] = S.view;
  if (!Number.isFinite(a) || !Number.isFinite(b) || b <= a) { a = -span * 0.02; b = span * 1.02; }
  const min = S.clock === "order" ? 4 : 2000, max = Math.max(span * 20, min);
  const width = Math.min(Math.max(b - a, min), max);
  const mid = Math.min(Math.max((a + b) / 2, -max), span + max);
  S.view = [mid - width / 2, mid + width / 2];
}

function viewChanged() {
  clampView();
  S.seq++;
  draw();
  clearTimeout(fetchTimer);
  fetchTimer = setTimeout(loadView, 70);
  saveHash();
}

function windowParams() {
  const from = Math.floor(S.view[0]), to = Math.max(from + 1, Math.ceil(S.view[1]));
  return { run: S.run, clock: S.clock, origin: clockInfo().origin || "0", from, to };
}

async function loadView() {
  const info = clockInfo();
  if (!S.meta || !info || info.origin === null) { S.dens = S.items = null; draw(); return; }
  const seq = ++S.seq;
  const p = windowParams();
  try {
    const dens = await api("density", { ...p, buckets: Math.max(50, Math.floor(G.tl.w / 3)) });
    if (seq !== S.seq) return;
    S.dens = dens;
    if (dens.total <= ITEM_LIMIT) {
      const raw = await api("items", { ...p, limit: ITEM_LIMIT + 500 });
      if (seq !== S.seq) return;
      const lanes = {};
      for (const [id, lane, t, count, length] of raw.packets) (lanes[lane] = lanes[lane] || []).push({ kind: "p", id, lane, t, count, length });
      for (const [id, lane, t, text] of raw.logs) (lanes[lane] = lanes[lane] || []).push({ kind: "l", id, lane, t, text });
      S.items = raw.truncated ? null : { lanes };
    } else S.items = null;
    draw();
    if (S.focus > 0 && !S.items) {
      // Jumping to a finding: keep closing in until single packets show.
      S.focus--;
      const mid = (S.view[0] + S.view[1]) / 2, half = (S.view[1] - S.view[0]) / 8;
      S.view = [mid - half, mid + half];
      viewChanged();
    } else S.focus = 0;
  } catch (e) { /* a newer request replaces this one */ }
}

async function loadOverview() {
  const info = clockInfo();
  S.over = null;
  if (!info || info.origin === null) return;
  const run = S.run, clock = S.clock;
  const d = await api("density", { run, clock, origin: info.origin, from: 0, to: Math.max(1, info.span), buckets: Math.max(50, Math.floor(G.over.w)) });
  if (run !== S.run || clock !== S.clock) return;
  const sum = [];
  for (const id in d.lanes) for (const [b, c] of d.lanes[id]) sum[b] = (sum[b] || 0) + c;
  S.over = { from: d.from, width: d.width, sum: Array.from(sum, (v) => v || 0) };
  drawOverview();
}

function fit() {
  const info = clockInfo();
  const span = info && info.span !== null ? Math.max(1, info.span) : 1;
  S.view = [-span * 0.02, span * 1.02];
  S.focus = 0;
  viewChanged();
}

async function loadRuns(select) {
  S.runs = (await api("runs")).runs;
  const el = $("run");
  el.textContent = "";
  for (const r of S.runs) {
    const o = document.createElement("option");
    o.value = r.id;
    o.textContent = r.root;
    el.append(o);
  }
  el.hidden = S.runs.length === 0;
  if (S.runs.length === 0) { S.meta = null; layout(); draw(); renderProblems(); openFiles(); return; }
  const want = select && S.runs.some((r) => r.id === select) ? select : S.runs[0].id;
  await loadRun(want);
}

async function loadRun(id, keep) {
  const mine = ++S.runSeq;
  S.seq++;
  S.run = id;
  $("run").value = id;
  const meta = await api("run", { run: id });
  if (mine !== S.runSeq) return;
  S.meta = meta;
  S.sel = null; S.finding = null; S.dens = null; S.items = null; S.measure = null;
  if (!keep) {
    S.hidden.clear(); S.pinned.clear();
    const c = S.meta.clocks;
    S.clock = ["receive", "packet", "order"].reduce((a, b) => (c[b].count > c[a].count ? b : a), "receive");
  }
  setClock(S.clock, keep);
  renderProblems();
  if (S.q) runSearch();
}

function setClock(clock, keepView) {
  S.clock = clock;
  for (const b of $("clock").children) {
    b.classList.toggle("on", b.dataset.clock === clock);
    b.disabled = !S.meta || S.meta.clocks[b.dataset.clock].count === 0;
  }
  S.dens = null; S.items = null; S.measure = null;
  layout();
  loadOverview().catch(() => {});
  if (keepView) viewChanged(); else fit();
}

// ---- side panel ------------------------------------------------------------

function setTab(tab) {
  if (!["problems", "detail", "hits"].includes(tab)) tab = "problems";
  S.tab = tab;
  for (const b of $("tabs").children) b.classList.toggle("on", b.dataset.tab === tab);
  for (const id of ["problems", "detail", "hits"]) $(id).classList.toggle("on", id === tab);
}

function listItem(color, title, text, where, onclick) {
  const div = document.createElement("div");
  div.className = "item";
  const dot = document.createElement("span");
  dot.className = "dot";
  dot.style.background = color;
  const body = document.createElement("div");
  if (title) { const b = document.createElement("b"); b.textContent = title; body.append(b); }
  const t = document.createElement("div");
  t.className = "text";
  t.textContent = text;
  const w = document.createElement("div");
  w.className = "where";
  w.textContent = where;
  body.append(t, w);
  div.append(dot, body);
  div.onclick = onclick;
  return div;
}

function renderProblems() {
  const pane = $("problems");
  pane.textContent = "";
  const list = S.meta ? S.meta.findings : [];
  $("n-problems").textContent = list.filter((f) => f.severity === "problem").length || "";
  const lanes = new Map((S.meta ? S.meta.lanes : []).map((l) => [l.id, l]));
  for (const f of list) {
    const l = lanes.get(f.lane);
    const title = l ? laneName(l) + (l.kind === "packet" && l.name ? " " + apidText(l.apid) : "") : "";
    const where = [l ? l.source : "", f.file].filter(Boolean).join(" · ");
    const div = listItem(f.severity === "problem" ? COLORS.problem : COLORS.info, title, f.message, where, () => jumpFinding(f));
    div.classList.toggle("on", S.finding === f.id);
    div.dataset.id = f.id;
    pane.append(div);
  }
}

function jumpTo(t, lane) {
  if (t === null || t === undefined) return;
  const info = clockInfo();
  const span = Math.min(S.view[1] - S.view[0], Math.max(1, info.span) / 50);
  S.view = [t - span / 2, t + span / 2];
  S.focus = 6;
  if (lane !== undefined && lane !== null && S.hidden.delete(lane)) layout();
  viewChanged();
  const row = S.rows.find((r) => r.lane && r.lane.id === lane);
  if (row) { const sc = $("scroll"); if (row.y < sc.scrollTop || row.y > sc.scrollTop + sc.clientHeight - ROW) sc.scrollTop = Math.max(0, row.y - 60); }
}

function jumpFinding(f) {
  S.finding = f.id;
  for (const d of $("problems").children) d.classList.toggle("on", Number(d.dataset.id) === f.id);
  const t = f[TIME_KEY[S.clock]];
  jumpTo(t, f.lane);
  if (f.packet !== null && t !== null && t !== undefined) select({ kind: "p", id: f.packet, lane: f.lane, t }, true);
  else draw();
  saveHash();
}

function stepFinding(dir) {
  const list = S.meta ? S.meta.findings.filter((f) => f[TIME_KEY[S.clock]] !== null) : [];
  if (!list.length) return;
  const i = list.findIndex((f) => f.id === S.finding);
  jumpFinding(list[(i + dir + list.length) % list.length]);
}

const short = (iso) => (iso ? iso.replace("T", " ").replace(/(\.\d{6})\d{3}Z$/, "$1") : "");

function kv(rows) {
  const table = document.createElement("table");
  for (const [k, v, cls] of rows) {
    if (v === null || v === undefined || v === "") continue;
    const tr = table.insertRow();
    tr.insertCell().textContent = k;
    const td = tr.insertCell();
    td.className = "v";
    if (Array.isArray(v)) {
      td.append(v[0] + " ");
      const s = document.createElement("span"); s.className = "lbl"; s.textContent = v[1]; td.append(s);
    } else td.textContent = v;
    if (cls) td.classList.add(cls);
  }
  return table;
}

function hexDump(hex) {
  const lines = [];
  for (let i = 0; i < hex.length; i += 32) {
    const chunk = hex.slice(i, i + 32);
    const bytes = chunk.match(/../g) || [];
    const ascii = bytes.map((b) => { const c = parseInt(b, 16); return c >= 32 && c < 127 ? String.fromCharCode(c) : "."; }).join("");
    lines.push(pad((i / 2).toString(16), 4) + "  " + bytes.join(" ").padEnd(47) + "  " + ascii);
  }
  return lines.join("\n");
}

async function select(item, keepTab) {
  S.sel = item;
  draw();
  saveHash();
  const pane = $("detail");
  try {
    if (item.kind === "p") {
      const p = await api("packet", { id: item.id });
      if (S.sel !== item) return;
      pane.textContent = "";
      const h = document.createElement("h2");
      h.textContent = p.name || (p.apid !== null ? apidText(p.apid) : p.label || "Other");
      pane.append(h);
      if (p.fields.length) pane.append(kv(p.fields.map((f) => [f.name, f.error ? f.error : f.label ? [String(f.value), f.label] : String(f.value) + (f.unit ? " " + f.unit : ""), f.error ? "error" : ""])));
      pane.append(kv([
        ["Receive", short(p.receive)], ["Packet", short(p.packet)],
        ["APID", p.apid !== null ? apidText(p.apid) + (p.command ? " TC" : "") : ""],
        ["Sequence count", p.count], ["Length", p.length], ["Label", p.label],
        ["Source", p.source], ["File", p.file], ["Offset", "0x" + p.offset.toString(16)], ["Index", p.index],
      ]));
      if (p.error) { const e = document.createElement("div"); e.className = "error"; e.textContent = p.error; pane.append(e); }
      if (p.hex) { const pre = document.createElement("pre"); pre.className = "hex"; pre.textContent = hexDump(p.hex); pane.append(pre); }
    } else {
      const g = await api("log", { id: item.id });
      if (S.sel !== item) return;
      pane.textContent = "";
      pane.append(kv([["Time", short(g.time)], ["Source", g.source], ["File", g.file], ["Offset", "0x" + g.offset.toString(16)]]));
      const pre = document.createElement("pre");
      pre.textContent = g.text;
      pane.append(pre);
    }
    if (!keepTab) setTab("detail");
  } catch (e) {
    if (S.sel !== item) return;
    pane.textContent = "";
    const d = document.createElement("div"); d.className = "error"; d.textContent = e.message; pane.append(d);
  }
}

// ---- search ----------------------------------------------------------------

let searchTimer = 0;
async function runSearch() {
  layout(); draw();
  const pane = $("hits");
  pane.textContent = "";
  S.hits = [];
  $("n-hits").textContent = "";
  const info = clockInfo();
  if (S.q && info && S.clock !== "order" && info.origin !== null) {
    const q = S.q, run = S.run, clock = S.clock;
    try {
      const res = await api("search", { run: S.run, origin: info.origin, q });
      if (q !== S.q || run !== S.run || clock !== S.clock) return;
      S.hits = res.logs.map(([id, lane, t, text]) => ({ id, lane, t, text }));
      $("n-hits").textContent = S.hits.length + (res.truncated ? "+" : "") || "";
      const lanes = new Map(S.meta.lanes.map((l) => [l.id, l]));
      for (const hit of S.hits) {
        const l = lanes.get(hit.lane);
        pane.append(listItem(COLORS.hit, hit.t === null ? "" : formatTime(hit.t, 1e6), hit.text, l ? l.source + " · " + l.file : "", () => {
          jumpTo(hit.t, hit.lane);
          select({ kind: "l", id: hit.id, lane: hit.lane, t: hit.t });
        }));
      }
      if (S.hits.length) setTab("hits");
    } catch (e) { /* leave the list empty */ }
  }
  draw();
  saveHash();
}

// ---- pointer ---------------------------------------------------------------

function rowAt(y) { return S.rows[Math.floor(y / ROW)]; }

function itemAt(x, y) {
  const r = rowAt(y);
  if (!r || !r.lane || !S.items) return null;
  const lane = S.items.lanes[r.lane.id];
  if (!lane) return null;
  let best = null, dist = 7;
  for (const it of lane) { const d = Math.abs(X(it.t) - x); if (d < dist) { dist = d; best = it; } }
  return best;
}

function findingAt(x, y) {
  const r = rowAt(y);
  if (!r || !r.lane || !S.meta) return null;
  for (const f of S.meta.findings) {
    const t = f[TIME_KEY[S.clock]];
    if (f.lane === r.lane.id && t !== null && t !== undefined && Math.abs(X(t) - x) < 7 && y - r.y < 11) return f;
  }
  return null;
}

function showTip(e, text) {
  const tip = $("tip");
  tip.hidden = !text;
  if (!text) return;
  tip.textContent = text;
  tip.style.left = Math.min(e.clientX + 12, innerWidth - tip.offsetWidth - 8) + "px";
  tip.style.top = e.clientY + 14 + "px";
}

function pos(e, el) { const b = el.getBoundingClientRect(); return [e.clientX - b.left, e.clientY - b.top]; }

function wirePointer() {
  const tl = $("tl");
  tl.addEventListener("wheel", (e) => {
    e.preventDefault();
    const [x] = pos(e, tl);
    const span = S.view[1] - S.view[0];
    if (Math.abs(e.deltaX) > Math.abs(e.deltaY)) {
      const dt = e.deltaX / G.tl.w * span;
      S.view = [S.view[0] + dt, S.view[1] + dt];
    } else {
      const k = Math.exp(e.deltaY * 0.0015), t = T(x);
      const next = Math.max(span * k, S.clock === "order" ? 4 : 2000);
      S.view = [t - (t - S.view[0]) * next / span, t + (S.view[1] - t) * next / span];
    }
    S.focus = 0;
    viewChanged();
  }, { passive: false });

  tl.addEventListener("pointerdown", (e) => {
    const [x, y] = pos(e, tl);
    tl.setPointerCapture(e.pointerId);
    const mode = e.shiftKey ? "zoom" : e.altKey || e.ctrlKey || e.metaKey ? "measure" : "pan";
    S.drag = { mode, x, y, t0: T(x), t1: T(x), view: S.view.slice(), moved: false };
    S.measure = null;
  });
  tl.addEventListener("pointermove", (e) => {
    const [x, y] = pos(e, tl);
    const d = S.drag;
    if (d) {
      if (Math.abs(x - d.x) > 3) d.moved = true;
      if (d.mode === "pan") {
        const dt = (x - d.x) / G.tl.w * (d.view[1] - d.view[0]);
        S.view = [d.view[0] - dt, d.view[1] - dt];
        S.focus = 0;
        viewChanged();
      } else { d.t1 = T(x); draw(); }
      showTip(e, "");
      return;
    }
    const f = findingAt(x, y), it = f ? null : itemAt(x, y), r = rowAt(y);
    tl.style.cursor = f || it ? "pointer" : "grab";
    let text = "";
    const step = (S.view[1] - S.view[0]) / 400;
    if (f) text = f.message;
    else if (it) text = formatTime(it.t, 1) + (it.kind === "p" ? (it.count !== null ? "  #" + it.count : "") + "  " + it.length + " B" : "\n" + it.text);
    else if (r && r.lane) text = formatTime(T(x), step);
    showTip(e, text);
  });
  tl.addEventListener("pointerup", (e) => {
    const d = S.drag;
    S.drag = null;
    if (!d) return;
    const [x, y] = pos(e, tl);
    if (d.mode === "zoom" && d.moved) {
      S.view = [Math.min(d.t0, d.t1), Math.max(d.t0, d.t1)];
      S.focus = 0;
      viewChanged();
    } else if (d.mode === "measure" && d.moved) {
      S.measure = { mode: "measure", t0: d.t0, t1: d.t1 };
      draw();
    } else if (!d.moved) {
      const f = findingAt(x, y), it = f ? null : itemAt(x, y);
      if (f) { setTab("problems"); jumpFinding(f); }
      else if (it) select(it);
      else draw();
    }
  });
  tl.addEventListener("pointerleave", (e) => showTip(e, ""));
  tl.addEventListener("dblclick", fit);

  const over = $("over");
  const moveTo = (e) => {
    const info = clockInfo();
    if (!info || info.span === null) return;
    const [x] = pos(e, over);
    const t = x / G.over.w * Math.max(1, info.span), half = (S.view[1] - S.view[0]) / 2;
    S.view = [t - half, t + half];
    S.focus = 0;
    viewChanged();
  };
  over.addEventListener("pointerdown", (e) => { over.setPointerCapture(e.pointerId); over.dataset.down = "1"; moveTo(e); });
  over.addEventListener("pointermove", (e) => { if (over.dataset.down) moveTo(e); });
  over.addEventListener("pointerup", () => { delete over.dataset.down; });

  $("scroll").addEventListener("scroll", () => { if (S.measure || S.drag) draw(); });
}

function wireKeys() {
  addEventListener("keydown", (e) => {
    if (e.target.matches("input, textarea, select") || document.querySelector("dialog[open]")) {
      if (e.key === "Escape" && e.target.id === "search") { e.target.value = ""; S.q = ""; runSearch(); e.target.blur(); }
      return;
    }
    const span = S.view[1] - S.view[0], mid = (S.view[0] + S.view[1]) / 2;
    const zoom = (k) => { S.view = [mid - span * k / 2, mid + span * k / 2]; S.focus = 0; viewChanged(); };
    const pan = (k) => { S.view = [S.view[0] + span * k, S.view[1] + span * k]; S.focus = 0; viewChanged(); };
    if (e.key === "ArrowLeft") pan(-0.2);
    else if (e.key === "ArrowRight") pan(0.2);
    else if (e.key === "+" || e.key === "=") zoom(0.5);
    else if (e.key === "-") zoom(2);
    else if (e.key === "0" || e.key === "f") fit();
    else if (e.key === "n") stepFinding(1);
    else if (e.key === "p") stepFinding(-1);
    else if (e.key === "/") { $("search").focus(); e.preventDefault(); }
    else if (e.key === "Escape") { S.sel = null; S.measure = null; S.finding = null; renderProblems(); draw(); saveHash(); }
  });
}

// ---- files -----------------------------------------------------------------

const sizeText = (n) => n >= 1e9 ? (n / 1e9).toFixed(1) + " GB" : n >= 1e6 ? (n / 1e6).toFixed(1) + " MB" : n >= 1e3 ? (n / 1e3).toFixed(1) + " kB" : n + " B";

async function browse(path) {
  $("files-error").textContent = "";
  try {
    const mine = ++S.askSeq;
    const res = await api("browse", path ? { path } : null);
    if (mine !== S.askSeq) return;
    S.cwd = res;
    $("cwd").textContent = res.path || "";
    $("up").disabled = res.path === null;
    const list = $("entries");
    list.textContent = "";
    for (const en of res.entries) {
      const row = document.createElement("label");
      row.className = "entry" + (en.dir ? " dir" : "");
      const box = document.createElement("input");
      box.type = "checkbox";
      box.value = en.path;
      box.disabled = !en.dir && (en.format === "unknown" || en.format === "gzip" || en.format === "empty");
      const name = document.createElement("span");
      name.className = "name";
      name.textContent = en.name + (en.dir ? "/" : "");
      if (en.dir) name.onclick = (ev) => { ev.preventDefault(); browse(en.path); };
      const format = document.createElement("span");
      format.className = "meta";
      format.textContent = en.dir ? "" : en.format || "";
      const size = document.createElement("span");
      size.className = "meta";
      size.textContent = en.dir ? "" : sizeText(en.size);
      const done = document.createElement("span");
      done.className = "meta done";
      done.textContent = en.ingested ? "✓ " + (en.packets + en.entries).toLocaleString("en-US") : "";
      row.append(box, name, format, size, done);
      list.append(row);
    }
  } catch (e) { $("files-error").textContent = e.message; }
}

function openFiles() {
  if (!$("files").open) $("files").showModal();
  browse(S.cwd && S.cwd.path);
}

async function ingestSelected() {
  let paths = [...$("entries").querySelectorAll("input:checked")].map((b) => b.value);
  if (!paths.length && S.cwd && S.cwd.path) paths = [S.cwd.path];
  if (!paths.length) return;
  const button = $("ingest");
  button.disabled = true;
  button.classList.add("busy");
  $("files-error").textContent = "";
  try {
    const res = await api("ingest", null, { paths });
    const failed = res.files.filter((f) => f.status === "not_readable" && f.note);
    if (failed.length) $("files-error").textContent = failed.map((f) => f.rel + ": " + f.note).join("\n");
    else $("files").close();
    await loadRuns(res.run);
    if (failed.length) browse(S.cwd.path);
  } catch (e) { $("files-error").textContent = e.message; }
  button.disabled = false;
  button.classList.remove("busy");
}

// ---- SQL -------------------------------------------------------------------

async function runSql() {
  const out = $("sql-result"), err = $("sql-error");
  err.textContent = "";
  out.textContent = "";
  try {
    const mine = ++S.askSeq;
    const res = await api("query", null, { sql: $("sql-text").value });
    if (mine !== S.askSeq) return;
    const table = document.createElement("table");
    const head = table.createTHead().insertRow();
    for (const c of res.columns) { const th = document.createElement("th"); th.textContent = c; head.append(th); }
    const body = table.createTBody();
    for (const r of res.rows) { const tr = body.insertRow(); for (const v of r) tr.insertCell().textContent = v === null ? "" : v; }
    out.append(table);
    if (res.truncated) err.textContent = "1000+";
  } catch (e) { err.textContent = e.message; }
}

// ---- query builder ---------------------------------------------------------
// Fills the SQL box from a few choices, so common questions need no typing.
// The text stays editable, and it runs on the same read-only connection.

const TABLES = {
  Packets: { view: "packet_view", cols: ["source", "file", "apid", "type", "seq", "length", "receive_time", "packet_time", "label", "idx", "offset"] },
  Logs: { view: "log_view", cols: ["source", "file", "log_time", "text"] },
  Problems: { view: "finding_view", cols: ["severity", "kind", "source", "apid", "file", "message"] },
  Files: { view: "file_view", cols: ["source", "file", "format", "size", "packets", "entries", "note"] },
};
const OPS = { "=": "=", "\u2260": "<>", ">": ">", "<": "<", "\u2265": ">=", "\u2264": "<=", "\u220b": "like" };
const SORT_AS = { receive_time: "receive_ns", packet_time: "packet_ns", log_time: "log_ns" };
const Q = { table: "Packets", filters: [], sort: "", desc: false, limit: 100 };

function sqlValue(v) {
  return /^-?\d+(\.\d+)?$/.test(v) ? v : "'" + v.replace(/'/g, "''") + "'";
}

function buildSql() {
  const t = TABLES[Q.table];
  const where = [];
  const run = S.runs.find((r) => r.id === S.run);
  if (run) where.push("run = " + sqlValue(run.root));
  for (const f of Q.filters) {
    if (f.value === "" || !t.cols.includes(f.col)) continue;
    if (OPS[f.op] === "like") where.push(f.col + " like '%" + f.value.replace(/[\\%_]/g, "\\$&").replace(/'/g, "''") + "%' escape '\\'");
    else where.push(f.col + " " + OPS[f.op] + " " + sqlValue(f.value));
  }
  const limit = Math.min(1000, Math.max(1, Math.round(Number(Q.limit)) || 100));
  return "select " + t.cols.join(", ") + "\nfrom " + t.view
    + (where.length ? "\nwhere " + where.join("\n  and ") : "")
    + "\norder by " + (t.cols.includes(Q.sort) ? (SORT_AS[Q.sort] || Q.sort) + (Q.desc ? " desc" : "") + ", " : "") + "id"
    + "\nlimit " + limit;
}

function option(select, text) {
  const o = document.createElement("option");
  o.textContent = text;
  select.append(o);
}

function renderBuilder() {
  const t = TABLES[Q.table];
  const sort = $("qb-sort");
  sort.textContent = "";
  option(sort, "");
  for (const c of t.cols) option(sort, c);
  sort.value = t.cols.includes(Q.sort) ? Q.sort : "";
  $("qb-desc").classList.toggle("on", Q.desc);
  const box = $("qb-filters");
  box.textContent = "";
  Q.filters.forEach((f, i) => {
    const row = document.createElement("span");
    row.className = "qb-filter";
    const col = document.createElement("select");
    col.setAttribute("aria-label", "Column");
    for (const c of t.cols) option(col, c);
    col.value = t.cols.includes(f.col) ? f.col : (f.col = t.cols[0]);
    col.onchange = () => { f.col = col.value; syncSql(); };
    const op = document.createElement("select");
    op.setAttribute("aria-label", "Operator");
    for (const o in OPS) option(op, o);
    op.value = f.op;
    op.onchange = () => { f.op = op.value; syncSql(); };
    const value = document.createElement("input");
    value.setAttribute("aria-label", "Value");
    value.value = f.value;
    value.oninput = () => { f.value = value.value; syncSql(); };
    value.onkeydown = (e) => { if (e.key === "Enter") runSql(); };
    const drop = document.createElement("button");
    drop.textContent = "\u2715";
    drop.setAttribute("aria-label", "Remove filter");
    drop.onclick = () => { Q.filters.splice(i, 1); renderBuilder(); };
    row.append(col, op, value, drop);
    box.append(row);
  });
  syncSql();
}

function syncSql() { $("sql-text").value = buildSql(); }

function openSql() {
  if (!$("qb-table").options.length) for (const name in TABLES) option($("qb-table"), name);
  $("qb-table").value = Q.table;
  renderBuilder();
  if (!$("sql").open) $("sql").showModal();
}

function wireBuilder() {
  $("qb-table").onchange = (e) => { Q.table = e.target.value; Q.filters = []; Q.sort = ""; renderBuilder(); };
  $("qb-add").onclick = () => { Q.filters.push({ col: TABLES[Q.table].cols[0], op: "=", value: "" }); renderBuilder(); };
  $("qb-sort").onchange = (e) => { Q.sort = e.target.value; syncSql(); };
  $("qb-desc").onclick = () => { Q.desc = !Q.desc; $("qb-desc").classList.toggle("on", Q.desc); syncSql(); };
  $("qb-limit").oninput = (e) => { Q.limit = e.target.value; syncSql(); };
}

// ---- address ---------------------------------------------------------------

let hashTimer = 0;
function saveHash() {
  clearTimeout(hashTimer);
  hashTimer = setTimeout(() => {
    const p = new URLSearchParams();
    if (S.run !== null) p.set("run", S.run);
    p.set("clock", S.clock);
    p.set("from", Math.round(S.view[0]));
    p.set("to", Math.round(S.view[1]));
    if (S.hidden.size) p.set("hide", [...S.hidden].join("."));
    if (S.pinned.size) p.set("pin", [...S.pinned].join("."));
    if (S.sel) p.set("sel", S.sel.kind + S.sel.id + "." + S.sel.lane + "." + Math.round(S.sel.t));
    if (S.finding !== null) p.set("finding", S.finding);
    if (S.q) p.set("q", S.q);
    if (S.tab !== "problems") p.set("tab", S.tab);
    history.replaceState(null, "", location.pathname + location.search + "#" + p);
  }, 200);
}

async function restore() {
  const p = new URLSearchParams(location.hash.slice(1));
  const ids = (k) => new Set((p.get(k) || "").split(".").map(Number).filter((n) => S.meta && S.meta.lanes.some((l) => l.id === n)));
  await loadRuns(Number(p.get("run")) || undefined);
  if (!S.meta || !p.has("clock")) return;
  S.hidden = ids("hide");
  S.pinned = ids("pin");
  const clock = p.get("clock");
  if (S.meta.clocks[clock] && S.meta.clocks[clock].count) S.clock = clock;
  const from = Number(p.get("from")), to = Number(p.get("to"));
  const hasView = p.has("from") && p.has("to") && Number.isFinite(from) && Number.isFinite(to) && to > from;
  if (hasView) S.view = [from, to];
  setClock(S.clock, hasView);
  if (p.get("q")) { S.q = p.get("q"); $("search").value = S.q; await runSearch(); }
  if (p.has("finding")) { S.finding = Number(p.get("finding")); renderProblems(); }
  const sel = /^([pl])(\d+)\.(\d+)\.(-?\d+)$/.exec(p.get("sel") || "");
  if (sel) await select({ kind: sel[1], id: Number(sel[2]), lane: Number(sel[3]), t: Number(sel[4]) }, true);
  if (p.get("tab")) setTab(p.get("tab"));
  if (p.get("dialog") === "files") { if (p.get("path")) S.cwd = { path: p.get("path") }; openFiles(); }
  if (p.get("dialog") === "sql") { openSql(); runSql(); }
  draw();
}

// ---- start -----------------------------------------------------------------

function start() {
  setTab("problems");
  wirePointer();
  wireKeys();
  $("run").onchange = (e) => loadRun(Number(e.target.value));
  for (const b of $("clock").children) b.onclick = () => setClock(b.dataset.clock);
  for (const b of $("tabs").children) b.onclick = () => { setTab(b.dataset.tab); saveHash(); };
  $("fit").onclick = fit;
  $("unhide").onclick = () => { S.hidden.clear(); layout(); draw(); saveHash(); };
  $("search").oninput = (e) => {
    S.q = e.target.value.trim();
    clearTimeout(searchTimer);
    searchTimer = setTimeout(runSearch, 250);
  };
  $("open-files").onclick = openFiles;
  $("up").onclick = () => browse(S.cwd && S.cwd.parent);
  $("ingest").onclick = ingestSelected;
  $("open-sql").onclick = openSql;
  wireBuilder();
  $("run-sql").onclick = runSql;
  $("sql-text").onkeydown = (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) runSql(); };
  for (const b of document.querySelectorAll("[data-close]")) b.onclick = () => b.closest("dialog").close();
  new ResizeObserver(() => { sizeCanvases(); draw(); clearTimeout(fetchTimer); fetchTimer = setTimeout(() => { loadView(); loadOverview().catch(() => {}); }, 120); }).observe($("stage"));
  sizeCanvases();
  restore().catch((e) => { document.body.textContent = e.message; });
}

start();
