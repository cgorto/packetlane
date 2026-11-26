#!/usr/bin/env node
// Drives the page in a headless Chrome through what a person does while
// looking at a run (open, zoom, pan, plots, hover, jump to a problem,
// search) and reports, for each, how long the page took to settle and how
// long it ever kept the main thread busy.
//
// Needs Node 22 or later and Chrome or Chromium. No packages.
//
//   packetlane serve --db store.db --root <run folder>      (prints a URL)
//   node tools/ui-load.js '<that URL>' [--run N] [--chrome /path/to/chrome]
//                                      [--budget ms] [--shot file.png]
//
// --run     which run to open, when the store holds several
// --budget  exit with status 1 if any step keeps the main thread busy for
//           longer than this in one go (default: only report)
//
// Headless Chrome draws without a graphics card, so drawing times here are
// on the slow side of what a person sees. Times to settle include the
// server's answers.

'use strict';
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const args = process.argv.slice(2);
const flag = (name) => { const i = args.indexOf('--' + name); return i < 0 ? null : args.splice(i, 2)[1]; };
const runId = flag('run');
const budget = Number(flag('budget')) || null;
const shot = flag('shot');
const chromePath = flag('chrome') || ['google-chrome', 'chromium', 'chromium-browser', 'chrome'].find((name) =>
  (process.env.PATH || '').split(path.delimiter).some((dir) => fs.existsSync(path.join(dir, name))));
const url = args[0];
if (!url || !chromePath) {
  console.error(url ? 'No Chrome found on PATH; give one with --chrome' : 'Usage: node tools/ui-load.js <page URL> [--run N] [--chrome path] [--budget ms] [--shot file.png]');
  process.exit(2);
}

const WIDTH = 1600, HEIGHT = 900;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Runs in the page before its own script: counts requests in flight and
// records every stretch of 50 ms or more in which the page could not respond.
const PROBE = `(() => {
  const L = window.__load = { inflight: 0, started: 0, lastChange: performance.now(), long: [], draws: [] };
  const real = window.fetch;
  window.fetch = function (...a) {
    L.inflight++; L.started++; L.lastChange = performance.now();
    const done = () => { L.inflight--; L.lastChange = performance.now(); };
    return real.apply(this, a).then((r) => {
      // The answer is not in hand until its body is read.
      const body = r.json.bind(r);
      r.json = () => body().finally(done);
      const text = r.text.bind(r);
      r.text = () => text().finally(done);
      return r;
    }, (e) => { done(); throw e; });
  };
  new PerformanceObserver((list) => { for (const e of list.getEntries()) L.long.push(e.duration); }).observe({ entryTypes: ['longtask'] });
})()`;

// Runs once the page's script is in: times every redraw of the timeline
// and of each plot.
const WRAP_DRAW = `(() => {
  for (const name of ['draw', 'drawPlot']) {
    const real = window[name];
    if (typeof real !== 'function') continue;
    window[name] = function (...a) {
      const t = performance.now();
      try { return real.apply(this, a); } finally { window.__load.draws.push(performance.now() - t); }
    };
  }
})()`;

(async () => {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'packetlane-ui-'));
  const chrome = spawn(chromePath, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
    `--window-size=${WIDTH},${HEIGHT}`, '--no-first-run', '--no-default-browser-check', '--disable-extensions', 'about:blank'],
  { stdio: ['ignore', 'ignore', 'pipe'] });
  // Chrome goes on writing to its profile for a moment after it is told to
  // stop, so stop it outright and try the removal more than once.
  const cleanup = () => { try { chrome.kill('SIGKILL'); } catch (e) { /* gone already */ } try { fs.rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 }); } catch (e) { /* leave it */ } };
  process.on('exit', cleanup);

  // Chrome prints the port it chose.
  const port = await new Promise((resolve, reject) => {
    let text = '';
    chrome.stderr.on('data', (d) => { text += d; const m = /DevTools listening on ws:\/\/[^:]+:(\d+)\//.exec(text); if (m) resolve(m[1]); });
    chrome.on('exit', () => reject(new Error('Chrome exited before it was ready:\n' + text)));
    setTimeout(() => reject(new Error('Chrome did not start in 20 s')), 20000);
  });
  const target = (await (await fetch(`http://127.0.0.1:${port}/json`)).json()).find((t) => t.type === 'page');
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((r) => (ws.onopen = r));
  let id = 0; const waiting = new Map(); const errors = [];
  ws.onmessage = (m) => {
    const d = JSON.parse(m.data);
    if (d.id && waiting.has(d.id)) { waiting.get(d.id)(d.result || d.error); waiting.delete(d.id); }
    if (d.method === 'Runtime.exceptionThrown') errors.push(d.params.exceptionDetails.exception?.description || d.params.exceptionDetails.text);
  };
  const send = (method, params = {}) => new Promise((r) => { waiting.set(++id, r); ws.send(JSON.stringify({ id, method, params })); });
  const ev = async (expression) => {
    const r = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error(expression.slice(0, 80) + ': ' + (r.exceptionDetails.exception?.description || r.exceptionDetails.text));
    return r.result?.value;
  };
  const mouse = (type, x, y, extra = {}) => send('Input.dispatchMouseEvent', { type, x, y, button: 'none', ...extra });

  await send('Runtime.enable');
  await send('Page.enable');
  await send('Emulation.setDeviceMetricsOverride', { width: WIDTH, height: HEIGHT, deviceScaleFactor: 1, mobile: false });
  await send('Page.addScriptToEvaluateOnNewDocument', { source: PROBE });

  // Settled: nothing in flight, nothing asked for or answered in the last
  // 400 ms (the page waits up to 250 ms after an input before it asks), and
  // a frame drawn since.
  const settle = async (since) => {
    const limit = Date.now() + 120000;
    for (;;) {
      const quiet = await ev(`(() => { const L = window.__load; return L ? (L.inflight === 0 ? performance.now() - L.lastChange : -1) : -1; })()`);
      if (quiet >= 400) break;
      if (Date.now() > limit) throw new Error('The page did not settle in two minutes');
      await sleep(25);
    }
    await ev(`new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)))`);
    // When the last answer landed, on the page's own clock.
    return (await ev(`window.__load.lastChange`)) - since;
  };

  const rows = [];
  // Runs one step: `act` makes the input and returns nothing; the time to
  // settle is counted from when the input ended.
  const step = async (name, act) => {
    await ev(`(() => { const L = window.__load; L.long = []; L.draws = []; L.started0 = L.started; })()`);
    const began = Date.now();
    await act();
    const input = Date.now() - began;
    // The end of the input starts the quiet period, so that a request the
    // page makes a moment later is waited for.
    const ended = await ev(`window.__load.lastChange = performance.now()`);
    const settled = Math.max(0, await settle(ended));
    const m = await ev(`(() => { const L = window.__load; return { long: L.long, draws: L.draws, asked: L.started - L.started0 }; })()`);
    const max = (a) => a.reduce((x, y) => Math.max(x, y), 0);
    rows.push({ name, input, settled, busy: max(m.long), longTasks: m.long.length, draws: m.draws.length, slowDraw: max(m.draws), asked: m.asked });
  };

  // ---- open the page -------------------------------------------------------
  const page = url + (runId ? `#run=${runId}` : '');
  await send('Page.navigate', { url: page });
  for (let i = 0; i < 400 && !(await ev(`typeof S !== 'undefined' && !!window.__load`).catch(() => false)); i++) await sleep(25);
  await ev(WRAP_DRAW);
  // The page's clock starts when it starts to load, so the moment the last
  // answer landed is how long opening took.
  const first = await settle(0);
  const info = await ev(`({ lanes: S.meta ? S.meta.lanes.length : 0, rows: S.rows.length, findings: S.meta ? S.meta.findings.length : 0, series: S.meta ? S.meta.series.length : 0, run: S.run })`);
  if (!info.lanes) throw new Error('The page opened no run. Is the URL the one `packetlane serve` printed?');
  const openLong = await ev(`window.__load.long`);
  rows.push({ name: 'open the page', input: 0, settled: first, busy: openLong.reduce((x, y) => Math.max(x, y), 0), longTasks: openLong.length, draws: 0, slowDraw: 0, asked: await ev(`window.__load.started`) });

  const box = async (sel) => ev(`(() => { const b = document.querySelector(${JSON.stringify(sel)}).getBoundingClientRect(); return [b.left, b.top, b.width, b.height]; })()`);
  const tl = await box('#tl');
  const at = (fx, fy) => [tl[0] + tl[2] * fx, tl[1] + Math.min(tl[3], HEIGHT - tl[1] - 40) * fy];

  const wheel = async (ticks, deltaY) => {
    const [x, y] = at(0.5, 0.3);
    for (let i = 0; i < ticks; i++) { await mouse('mouseWheel', x, y, { deltaX: 0, deltaY }); await sleep(16); }
  };
  const drag = async (from, to) => {
    const [x0, y] = at(from, 0.3), [x1] = at(to, 0.3);
    await mouse('mousePressed', x0, y, { button: 'left', clickCount: 1 });
    for (let i = 1; i <= 30; i++) { await mouse('mouseMoved', x0 + (x1 - x0) * i / 30, y, { button: 'left', buttons: 1 }); await sleep(16); }
    await mouse('mouseReleased', x1, y, { button: 'left', clickCount: 1 });
  };
  const hover = async () => {
    for (let i = 0; i <= 60; i++) { const [x, y] = at(0.2 + 0.6 * i / 60, 0.3); await mouse('mouseMoved', x, y); await sleep(16); }
  };
  const fit = () => ev(`document.getElementById('fit').click()`);
  const addPlots = async (n) => {
    // Values first, then arrival delay, as many as asked for.
    const keys = await ev(`[...document.querySelectorAll('#add-plot option')].map((o) => o.value).filter(Boolean)`);
    const have = await ev(`S.plots.length`);
    for (const key of keys.slice(have, n)) {
      await ev(`(() => { const s = document.getElementById('add-plot'); s.value = ${JSON.stringify(key)}; s.dispatchEvent(new Event('change')); })()`);
    }
  };

  const gestures = async (label) => {
    await step(`zoom in 20 notches${label}`, () => wheel(20, -120));
    await step(`pan by half a screen${label}`, () => drag(0.7, 0.2));
    await step(`sweep the pointer across${label}`, hover);
    await step(`zoom out 20 notches${label}`, () => wheel(20, 120));
    await step(`show the whole run${label}`, fit);
  };

  await gestures('');
  for (const n of [2, 6]) {
    await step(`add plots, to ${n}`, () => addPlots(n));
    const open = await ev(`S.plots.length`);
    if (open) await gestures(`, ${open} plot${open === 1 ? '' : 's'}`);
    if (open < n) break;
  }

  // ---- side panel ------------------------------------------------------------
  if (info.findings) {
    await step('jump to the first problem', () => ev(`document.querySelector('#problems > *').click()`));
    // A jump closes in until single packets show: the same moves again, on
    // packets instead of counts.
    const single = await ev(`!!S.items`);
    const close = single ? ', single packets' : ', after the jump';
    await step(`pan by half a screen${close}`, () => drag(0.7, 0.2));
    await step(`sweep the pointer across${close}`, hover);
    await step('jump to the last problem', () => ev(`document.querySelector('#problems > :last-child').click()`));
    await step('show the whole run again', fit);
  }
  await step('search for "a"', () => ev(`(() => { const s = document.getElementById('search'); s.value = 'a'; s.dispatchEvent(new Event('input')); })()`));

  if (shot) fs.writeFileSync(shot, Buffer.from((await send('Page.captureScreenshot', { format: 'png' })).data, 'base64'));

  // ---- report ----------------------------------------------------------------
  console.log(`run ${info.run}: ${info.lanes} lanes (${info.rows} rows shown), ${info.findings} findings listed, ${info.series} series; window ${WIDTH}x${HEIGHT}, headless`);
  const f = (n) => n.toFixed(0).padStart(8);
  console.log('step'.padEnd(44) + ' input ms  settled ms  longest busy ms  busy spells  redraws  slowest redraw ms  requests');
  for (const r of rows) {
    console.log(r.name.padEnd(44) + f(r.input) + '  ' + (r.asked ? f(r.settled) : '       -') + '   ' + f(r.busy) + '        ' + String(r.longTasks).padStart(5) + '   ' + String(r.draws).padStart(6) + '        ' + r.slowDraw.toFixed(1).padStart(8) + '     ' + String(r.asked).padStart(5));
  }
  console.log('input: how long the scripted input took to deliver (Chrome takes one event a frame: about 1000 ms for a zoom, 650 for a pan and 1250 for a sweep when the page keeps up; more means the page held the input up).');
  console.log('settled: from the end of the input to the last answer arriving (- when nothing was asked for).');
  console.log('busy: a stretch of 50 ms or more in which the page could not respond. redraws: of the timeline or of one plot.');
  for (const e of errors) console.log('PAGE ERROR: ' + e);
  const over = budget ? rows.filter((r) => r.busy > budget) : [];
  for (const r of over) console.log(`OVER BUDGET (${budget} ms): ${r.name} kept the page busy for ${r.busy.toFixed(0)} ms`);
  ws.close();
  process.exit(errors.length || over.length ? 1 : 0);
})().catch((e) => { console.error(e.message || e); process.exit(2); });
