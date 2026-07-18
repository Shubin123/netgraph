// Automated frame-drop / render perf harness for netgraph/index.html.
//
// Loads the REAL index.html in headless Chrome, feeds it a pcap through the app's
// own parse path, and instruments the page's own globals (`sim`, `updateGraph`) to
// measure where time goes. No modifications to index.html are required.
//
//   node measure.mjs [--capture path.pcap] [--html ../index.html]
//                    [--stress-ms 5000] [--settle-timeout 15000] [--label "before"]
//
// Primary frame-drop signals (these are vsync-independent and the most trustworthy):
//   • tick.avg / tick.over16  — main-thread cost of one force-sim tick. >16.7ms ⇒ you
//                               physically cannot hold 60fps no matter the GPU.
//   • longTasks                — main-thread blocks >50ms (the browser's own jank metric).
// Secondary: rAF-cadence FPS (a proxy; headless framerate isn't real vsync).
import puppeteer from 'puppeteer-core';
import { pathToFileURL } from 'node:url';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync, statSync, writeFileSync, appendFileSync } from 'node:fs';

const HERE = dirname(fileURLToPath(import.meta.url));
const arg = (k, d) => {
  const i = process.argv.indexOf('--' + k);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : d;
};
// Prefer CHROME_PATH, then common Windows / macOS / Linux install locations.
const CHROME = process.env.CHROME_PATH || [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium-browser',
  '/usr/bin/chromium',
].find(p => existsSync(p)) || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const HTML = resolve(arg('html', resolve(HERE, '..', 'index.html')));
// Default to the smaller real Wireshark capture; override with --capture for the bigger
// file (../fuzz-2006-08-23-6489.pcap) or a synthetic stress graph (synthetic.pcap).
const CAPTURE = resolve(arg('capture', resolve(HERE, '..', 'fuzz-2006-07-09-13403.pcap')));
const SETTLE_TIMEOUT = +arg('settle-timeout', 15000);
const LABEL = arg('label', '');

for (const [p, what] of [[CHROME, 'Chrome'], [HTML, 'index.html'], [CAPTURE, 'capture']]) {
  if (!existsSync(p)) {
    console.error(`✗ ${what} not found at: ${p}` +
      (what === 'capture'
        ? '\n  Pass --capture <path>, or generate a synthetic one: node gen-pcap.js'
        : ''));
    process.exit(1);
  }
}

const captureUrl = pathToFileURL(CAPTURE).href;
const captureMB = (statSync(CAPTURE).size / 1048576).toFixed(1);

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: true,
  args: [
    '--allow-file-access-from-files',          // let the page fetch() the local pcap
    '--disable-background-timer-throttling',   // keep rAF / d3-timer running at full rate
    '--disable-backgrounding-occluded-windows',
    '--disable-renderer-backgrounding',
    '--no-sandbox', '--disable-dev-shm-usage', '--hide-scrollbars',
    '--window-size=1600,1000',
  ],
  defaultViewport: { width: 1600, height: 1000 },
});

try {
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  page.on('console', m => { if (m.type() === 'error') errors.push('console: ' + m.text()); });

  await page.goto(pathToFileURL(HTML).href, { waitUntil: 'load', timeout: 30000 });
  await page.bringToFront();
  await page.waitForFunction(() => !!window.d3 && typeof window.updateGraph === 'function',
    { timeout: 20000 }).catch(() => {
      throw new Error('App or d3 failed to load.\n' + (errors.join('\n') || '(no page errors captured)'));
    });

  // ── Instrument the app's own globals (sim tick + updateGraph) and longtasks ──
  await page.evaluate(() => {
    window.__perf = { sampling: false, longTasks: [], tickDurs: [], ugDurs: [] };
    try {
      new PerformanceObserver(l => { for (const e of l.getEntries()) __perf.longTasks.push(e.duration); })
        .observe({ entryTypes: ['longtask'] });
    } catch (e) {}
    const _ug = updateGraph;
    updateGraph = function () {
      const t = performance.now(); const r = _ug.apply(this, arguments);
      __perf.ugDurs.push(performance.now() - t); return r;
    };
    const origTick = sim.on('tick');
    sim.on('tick', function () {
      const t = performance.now(); origTick.apply(this, arguments);
      __perf.tickDurs.push(performance.now() - t);
    });
  });

  // ── Begin sampling, then feed the pcap so we capture the real end-to-end experience:
  //    parse → big "enter all nodes" render → force-layout settle, exactly as a user sees it.
  await page.evaluate(() => {
    __perf.win = { raf: [], t0: performance.now(), longStart: 0, tickStart: 0, ugStart: 0 };
    __perf.sampling = true;
    let last = null;
    const loop = (now) => {
      if (!__perf.sampling) return;
      if (last != null) __perf.win.raf.push(now - last);
      last = now; requestAnimationFrame(loop);
    };
    requestAnimationFrame(loop);
  });

  const parse = await page.evaluate(async (url) => {
    const ab = await (await fetch(url)).arrayBuffer();
    fileHandle = { getFile: async () => new File([ab], 'capture.pcap') }; // global lexical
    if (typeof initUI === 'function') initUI();
    const t0 = performance.now();
    await processStaticPCAP();
    return { parseMs: performance.now() - t0, nodes: nodes.size, edges: edges.size, packets: globalPacketIndex };
  }, captureUrl);

  // Wait for the force layout to go still (or give up after the timeout).
  const tWait = Date.now();
  const settled = await page.waitForFunction(() => sim.alpha() < 0.02,
    { timeout: SETTLE_TIMEOUT, polling: 100 }).then(() => true).catch(() => false);
  const settleMs = Date.now() - tWait;

  // Close window ① and pull the end-to-end load+settle stats.
  const load = await page.evaluate(() => {
    __perf.sampling = false;
    const w = __perf.win, raf = w.raf.slice().sort((a, b) => a - b);
    const q = p => raf.length ? raf[Math.min(raf.length - 1, Math.floor(raf.length * p))] : 0;
    const sum = raf.reduce((a, b) => a + b, 0);
    const longs = __perf.longTasks, ugs = __perf.ugDurs, ticks = __perf.tickDurs;
    return {
      frames: raf.length, meanFps: raf.length ? 1000 / (sum / raf.length) : 0,
      p95: q(0.95), worst: raf.length ? raf[raf.length - 1] : 0,
      firstRenderMs: ugs.length ? Math.max(...ugs) : 0,
      ticksRun: ticks.length, tickAvg: ticks.length ? ticks.reduce((a, b) => a + b, 0) / ticks.length : 0,
      longTasks: longs.length, longMax: longs.length ? Math.max(...longs) : 0,
      longTotal: longs.reduce((a, b) => a + b, 0),
      heapMB: performance.memory ? performance.memory.usedJSHeapSize / 1048576 : 0,
    };
  });

  // ── Headline: deterministic per-tick cost. Drive the sim a fixed number of ticks
  //    by hand (timer stopped), running the app's real tick handler + forcing a layout
  //    flush each time. This can't be starved by jank, so it's the trustworthy number. ──
  const TICKS = +arg('bench-ticks', 80);
  const bench = await page.evaluate((N) => {
    const handler = sim.on('tick');
    sim.stop();
    sim.alpha(1);
    const durs = [];
    for (let i = 0; i < N; i++) {
      const t = performance.now();
      sim.tick();
      handler();
      void document.body.offsetHeight; // force layout so SVG attr writes actually apply
      durs.push(performance.now() - t);
    }
    const sorted = durs.slice().sort((a, b) => a - b);
    const q = p => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];
    const sum = durs.reduce((a, b) => a + b, 0);
    return {
      ticks: N, avg: sum / N, p50: q(0.5), p95: q(0.95), max: sorted[sorted.length - 1],
      over16: durs.filter(d => d > 16.7).length / N * 100, projFps: 1000 / (sum / N),
    };
  }, TICKS);

  // ── Report ──
  const n = (x, d = 1) => Number(x).toFixed(d);
  console.log('\n' + '═'.repeat(78));
  console.log(`  netgraph frame-drop benchmark${LABEL ? '  [' + LABEL + ']' : ''}`);
  console.log('═'.repeat(78));
  console.log(`  capture ................. ${CAPTURE.split('/').pop()}  (${captureMB} MB)`);
  console.log(`  parsed .................. ${parse.packets.toLocaleString()} packets → ${parse.nodes.toLocaleString()} nodes, ${parse.edges.toLocaleString()} edges  in ${n(parse.parseMs)} ms`);

  console.log(`\n  ① OPEN → SETTLE  (what the user actually experiences)`);
  console.log(`     time to still ......... ${settled ? n(settleMs) + ' ms' : 'NEVER settled within ' + SETTLE_TIMEOUT + ' ms'}`);
  console.log(`     first render (enter) .. ${n(load.firstRenderMs)} ms  to build ${parse.nodes.toLocaleString()} nodes + ${parse.edges.toLocaleString()} edges`);
  console.log(`     main-thread blocking .. ${n(load.longTotal)} ms across ${load.longTasks} long tasks (worst ${n(load.longMax)} ms)`);
  console.log(`     ticks completed ....... ${load.ticksRun}   observed ~${n(load.meanFps)} fps (rAF proxy; starved under load)`);
  console.log(`     JS heap ............... ${n(load.heapMB)} MB`);

  console.log(`\n  ② PER-TICK COST  (deterministic, ${bench.ticks} hand-driven ticks @ alpha 1 — the trustworthy metric)`);
  console.log(`     MEDIAN frame .......... ${n(bench.p50, 2)} ms  →  ${n(1000 / bench.p50)} fps ceiling   (the steady-state number; reproducible)`);
  console.log(`     avg / p95 / max ....... ${n(bench.avg, 1)} / ${n(bench.p95, 1)} / ${n(bench.max, 1)} ms   (inflated by startup hitches — see note)`);
  console.log(`     over 16.7ms budget .... ${n(bench.over16)}% of ticks`);

  // Verdict from the median (low-noise) per-tick cost.
  console.log('\n  ' + '─'.repeat(74));
  const ta = bench.p50;
  const verdict = ta > 33.4
    ? `${n(ta, 1)}ms median tick ⇒ the graph runs below 30fps whenever the layout moves.`
    : ta > 16.7
      ? `${n(ta, 1)}ms median tick ⇒ over the 16.7ms budget, so 60fps is impossible during layout.`
      : `${n(ta, 1)}ms median tick ⇒ within the 16.7ms budget; layout should hold ~60fps.`;
  console.log(`  VERDICT: ${verdict}`);
  console.log(`           dominant cost = per-tick DOM update of ${parse.nodes.toLocaleString()} nodes + ${parse.edges.toLocaleString()} <line>s in SVG.`);
  console.log('═'.repeat(78) + '\n');

  // Persist machine-readable results for before/after comparison.
  const record = {
    ts: new Date().toISOString(), label: LABEL,
    capture: CAPTURE.split('/').pop(), captureMB: +captureMB,
    nodes: parse.nodes, edges: parse.edges, packets: parse.packets, parseMs: +n(parse.parseMs),
    settled, settleMs, load, bench,
  };
  writeFileSync(resolve(HERE, 'last-run.json'), JSON.stringify(record, null, 2));
  appendFileSync(resolve(HERE, 'history.ndjson'), JSON.stringify(record) + '\n');
  console.log(`  → wrote perf/last-run.json  (appended to perf/history.ndjson)\n`);
} finally {
  await browser.close();
}
