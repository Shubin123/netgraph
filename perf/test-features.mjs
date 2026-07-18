// Functional regression harness for netgraph timeline edges, autoplay, and node stability.
//
// Loads the real index.html in headless Chrome, feeds a synthetic pcap, then asserts:
//   1. Edge history tracks packet traversal (timeline scrub shows/hides/grows edges)
//   2. Autoplay advances the timeline without throwing
//   3. Dragging one node does not move the rest
//   4. Legend filter hide/show preserves node positions (no respawn thrash)
//
//   node test-features.mjs [--capture path.pcap] [--html ../index.html]
//
// Exit code 0 = all assertions passed; non-zero = failures printed.
import puppeteer from 'puppeteer-core';
import { pathToFileURL } from 'node:url';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const HERE = dirname(fileURLToPath(import.meta.url));
const arg = (k, d) => {
  const i = process.argv.indexOf('--' + k);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : d;
};

function findChrome() {
  if (process.env.CHROME_PATH && existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  const candidates = [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium',
  ];
  for (const c of candidates) if (existsSync(c)) return c;
  return null;
}

const CHROME = findChrome();
const HTML = resolve(arg('html', resolve(HERE, '..', 'index.html')));
let CAPTURE = resolve(arg('capture', resolve(HERE, 'feature-test.pcap')));

if (!CHROME) {
  console.error('✗ Chrome/Edge not found. Set CHROME_PATH.');
  process.exit(1);
}
if (!existsSync(HTML)) {
  console.error('✗ index.html not found at', HTML);
  process.exit(1);
}

// Auto-generate a modest synthetic capture if none was provided / present.
if (!existsSync(CAPTURE) || arg('capture', null) == null) {
  const out = resolve(HERE, 'feature-test.pcap');
  console.log('  generating feature-test.pcap (small synthetic)…');
  const r = spawnSync(process.execPath, [
    resolve(HERE, 'gen-pcap.js'),
    '--hubs', '8',
    '--leaves', '40',
    '--fanout', '3',
    '--packets', '800',
    '--out', out,
  ], { stdio: 'inherit' });
  if (r.status !== 0) {
    console.error('✗ gen-pcap.js failed');
    process.exit(1);
  }
  CAPTURE = out;
}

const results = [];
const pass = (name, detail = '') => { results.push({ name, ok: true, detail }); console.log(`  ✓ ${name}${detail ? ' — ' + detail : ''}`); };
const fail = (name, detail = '') => { results.push({ name, ok: false, detail }); console.error(`  ✗ ${name}${detail ? ' — ' + detail : ''}`); };
const assert = (name, cond, detail = '') => { (cond ? pass : fail)(name, detail); };

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: true,
  args: [
    '--allow-file-access-from-files',
    '--disable-background-timer-throttling',
    '--disable-backgrounding-occluded-windows',
    '--disable-renderer-backgrounding',
    '--no-sandbox', '--disable-dev-shm-usage', '--hide-scrollbars',
    '--window-size=1400,900',
  ],
  defaultViewport: { width: 1400, height: 900 },
});

try {
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  page.on('console', m => { if (m.type() === 'error') errors.push('console: ' + m.text()); });

  await page.goto(pathToFileURL(HTML).href, { waitUntil: 'load', timeout: 30000 });
  await page.waitForFunction(() => !!window.d3 && typeof window.updateGraph === 'function', { timeout: 20000 });

  // ── Load capture ──────────────────────────────────────────────────────────
  const captureUrl = pathToFileURL(CAPTURE).href;
  const parse = await page.evaluate(async (url) => {
    const ab = await (await fetch(url)).arrayBuffer();
    fileHandle = { getFile: async () => new File([ab], 'feature-test.pcap') };
    if (typeof initUI === 'function') initUI();
    await processStaticPCAP();
    return {
      nodes: nodes.size,
      edges: edges.size,
      packets: globalPacketIndex,
      edgeHasHistory: [...edges.values()].every(e => Array.isArray(e.history) && e.history.length > 0),
      nodeHasHistory: [...nodes.values()].every(n => Array.isArray(n.history) && n.history.length > 0),
      sampleEdgeHistLen: (() => {
        let m = 0;
        edges.forEach(e => { m = Math.max(m, e.history?.length || 0); });
        return m;
      })(),
    };
  }, captureUrl);

  assert('pcap parsed with nodes/edges', parse.nodes > 0 && parse.edges > 0,
    `${parse.packets} pkts → ${parse.nodes} nodes / ${parse.edges} edges`);
  assert('edges store packet history', parse.edgeHasHistory,
    `max edge history length = ${parse.sampleEdgeHistLen}`);
  assert('nodes store packet history', parse.nodeHasHistory);

  // Wait for force layout to cool + auto-pin.
  const settled = await page.waitForFunction(() => {
    const ns = sim.nodes();
    if (!ns.length) return false;
    const pinned = ns.filter(n => n.fx != null && n.fy != null).length;
    return sim.alpha() < 0.03 && pinned === ns.length;
  }, { timeout: 20000, polling: 100 }).then(() => true).catch(() => false);

  const pinInfo = await page.evaluate(() => {
    const ns = sim.nodes();
    return {
      alpha: sim.alpha(),
      total: ns.length,
      pinned: ns.filter(n => n.fx != null && n.fy != null).length,
      renderMode,
    };
  });
  assert('graph settled and all active nodes pinned', settled && pinInfo.pinned === pinInfo.total,
    `alpha=${pinInfo.alpha.toFixed(4)} pinned=${pinInfo.pinned}/${pinInfo.total} mode=${pinInfo.renderMode}`);

  // ── 1. Edge timeline traversal ────────────────────────────────────────────
  const edgeTimeline = await page.evaluate(() => {
    const max = globalPacketIndex;
    const mid = Math.max(1, Math.floor(max * 0.4));
    const early = Math.max(1, Math.floor(max * 0.1));

    const countActive = () => {
      updateGraph();
      return {
        nodes: +document.getElementById('nc').textContent,
        edges: +document.getElementById('ec').textContent,
        slider: +document.getElementById('timeSlider').value,
      };
    };

    // Full timeline
    document.getElementById('timeSlider').value = max;
    const full = countActive();

    // Early — fewer packets traversed ⇒ fewer (or equal) edges visible
    document.getElementById('timeSlider').value = early;
    const earlyC = countActive();

    // Mid
    document.getElementById('timeSlider').value = mid;
    const midC = countActive();

    // Edge currentCount should equal history packets ≤ limit for a sample edge
    let histOk = true;
    let sample = null;
    edges.forEach(e => {
      if (sample) return;
      const limit = mid;
      const expected = e.history.filter(h => h.index <= limit).length;
      // bisect-right on sorted history
      const split = (() => {
        let lo = 0, hi = e.history.length;
        while (lo < hi) {
          const m = (lo + hi) >> 1;
          if (e.history[m].index <= limit) lo = m + 1; else hi = m;
        }
        return lo;
      })();
      sample = { expected, split, currentCount: e.currentCount, id: e.id };
      if (split !== expected || e.currentCount !== expected) histOk = false;
    });

    // Edge widths should grow with more packets (at full vs early for multi-packet edges)
    document.getElementById('timeSlider').value = max;
    updateGraph();
    let widthGrew = false;
    let multiPacketEdges = 0;
    edges.forEach(e => {
      if (e.history.length >= 3) {
        multiPacketEdges++;
        const fullW = getEdgeWidth({ currentCount: e.history.length });
        const earlyW = getEdgeWidth({ currentCount: 1 });
        if (fullW > earlyW) widthGrew = true;
      }
    });

    // Restore full
    document.getElementById('timeSlider').value = max;
    updateGraph();

    return { full, earlyC, midC, histOk, sample, widthGrew, multiPacketEdges, max, early, mid };
  });

  assert('timeline early shows fewer-or-equal edges than full',
    edgeTimeline.earlyC.edges <= edgeTimeline.full.edges,
    `early=${edgeTimeline.earlyC.edges} mid=${edgeTimeline.midC.edges} full=${edgeTimeline.full.edges}`);
  assert('timeline mid is between early and full (edges)',
    edgeTimeline.midC.edges >= edgeTimeline.earlyC.edges &&
    edgeTimeline.midC.edges <= edgeTimeline.full.edges,
    `early=${edgeTimeline.earlyC.edges} mid=${edgeTimeline.midC.edges} full=${edgeTimeline.full.edges}`);
  assert('timeline early shows fewer-or-equal nodes than full',
    edgeTimeline.earlyC.nodes <= edgeTimeline.full.nodes,
    `early=${edgeTimeline.earlyC.nodes} full=${edgeTimeline.full.nodes}`);
  assert('edge currentCount matches history ≤ timeline',
    edgeTimeline.histOk,
    JSON.stringify(edgeTimeline.sample));
  assert('edge width scales with packet count',
    edgeTimeline.widthGrew || edgeTimeline.multiPacketEdges === 0,
    `multi-packet edges=${edgeTimeline.multiPacketEdges}`);

  // ── 2. Autoplay ───────────────────────────────────────────────────────────
  const autoplay = await page.evaluate(async () => {
    const max = globalPacketIndex;
    // Start near the beginning
    document.getElementById('timeSlider').value = 0;
    updateGraph();
    if (typeof startAutoplay === 'function') startAutoplay();
    else document.getElementById('btnPlay').click();

    const t0 = performance.now();
    // Wait until slider advances or timeout
    let advanced = false;
    let finalVal = 0;
    let playLabel = '';
    while (performance.now() - t0 < 4000) {
      finalVal = +document.getElementById('timeSlider').value;
      playLabel = document.getElementById('timeStatus').textContent;
      if (finalVal > 0) { advanced = true; break; }
      await new Promise(r => setTimeout(r, 50));
    }
    // Let it run a bit more, then stop
    await new Promise(r => setTimeout(r, 400));
    const midVal = +document.getElementById('timeSlider').value;
    if (typeof stopAutoplay === 'function') stopAutoplay();
    else document.getElementById('btnPlay').click();

    const afterStop = +document.getElementById('timeSlider').value;
    // Ensure stop actually halted progress
    await new Promise(r => setTimeout(r, 300));
    const afterWait = +document.getElementById('timeSlider').value;

    // Restart from near end should complete
    document.getElementById('timeSlider').value = Math.max(0, max - 5);
    updateGraph();
    startAutoplay();
    await new Promise(r => setTimeout(r, 2500));
    const endVal = +document.getElementById('timeSlider').value;
    const endedAtMax = endVal === max;
    stopAutoplay();

    // Button exists and has expected API surface
    const btn = document.getElementById('btnPlay');
    return {
      advanced, finalVal, midVal, afterStop, afterWait, endedAtMax, endVal, max,
      playLabel, hasBtn: !!btn, btnType: btn?.tagName,
    };
  });

  assert('autoplay button present', autoplay.hasBtn, autoplay.btnType);
  assert('autoplay advances timeline', autoplay.advanced,
    `slider ${autoplay.finalVal} → ${autoplay.midVal} / ${autoplay.max}`);
  assert('stopAutoplay halts progress', autoplay.afterWait === autoplay.afterStop,
    `stopped@${autoplay.afterStop} afterWait@${autoplay.afterWait}`);
  assert('autoplay reaches end when near finish', autoplay.endedAtMax,
    `endVal=${autoplay.endVal} max=${autoplay.max}`);

  // Restore full timeline + re-pin settle after autoplay
  await page.evaluate(() => {
    stopAutoplay();
    document.getElementById('timeSlider').value = globalPacketIndex;
    updateGraph();
    // Ensure everything is pinned again for stability tests
    pinNodes(sim.nodes());
    sim.alpha(0);
  });

  // ── 3. Drag stability — one node must not move the others ─────────────────
  const dragStab = await page.evaluate(() => {
    const ns = sim.nodes();
    if (ns.length < 2) return { ok: false, reason: 'need ≥2 nodes' };

    // Prefer a node near the viewport center for reliable hit-testing
    const cx = window.innerWidth / 2, cy = window.innerHeight / 2;
    let target = ns[0], best = Infinity;
    for (const n of ns) {
      // Approximate screen pos ignoring zoom (view may be identity after load)
      const sx = (n.x * (view?.k || 1)) + (view?.x || 0);
      const sy = (n.y * (view?.k || 1)) + (view?.y || 0);
      const d = Math.hypot(sx - cx, sy - cy);
      if (d < best) { best = d; target = n; }
    }

    const before = snapshotPositions();
    const ox = target.x, oy = target.y;
    const dx = 80, dy = -60;
    // Simulate a drag: move pin only (same code path as real drag end-state)
    target.fx = ox + dx; target.fy = oy + dy;
    target.x = ox + dx;  target.y = oy + dy;
    // Reheat deliberately — old code would thrash others; pinned nodes must hold.
    sim.alpha(0.5).restart();
    for (let i = 0; i < 40; i++) sim.tick();
    sim.alpha(0);
    pinNode(target);

    const after = snapshotPositions();
    const drift = positionDrift(before, after, target.id);
    const moved = Math.hypot(after[target.id].x - before[target.id].x, after[target.id].y - before[target.id].y);
    return {
      ok: true,
      targetId: target.id,
      moved,
      driftMax: drift.max,
      driftAvg: drift.avg,
      others: drift.count,
      renderMode,
    };
  });

  assert('drag target moved to new position', dragStab.ok && dragStab.moved > 50,
    dragStab.ok ? `moved ${dragStab.moved.toFixed(1)}px` : dragStab.reason);
  assert('other nodes stay put while one is dragged/reheated',
    dragStab.ok && dragStab.driftMax < 1.0,
    `max drift ${dragStab.driftMax?.toFixed?.(3)} avg ${dragStab.driftAvg?.toFixed?.(3)} over ${dragStab.others} nodes`);

  // ── 4. Legend filter preserves positions on hide/show ─────────────────────
  const filterStab = await page.evaluate(() => {
    // Ensure full graph, pinned
    document.getElementById('timeSlider').value = globalPacketIndex;
    activeFilter = null;
    updateLegend();
    updateGraph();
    pinNodes(sim.nodes());
    sim.alpha(0);

    const protos = [...knownProtos];
    if (!protos.length) return { ok: false, reason: 'no protocols' };

    // Pick the protocol that covers a non-trivial subset (not all, not none if possible)
    let chosen = protos[0];
    let bestScore = -1;
    for (const p of protos) {
      let c = 0;
      nodes.forEach(n => {
        if (n.history.some(h => h.proto === p)) c++;
      });
      // Prefer a filter that hides some but not all
      const score = (c > 0 && c < nodes.size) ? Math.min(c, nodes.size - c) : 0;
      if (score > bestScore) { bestScore = score; chosen = p; }
    }

    const before = snapshotPositions();
    const beforeCount = sim.nodes().length;

    activeFilter = chosen;
    updateLegend();
    updateGraph();
    const filteredCount = sim.nodes().length;
    // Even if sim tries to run, pinned nodes must not drift
    for (let i = 0; i < 20; i++) sim.tick();

    const during = snapshotPositions();
    const driftDuring = positionDrift(before, during, null);

    // Clear filter — nodes respawn into the active set
    activeFilter = null;
    updateLegend();
    updateGraph();
    for (let i = 0; i < 20; i++) sim.tick();
    sim.alpha(0);

    const after = snapshotPositions();
    const driftAfter = positionDrift(before, after, null);
    const afterCount = sim.nodes().length;

    // Positions of nodes that existed before must match
    let maxRestore = 0, missing = 0;
    for (const id of Object.keys(before)) {
      if (!after[id]) { missing++; continue; }
      maxRestore = Math.max(maxRestore, Math.hypot(after[id].x - before[id].x, after[id].y - before[id].y));
    }

    return {
      ok: true,
      chosen,
      beforeCount,
      filteredCount,
      afterCount,
      driftDuringMax: driftDuring.max,
      driftAfterMax: driftAfter.max,
      maxRestore,
      missing,
      protos: protos.length,
    };
  });

  assert('legend filter applied', filterStab.ok && filterStab.filteredCount <= filterStab.beforeCount,
    filterStab.ok
      ? `proto=${filterStab.chosen} ${filterStab.beforeCount} → ${filterStab.filteredCount} → ${filterStab.afterCount}`
      : filterStab.reason);
  assert('nodes do not drift while filtered',
    filterStab.ok && filterStab.driftDuringMax < 1.0,
    `max drift while filtered=${filterStab.driftDuringMax?.toFixed?.(3)}`);
  assert('nodes restore to same positions after clearing filter',
    filterStab.ok && filterStab.maxRestore < 1.0 && filterStab.missing === 0,
    `max restore drift=${filterStab.maxRestore?.toFixed?.(3)} missing=${filterStab.missing}`);
  assert('clearing filter restores full active node count',
    filterStab.ok && filterStab.afterCount === filterStab.beforeCount,
    `${filterStab.afterCount} vs ${filterStab.beforeCount}`);

  // ── No page errors ────────────────────────────────────────────────────────
  assert('no page errors during tests', errors.length === 0,
    errors.length ? errors.slice(0, 3).join(' | ') : '');

  // ── Summary ───────────────────────────────────────────────────────────────
  const failed = results.filter(r => !r.ok);
  console.log('\n' + '═'.repeat(72));
  console.log(`  netgraph feature tests  —  ${results.length - failed.length}/${results.length} passed`);
  console.log('═'.repeat(72));
  if (failed.length) {
    console.log('  Failures:');
    for (const f of failed) console.log(`    • ${f.name}${f.detail ? ': ' + f.detail : ''}`);
    console.log('');
    process.exitCode = 1;
  } else {
    console.log('  All feature assertions passed.\n');
  }
} finally {
  await browser.close();
}
