// Diff two benchmark runs from perf/history.ndjson — the "before/after" tool.
//
//   node compare.mjs                  # compares the two most recent runs
//   node compare.mjs before after     # compares the latest run of each label
//
// Exit code is non-zero if the newer run regressed on per-tick cost, so this can
// gate a CI check or a pre-commit hook.
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const HIST = resolve(HERE, 'history.ndjson');
if (!existsSync(HIST)) { console.error('No history.ndjson yet — run: node measure.mjs'); process.exit(1); }

const runs = readFileSync(HIST, 'utf8').trim().split('\n')
  .map(l => { try { return JSON.parse(l); } catch { return null; } })
  .filter(r => r && r.bench);          // only entries from the current harness format
if (runs.length < 2) { console.error('Need at least 2 runs to compare (have ' + runs.length + ').'); process.exit(1); }

const [aLabel, bLabel] = process.argv.slice(2);
const latestWith = lbl => [...runs].reverse().find(r => r.label === lbl);
let A, B;
if (aLabel && bLabel) {
  A = latestWith(aLabel); B = latestWith(bLabel);
  if (!A || !B) { console.error(`Could not find runs labelled "${aLabel}" and "${bLabel}".`); process.exit(1); }
} else {
  A = runs[runs.length - 2]; B = runs[runs.length - 1];   // before, after
}

const tag = r => r.label || r.ts.slice(0, 19);
// metric: [label, accessor, unit, lowerIsBetter]
const METRICS = [
  ['per-tick avg', r => r.bench.avg, 'ms', true],
  ['per-tick p50', r => r.bench.p50, 'ms', true],
  ['per-tick p95', r => r.bench.p95, 'ms', true],
  ['fps ceiling', r => r.bench.projFps, 'fps', false],
  ['settle time', r => r.settled ? r.settleMs : r.settleMs, 'ms', true],
  ['first render', r => r.load.firstRenderMs, 'ms', true],
  ['mt blocking', r => r.load.longTotal, 'ms', true],
  ['heap', r => r.load.heapMB, 'MB', true],
];

const n = (x, d = 1) => Number(x).toFixed(d);
console.log('\n' + '═'.repeat(72));
console.log(`  compare:  ${tag(A)}  →  ${tag(B)}`);
console.log(`  graph:    ${B.nodes} nodes / ${B.edges} edges  (${B.capture})`);
console.log('═'.repeat(72));
console.log(`  ${'metric'.padEnd(14)} ${'before'.padStart(12)} ${'after'.padStart(12)} ${'change'.padStart(12)}`);
console.log('  ' + '─'.repeat(68));

let regressed = false;
for (const [name, get, unit, lowerBetter] of METRICS) {
  const av = get(A), bv = get(B);
  const pct = av === 0 ? 0 : (bv - av) / av * 100;
  const better = lowerBetter ? bv < av : bv > av;
  const worse = lowerBetter ? bv > av : bv < av;
  // Gate on the MEDIAN tick — it's reproducible. The avg/p95 are dominated by a few
  // catastrophic startup ticks and swing ~10% run-to-run, so they're context only.
  if (name === 'per-tick p50' && worse && Math.abs(pct) > 8) regressed = true;
  const mark = Math.abs(pct) < 1 ? '  ·' : better ? ' ✓' : worse ? ' ✗' : '  ';
  const arrow = bv === av ? '' : (pct > 0 ? '+' : '') + n(pct) + '%';
  console.log(`  ${name.padEnd(14)} ${(n(av) + unit).padStart(12)} ${(n(bv) + unit).padStart(12)} ${arrow.padStart(10)}${mark}`);
}
console.log('  ' + '─'.repeat(68));
const dMed = (B.bench.p50 - A.bench.p50) / A.bench.p50 * 100;
console.log(regressed
  ? `  ✗ REGRESSION: median tick ${dMed > 0 ? 'up' : 'down'} ${n(Math.abs(dMed))}% (${n(A.bench.p50)}ms → ${n(B.bench.p50)}ms)`
  : `  ✓ median tick ${n(A.bench.p50)}ms → ${n(B.bench.p50)}ms  (${dMed <= 0 ? n(Math.abs(dMed)) + '% faster' : 'within noise'})`);
console.log('═'.repeat(72) + '\n');
process.exit(regressed ? 1 : 0);
