# netgraph perf harness

Automated, reproducible frame-drop testing for `../index.html`. It loads the **real**
page in headless Chrome, feeds it a pcap through the app's own parser, and measures
where the main thread spends its time — no changes to `index.html` required.

## Setup (once)

```bash
cd perf
npm install        # pulls puppeteer-core only (uses your installed Google Chrome)
```

If Chrome isn't at the default macOS path, set `CHROME_PATH=/path/to/chrome`.

## Test fixtures

The primary fixtures are the real Wireshark fuzz captures in the repo root (these exercise
the actual parser against real, occasionally-malformed traffic — closer to real use than a
clean synthetic file):

| file | size | parses to | settles? |
|------|-----:|-----------|----------|
| `../fuzz-2006-07-09-13403.pcap` | 2.4 MB | 1,467 nodes / 1,898 edges | yes, ~8 s (default — start here) |
| `../fuzz-2006-08-23-6489.pcap`  | 7.3 MB | (bigger) | — |
| `synthetic.pcap` (generated)    | tunable | ~2k nodes / 15.5k edges | deliberately extreme stress |

> The `*.pcap` files are git-ignored, so they must be present locally to run.

## Run

```bash
npm run measure            # the smaller real capture (13403) — the default, start here
npm run measure:big        # the larger real capture (6489)
npm run bench              # both real captures, back to back
npm run measure:synthetic  # generate + measure the synthetic stress graph
```

Any capture, any label, by hand:

```bash
node measure.mjs --capture ../fuzz-2006-07-09-13403.pcap --label 13403
```

The synthetic generator is still useful for scaling node/edge count past what the sample
files contain (render cost is driven by element count, not file size):

```bash
node gen-pcap.js --leaves 4000 --hubs 100 --fanout 5 --packets 400000
node measure.mjs --capture synthetic.pcap --label big-synthetic
```

## What it reports

```
① OPEN → SETTLE   end-to-end "user opens the pcap and waits for it to stop moving"
     time to still, first-render (enter) cost, total main-thread blocking, observed fps
② PER-TICK COST   the trustworthy headline number
     avg / p50 / p95 / max ms for one force-sim tick (incl. the SVG DOM update),
     % of ticks over the 16.7ms (60fps) budget, and the resulting fps ceiling
VERDICT           plain-English read on whether 60/30fps is achievable during layout
```

**Why per-tick cost is the headline.** Headless Chrome's frame rate isn't real vsync,
so the rAF-based fps in ① is only a proxy (and gets *starved* exactly when the page is
janky). Window ② instead drives the simulation a fixed number of ticks **by hand** with
the timer stopped, runs the app's real tick handler, and forces a layout flush each time.
That number is environment-independent and is what actually predicts dropped frames:
if one tick costs >16.7ms, you physically cannot hold 60fps while the graph is moving.

## Before / after

Every run appends to `history.ndjson`. Compare two of them:

```bash
node measure.mjs --label before
#   ...make an optimization to index.html...
node measure.mjs --label after
node compare.mjs before after        # diffs per-tick cost, settle, blocking, heap
```

`compare.mjs` exits non-zero if the **median** tick regressed >8%, so it can gate a hook or
CI. With no args it compares the two most recent runs.

## Files

| file | purpose |
|------|---------|
| `gen-pcap.js`   | deterministic synthetic pcap generator (seeded, reproducible) |
| `measure.mjs`   | headless-Chrome measurement driver + report |
| `compare.mjs`   | before/after diff from `history.ndjson` |
| `synthetic.pcap`| generated capture (git-ignorable) |
| `last-run.json` | full metrics of the most recent run |
| `history.ndjson`| one JSON line per run, for trend/compare |

## Findings

### Real captures (default fixtures)

`fuzz-2006-07-09-13403.pcap` → 1,467 nodes / 1,898 edges parses in ~59 ms, **settles in
~8 s**, and holds a **~10 ms median tick (~96 fps ceiling)** with only ~1 % of ticks over
budget. So on representative real traffic the app is already smooth — the heavy numbers
below come from the deliberately extreme synthetic graph (8× the edges).

### Synthetic stress (2,000 nodes / 15,520 edges / 13.8 MB)

### Startup hitches — FIXED (spread-spawn)

Originally every node spawned on the exact same point (`W/2,H/2`, or precisely on its
peer), so thousands of coincident points made `forceManyBody`'s Barnes-Hut quadtree
degenerate — producing multi-second "hitch" ticks on load. `index.html` now spreads
initial positions (phyllotaxis spiral for first-seen nodes, a ring around the peer for
linked ones). Measured before → after:

| metric (deterministic per-tick) | before | after | change |
|---|--:|--:|--:|
| **worst tick** | **8516 ms** | **95 ms** | **−99 %** |
| p95 tick | 806 ms | 47 ms | −94 % |
| avg tick | 249 ms | 41 ms | −84 % |
| median tick | 61 ms | 39 ms | −36 % |
| fps ceiling | 4 fps | 25 fps | +6× |

The catastrophic startup ticks are gone, and the steady-state median improved too (the
layout no longer explodes outward from one point).

### Remaining bottleneck — steady-state SVG cost

The median tick is still **~39 ms (~25 fps ceiling)** and the graph still doesn't settle
within 15 s, because every tick re-lays-out **~15.5k SVG `<line>`s + 2k node groups** in
the DOM. This is the dominant remaining cost — **not** the glow/lighting (the harness
confirms that costs ~nothing at this scale). The next lever is rendering the link layer to
`<canvas>`, hiding links past a node threshold, or `sim.stop()` once settled.

### Note on the metrics

Comparison gates on the **median** tick — the least-noisy metric — rather than avg/p95,
which were dominated by the (now-fixed) startup hitches. The median still carries some
run-to-run variance (the bench inherits whatever layout the prior settle produced), so
`compare.mjs` treats changes under ~8 % as noise.

**Next optimization lever** (reduce per-tick DOM work at scale): render the link layer to
`<canvas>` instead of thousands of SVG elements, hide links past a node threshold, or
`sim.stop()` once settled so an idle graph costs nothing. Use this harness to validate
any such change against the baseline above.
