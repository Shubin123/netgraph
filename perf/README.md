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
| `../fuzz-2006-07-09-13403.pcap` | 2.4 MB | 1,467 nodes / 1,898 edges | yes, ~2.7 s (default — start here) |
| `../fuzz-2006-08-23-6489.pcap`  | 7.3 MB | 10,733 nodes / 14,039 edges | yes, ~2.6 s (real stress case) |
| `synthetic.pcap` (generated)    | tunable | ~2k nodes / 15.5k edges | yes, ~1.8 s (deliberately extreme) |

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

`fuzz-2006-07-09-13403.pcap` → 1,467 nodes / 1,898 edges parses in ~59 ms. It now crosses onto
the canvas fast-path (1.9k edges > the 1,200 threshold) and holds a **~4.5 ms median tick
(~219 fps ceiling)**, settling in **~2.7 s** — down from ~10 ms / ~8 s on the old SVG path.
`fuzz-2006-08-23-6489.pcap` is the real stress fixture: **10,733 nodes / 14,039 edges** (see the
force-compute finding below).

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

### Steady-state render cost — FIXED (canvas fast-path)

Past **600 nodes / 1,200 edges** the heavy layers now render to a single `<canvas>` instead
of SVG: all links collapse into one batched, viewport-culled path (they share a color), nodes
become cached glow-sprite + `arc()` draws, and the DOM stops mutating entirely — so per-tick
cost scales with what's *on screen*, not with total graph size, and a settled graph is free.
Small graphs (below the threshold) keep the full SVG treatment (entrance pops, ping rings,
activity flashes). A decomposition probe pinned the cost exactly: at synthetic scale SVG spent
~45 ms/tick re-laying-out the DOM, whereas the canvas *draw* is **0.8 ms**.

| deterministic median tick | SVG before | canvas after | change |
|---|--:|--:|--:|
| synthetic (2k nodes / 15.5k edges) | 45.4 ms (22 fps) | **5.2 ms (192 fps)** | **−89 %** |
| real 13403 (1.5k / 1.9k) | 10.2 ms (98 fps) | **4.5 ms (219 fps)** | −56 % |
| settle, synthetic | never (>15 s) | **1.8 s** | — |
| main-thread blocking, synthetic | 4027 ms | **0 ms** | −100 % |

### Force compute at 10k+ nodes — FIXED (adaptive Barnes-Hut theta)

With rendering off the critical path, the next ceiling is the `forceManyBody` charge force
itself. The bigger real capture (`fuzz-2006-08-23-6489.pcap`, **10,733 nodes / 14,039 edges**)
spent ~48 ms/tick purely in `sim.tick()` (canvas draw was ~1 ms). The Barnes-Hut approximation
angle `theta` is the lever — `distanceMax` barely moved the needle (the graph is already
compact), but opening `theta` cut the tick cleanly:

| theta @ 10.7k nodes | median tick |
|--:|--:|
| 0.9 (d3 default) | 43.9 ms (23 fps) |
| 1.5 | 25.6 ms (39 fps) |
| 1.8 | 18.1 ms (55 fps) |
| 2.2 | 15.0 ms (67 fps) |

`index.html` scales `theta` with node count **in canvas mode only** (≤2,500 nodes keep the
accurate 0.9; ramps to ~1.8 by 10k, capped at 2.0) — at that zoom the coarser spacing is
imperceptible. Net on the 10.7k-node capture: **45.5 → 17.4 ms median tick (23 → 58 fps),
settles in 2.6 s (was never), 0 ms blocking.**

> The `<canvas>` sits at `z-index: 1`, so any *clickable* overlay must stack above it — the
> legend needed an explicit `z-index: 10` it had previously done without (HUD/timeline already
> had one). Watch for this when adding new interactive UI.

### Note on the metrics

Comparison gates on the **median** tick — the least-noisy metric — rather than avg/p95,
which were dominated by the (now-fixed) startup hitches. The median still carries some
run-to-run variance (the bench inherits whatever layout the prior settle produced), so
`compare.mjs` treats changes under ~8 % as noise.

**Next optimization lever** (if you push well past ~15k nodes): rendering is no longer the
bottleneck — the remaining per-tick cost is almost entirely `forceManyBody` + `forceLink`
compute. Options from here are a higher `velocityDecay`/`alphaDecay` to settle in fewer ticks,
capping the *simulated* set to on-screen nodes, or moving the layout into a Web Worker so it
never blocks the main thread at all. Validate any such change against the canvas baseline above.
