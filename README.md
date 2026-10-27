Live Network Map Engine
A real-time, browser-based network traffic visualization tool. It renders interactive D3.js force-directed graphs from packet captures and supports live 802.11 WiFi sniffing directly from an ESP32 microcontroller via WebSerial. Windump ethtap pipeline provided aswell

Features
Live WebSerial Capture: Stream raw 802.11 frames directly from an ESP32 to the browser at 921600 baud.

Multi-Format Parsing: Native browser parsing for binary PCAP/PCAPNG (Ethernet and 802.11 LinkTypes), Wireshark CSVs, and live NDJSON streams.

Real-time OUI Resolution: Automatically fetches IEEE OUI data to resolve MAC addresses into human-readable vendor names (e.g., Apple_ab:cd:ef) mirroring Wireshark's behavior.

Interactive Visualization: D3.js physics-based node graph with protocol filtering, timeline scrubbing, and dynamic node sizing based on traffic volume.

supports precaptured pcaps, csv exports visualization (including timing).



SCREENSHOTS:
<br>
From example pcaps on https://www.wireshark.org/download/automated/captures/ <br>
fuzz-2006-07-05-6279.pcap
<img width="1820" height="985" alt="image" src="https://github.com/user-attachments/assets/ccca3d95-2b4c-4a6f-b8d5-8ddc34326ca5" />

randpkt-2020-09-06-16170.pcap
<img width="1630" height="718" alt="image" src="https://github.com/user-attachments/assets/f39db83c-7d12-4c6d-b39c-716d9817af18" />


using puppeteer for auto testing

## 802.class integration

Open **802.class browser inference** on the start screen or in the graph toolbar.
Select a field logistic baseline model JSON and the AP radio BSSID, then click
**Run in browser** to classify the capture already loaded in the graph. An optional
capture override accepts another raw 802.11/radiotap PCAP or PCAPNG.
Capture parsing, BSSID/DS-bit
scoping, protected-frame filtering, retry deduplication, idle sessions, sliding
windows, 18-feature aggregation and logistic prediction all run locally in
JavaScript. No capture uploads or Python inference service are used.

**Load Example PCAP** separates monitor-mode captures (raw 802.11/radiotap frames)
from Ethernet/IP ones. Selecting a monitor-mode example (`perf/wpa-induction.pcap`
from the Wireshark wiki, or the synthetic `perf/80211-fixture.pcap`) fills in its AP
BSSID and immediately classifies its protected ToDS/FromDS data frames, badging the
client and AP nodes. Beacons, probes, ACKs, null-data and unprotected EAPOL frames are
drawn but never scored. These examples use `perf/demo-frame-size-model.json`, a
hand-weighted demo on mean data-frame payload size: its labels (small/mixed/bulk
frames) describe frame sizes, not applications. Choose a Model JSON to override it.

Use an existing 802.class `models/active_model.json`, or export a **trusted**
trained field baseline with the Python environment used by 802.class:

```sh
python scripts/export-browser-model.py /path/to/field_baseline.joblib model.json
python -m http.server 8000
node perf/test-classification.cjs
node perf/test-browser-inference.cjs
npm --prefix perf test
```

Open localhost port 8000 for worker-based inference with cancellation; direct
`file://` use falls back to main-thread inference and is limited to 16 MiB captures
(128 MiB over HTTP). Model JSON is limited to 5 MiB. Only native field logistic
baselines are supported for browser execution, not PyTorch/joblib files, TCN or
legacy checkpoints. The exporter loads pickle-based bundles: never use untrusted
checkpoints. Python is needed only for this optional one-time export.

The matching capture is visualized using AP/client infrastructure links. Predictions
appear directly beneath client nodes, with confidence and colored rings; the AP
gets its own badge. SVG and canvas rendering both support these annotations.
The setup panel closes after inference, leaving the graph and a compact inspector.
Click a node (or focus it and press Enter in SVG mode) to inspect the latest
session's classification, usable frames, and observation interval. Hide/show badges
or clear the overlay without changing the captured traffic. Loading another capture
clears the annotations to prevent stale predictions from following reused MACs.

Use **Model & results** to expand sessions for window predictions, highlight
clients/AP, and download result JSON. Node badges summarize the latest client
session across the capture; they do not claim an app prediction at the timeline
cursor. Older sessions remain available in the full results.
Existing baseline/TCN result JSON can also be imported for review. Inference
results are independent of packet timeline scrubbing. `unknown` follows the
model's threshold; short sessions report `insufficient_data`. Missing radio values
use the field schema's masks. Ethernet captures and untimestamped PCAPNG Simple
Packet Blocks are rejected; snaplen-truncated frames are excluded and counted.

Confidence describes observation windows, not individual packets. This does not
decrypt WPA2/WPA3 or TLS or train a model. The source project's active model may
contain `fixture_*` labels: these are synthetic smoke-test classes, **not evidence
of real-world app accuracy**. Supply a field-trained model for meaningful labels.

For numerical parity checks against the original pipeline, run
`python perf/test-python-parity.py /path/to/802.class` with its Python environment.
This trains temporary test baselines and compares binary/multiclass predictions
on generated monitor captures, with and without FCS. No test models are shipped.
