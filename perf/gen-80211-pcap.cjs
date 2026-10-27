'use strict';
// Deterministic synthetic monitor-mode capture (LINKTYPE_IEEE802_11_RADIOTAP) for
// the 802.11 classifier. Protected ToDS/FromDS data frames are what the classifier
// scores; beacons, probes, ACKs, null-data and unprotected EAPOL frames are mixed
// in, as in a real monitor capture, and must not change the inference result.
//
//   node gen-80211-pcap.cjs [--clients 6] [--frames 400] [--out 80211-fixture.pcap]
//
const { writeFileSync } = require('node:fs');
const { resolve } = require('node:path');

const arg = (k, d) => {
  const i = process.argv.indexOf('--' + k);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : d;
};

const CLIENTS = +arg('clients', 6);
const FRAMES  = +arg('frames', 400);
const SEED    = +arg('seed', 42);
const OUT     = resolve(arg('out', resolve(__dirname, '80211-fixture.pcap')));

function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
// Separate streams so adding non-data frames never perturbs the data frames.
const rnd = mulberry32(SEED);
const rndOther = mulberry32(SEED ^ 0x9e3779b9);
const ri = n => Math.floor(rnd() * n);
const pick = arr => arr[ri(arr.length)];

const AP_BSSID = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const BROADCAST = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
const clientMAC = i => [0x02, 0x00, 0x00, 0x00, 0x00, 0x10 + i];

const profiles = [
  { payloads: [60, 80, 120],          signals: [-35, -40],      rates: [54],     mcs: [7],    qos: true,  retryRate: 0.02 },
  { payloads: [200, 400, 800, 1400],  signals: [-55, -60, -65], rates: [24, 36], mcs: [4, 5], qos: true,  retryRate: 0.08 },
  { payloads: [40, 60],               signals: [-70, -75, -80], rates: [6, 12],  mcs: [0, 1], qos: true,  retryRate: 0.15 },
  { payloads: [100, 150],             signals: [-45, -50],      rates: [48],     mcs: [6],    qos: false, retryRate: 0.03 },
  { payloads: [1200, 1400],           signals: [-30, -32],      rates: [54],     mcs: [7],    qos: true,  retryRate: 0.01 },
  { payloads: [50, 70, 90],           signals: [-60, -62],      rates: [18],     mcs: [3],    qos: true,  retryRate: 0.10 },
];

const clients = Array.from({ length: CLIENTS }, (_, i) => ({
  mac: clientMAC(i),
  profile: profiles[i % profiles.length],
  sequence: 0,
  time: 1700000000 + rnd() * 2,
}));

function radiotap(body, { signal = -40, rate = 6, mcs = 0 } = {}) {
  const radio = Buffer.alloc(14);
  radio.writeUInt16LE(14, 2);
  radio.writeUInt32LE(0x00080026, 4);  // flags, rate, dBm signal, MCS
  radio[9] = rate * 2;
  radio.writeInt8(signal, 10);
  radio[11] = 0x07;
  radio[13] = mcs;
  return Buffer.concat([radio, body]);
}

function header(fc0, fc1, a1, a2, a3, sequence, length) {
  const frame = Buffer.alloc(length);
  frame[0] = fc0;
  frame[1] = fc1;
  frame.writeUInt16LE(fc0 & 0x0c ? 44 : 0, 2);
  Buffer.from(a1).copy(frame, 4);
  if (a2) Buffer.from(a2).copy(frame, 10);
  if (a3) Buffer.from(a3).copy(frame, 16);
  if (length >= 24) frame.writeUInt16LE((sequence & 0xfff) << 4, 22);
  return frame;
}

const records = [];
const counts = { data: 0, beacon: 0, probeReq: 0, probeResp: 0, ack: 0, nullData: 0, eapol: 0 };

// Classifier-relevant traffic: protected QoS/plain data, ToDS and FromDS.
for (let f = 0; f < FRAMES; f++) {
  const client = pick(clients);
  const p = client.profile;
  const down = rnd() < 0.4;
  const payload = pick(p.payloads);
  const signal = pick(p.signals);
  const rate = pick(p.rates);
  const mcs = pick(p.mcs);
  const isRetry = rnd() < p.retryRate;
  client.time += rnd() < 0.03 ? 20 + rnd() * 30 : 0.001 + rnd() * 0.1;
  client.sequence = (client.sequence + (isRetry ? 0 : 1)) % 4096;

  const headerLen = p.qos ? 26 : 24;
  const frame = header(p.qos ? 0x88 : 0x08, (down ? 2 : 1) | 0x40 | (isRetry ? 0x08 : 0),
    down ? client.mac : AP_BSSID, down ? AP_BSSID : client.mac, AP_BSSID, client.sequence, headerLen + payload);
  frame.writeUInt16LE(300 + ri(200), 2);
  if (p.qos) frame[24] = ri(8);
  for (let b = headerLen; b < frame.length; b++) frame[b] = (f + b + 14) & 0xff;
  records.push({ packet: radiotap(frame, { signal, rate, mcs }), time: client.time });
  counts.data++;

  if (rndOther() < 0.5) {
    const ack = header(0xd4, 0, down ? AP_BSSID : client.mac, null, null, 0, 10);
    records.push({ packet: radiotap(ack, { signal, rate: 24 }), time: client.time + 0.00005 });
    counts.ack++;
  }
}

const start = Math.min(...records.map(r => r.time));
const end = Math.max(...records.map(r => r.time));

// AP beacons once a second (SSID "netgraph-demo").
let apSequence = 0;
const ssid = Buffer.from('netgraph-demo');
for (let t = Math.floor(start); t <= end; t += 1) {
  const body = Buffer.concat([Buffer.alloc(12), Buffer.from([0, ssid.length]), ssid]);
  body.writeUInt16LE(100, 8);
  body.writeUInt16LE(0x0411, 10);
  const beacon = Buffer.concat([header(0x80, 0, BROADCAST, AP_BSSID, AP_BSSID, apSequence++, 24), body]);
  records.push({ packet: radiotap(beacon, { signal: -38, rate: 1 }), time: t + 0.0001 });
  counts.beacon++;
}

// Per client: probe exchange, unprotected EAPOL handshake, and power-save null-data.
for (const client of clients) {
  const first = Math.min(...records.filter(r => r.packet.includes(Buffer.from(client.mac))).map(r => r.time));
  let seq = 0;
  const probeReq = Buffer.concat([header(0x40, 0, BROADCAST, client.mac, BROADCAST, seq++, 24), Buffer.from([0, ssid.length]), ssid]);
  records.push({ packet: radiotap(probeReq, { signal: -50, rate: 1 }), time: first - 0.5 });
  counts.probeReq++;
  const probeResp = Buffer.concat([header(0x50, 0, client.mac, AP_BSSID, AP_BSSID, apSequence++, 24), Buffer.alloc(12), Buffer.from([0, ssid.length]), ssid]);
  records.push({ packet: radiotap(probeResp, { signal: -38, rate: 1 }), time: first - 0.49 });
  counts.probeResp++;
  for (let m = 0; m < 4; m++) {
    const down = m % 2 === 0;
    const eapol = header(0x88, down ? 2 : 1, down ? client.mac : AP_BSSID, down ? AP_BSSID : client.mac, AP_BSSID, 1000 + m, 26 + 99);
    Buffer.from([0xaa, 0xaa, 0x03, 0, 0, 0, 0x88, 0x8e]).copy(eapol, 26);
    records.push({ packet: radiotap(eapol, { signal: -45, rate: 24 }), time: first - 0.3 + m * 0.01 });
    counts.eapol++;
  }
  const nulls = 3 + Math.floor(rndOther() * 4);
  for (let n = 0; n < nulls; n++) {
    const qosNull = header(0xc8, 0x01 | (n % 2 ? 0x10 : 0), AP_BSSID, client.mac, AP_BSSID, 2000 + n, 26);
    records.push({ packet: radiotap(qosNull, { signal: -50, rate: 24 }), time: start + rndOther() * (end - start) });
    counts.nullData++;
  }
}

records.sort((a, b) => a.time - b.time);

const pcapHeader = Buffer.alloc(24);
pcapHeader.writeUInt32LE(0xa1b2c3d4, 0);
pcapHeader.writeUInt16LE(2, 4);
pcapHeader.writeUInt16LE(4, 6);
pcapHeader.writeUInt32LE(65535, 16);
pcapHeader.writeUInt32LE(127, 20);

const parts = [pcapHeader];
for (const { packet, time } of records) {
  const rec = Buffer.alloc(16);
  let seconds = Math.floor(time);
  let micros = Math.round((time - seconds) * 1e6);
  if (micros === 1e6) { seconds++; micros = 0; }
  rec.writeUInt32LE(seconds, 0);
  rec.writeUInt32LE(micros, 4);
  rec.writeUInt32LE(packet.length, 8);
  rec.writeUInt32LE(packet.length, 12);
  parts.push(rec, packet);
}
const buf = Buffer.concat(parts);
writeFileSync(OUT, buf);

console.log(`wrote ${OUT} (${(buf.length / 1024).toFixed(1)} KB, ${records.length} frames, ${CLIENTS} clients, BSSID 02:00:00:00:00:01, seed ${SEED})`);
console.log(`  protected data ${counts.data} · beacon ${counts.beacon} · probe req/resp ${counts.probeReq}/${counts.probeResp} · ACK ${counts.ack} · QoS-null ${counts.nullData} · EAPOL ${counts.eapol}`);
