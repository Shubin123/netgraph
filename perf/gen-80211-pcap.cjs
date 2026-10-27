'use strict';
// Deterministic synthetic 802.11 radiotap PCAP generator for classifier testing.
//
// Produces a classic LE PCAP (LINKTYPE_IEEE802_11_RADIOTAP) with multiple
// clients associated to a single AP, exercising the full inference pipeline:
// radiotap parsing (signal/rate/MCS), retry deduplication, session splitting,
// sliding windows, and multi-client graph entries.
//
//   node gen-80211-pcap.js [--clients 6] [--frames 400] [--out 80211-fixture.pcap]
//
const { writeFileSync } = require('node:fs');
const { resolve, dirname } = require('node:path');

const HERE = dirname(__filename);
const arg = (k, d) => {
  const i = process.argv.indexOf('--' + k);
  if (i >= 0 && i + 1 < process.argv.length) return process.argv[i + 1];
  return d;
};

const CLIENTS    = +arg('clients', 6);
const FRAMES     = +arg('frames', 400);
const SEED       = +arg('seed', 42);
const OUT        = resolve(arg('out', resolve(HERE, '80211-fixture.pcap')));

function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rnd = mulberry32(SEED);
const ri = n => Math.floor(rnd() * n);
const pick = arr => arr[ri(arr.length)];

const AP_BSSID = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const clientMAC = i => [0x02, 0x00, 0x00, 0x00, 0x00, 0x10 + i];

// Client profiles: different traffic patterns to exercise varied feature vectors.
const profiles = [
  { weight: 3, payloads: [60, 80, 120],  signals: [-35, -40], rates: [54], mcs: [7],  qos: true,  retryRate: 0.02 },
  { weight: 2, payloads: [200, 400, 800, 1400], signals: [-55, -60, -65], rates: [24, 36], mcs: [4, 5], qos: true, retryRate: 0.08 },
  { weight: 2, payloads: [40, 60],       signals: [-70, -75, -80], rates: [6, 12], mcs: [0, 1], qos: true,  retryRate: 0.15 },
  { weight: 1, payloads: [100, 150],     signals: [-45, -50], rates: [48], mcs: [6],  qos: false, retryRate: 0.03 },
  { weight: 1, payloads: [1200, 1400],   signals: [-30, -32], rates: [54], mcs: [7],  qos: true,  retryRate: 0.01 },
  { weight: 1, payloads: [50, 70, 90],   signals: [-60, -62], rates: [18], mcs: [3],  qos: true,  retryRate: 0.10 },
];

const clients = Array.from({ length: CLIENTS }, (_, i) => ({
  mac: clientMAC(i),
  profile: profiles[i % profiles.length],
  sequence: 0,
  time: 1700000000 + rnd() * 2,
  session: 0,
}));

const records = [];
for (let f = 0; f < FRAMES; f++) {
  const client = pick(clients);
  const p = client.profile;
  const down = rnd() < 0.4;
  const payload = pick(p.payloads);
  const signal = pick(p.signals);
  const rate = pick(p.rates);
  const mcs = pick(p.mcs);
  const isRetry = rnd() < p.retryRate;

  // Advance time: mostly short IATs, occasional session gap.
  const gap = rnd() < 0.03 ? 20 + rnd() * 30 : 0.001 + rnd() * 0.1;
  client.time += gap;

  client.sequence = (client.sequence + (isRetry ? 0 : 1)) % 4096;

  const frameLen = (p.qos ? 26 : 24) + payload;
  const radiotapLen = 14;
  const packetLen = radiotapLen + frameLen;

  const packet = Buffer.alloc(packetLen);

  // Radiotap header: version, pad, length, present(flags+rate+signal+MCS)
  packet[0] = 0;
  packet[1] = 0;
  packet.writeUInt16LE(radiotapLen, 2);
  packet.writeUInt32LE(0x00080026, 4);
  packet[8] = 0;                       // flags: no FCS, no padding
  packet[9] = rate * 2;                // rate in 500kbps units
  packet.writeInt8(signal, 10);        // signal dBm
  packet[11] = 0x07;                   // MCS known: bandwidth, MCS index, guard interval
  packet[12] = 0;                      // MCS flags
  packet[13] = mcs;                    // MCS index

  // 802.11 frame header
  const h = radiotapLen;
  packet[h] = p.qos ? 0x88 : 0x08;    // type=data, subtype=8(QoS) or 0(plain)
  const ds = down ? 2 : 1;
  packet[h + 1] = ds | 0x40 | (isRetry ? 0x08 : 0);  // protected + retry

  packet.writeUInt16LE(300 + ri(200), h + 2);  // duration

  if (down) {
    // FromDS: addr1=client, addr2=BSSID, addr3=source(BSSID)
    Buffer.from(client.mac).copy(packet, h + 4);
    Buffer.from(AP_BSSID).copy(packet, h + 10);
    Buffer.from(AP_BSSID).copy(packet, h + 16);
  } else {
    // ToDS: addr1=BSSID, addr2=client, addr3=dest(BSSID)
    Buffer.from(AP_BSSID).copy(packet, h + 4);
    Buffer.from(client.mac).copy(packet, h + 10);
    Buffer.from(AP_BSSID).copy(packet, h + 16);
  }

  packet.writeUInt16LE(client.sequence << 4, h + 22);

  if (p.qos) {
    packet[h + 24] = ri(8);  // TID 0-7
    packet[h + 25] = 0;
  }

  // Fill payload with deterministic bytes
  for (let b = (p.qos ? h + 26 : h + 24); b < packetLen; b++) {
    packet[b] = (f + b) & 0xff;
  }

  records.push({ packet, time: client.time });
}

// Sort by timestamp for a realistic packet ordering.
records.sort((a, b) => a.time - b.time);

// Write PCAP.
const pcapHeader = Buffer.alloc(24);
pcapHeader.writeUInt32LE(0xa1b2c3d4, 0);  // magic (LE, microsecond)
pcapHeader.writeUInt16LE(2, 4);
pcapHeader.writeUInt16LE(4, 6);
pcapHeader.writeInt32LE(0, 8);
pcapHeader.writeUInt32LE(0, 12);
pcapHeader.writeUInt32LE(65535, 16);
pcapHeader.writeUInt32LE(127, 20);         // LINKTYPE_IEEE802_11_RADIOTAP

const parts = [pcapHeader];
for (const { packet, time } of records) {
  const rec = Buffer.alloc(16);
  rec.writeUInt32LE(Math.floor(time), 0);
  rec.writeUInt32LE(Math.round((time % 1) * 1e6), 4);
  rec.writeUInt32LE(packet.length, 8);
  rec.writeUInt32LE(packet.length, 12);
  parts.push(rec, packet);
}

const buf = Buffer.concat(parts);
writeFileSync(OUT, buf);

const mb = (buf.length / 1024).toFixed(1);
const uniqueClients = new Set(records.map(r => {
  const h = r.packet[3] < 14 ? 14 : r.packet.readUInt16LE(2);
  const ds = r.packet[h + 1] & 3;
  return Array.from(r.packet.subarray(ds === 1 ? h + 10 : h + 4, (ds === 1 ? h + 10 : h + 4) + 6))
    .map(b => b.toString(16).padStart(2, '0')).join(':');
}));

console.log(`wrote ${OUT}`);
console.log(`  ${FRAMES} frames, ${mb} KB, ${uniqueClients.size} clients, BSSID 02:00:00:00:00:01`);
console.log(`  radiotap: signal/rate/MCS, link type 127`);
console.log(`  seed ${SEED}`);
