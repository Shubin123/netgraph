// Deterministic synthetic PCAP generator for perf testing netgraph/index.html.
//
// Produces a classic little-endian PCAP (LINKTYPE_ETHERNET) full of Ethernet/IPv4
// TCP+UDP frames arranged as a client/server topology, so the resulting graph has
// a predictable node and edge count — the two things that actually drive render cost.
//
//   node gen-pcap.js --hubs 60 --leaves 1940 --fanout 4 --packets 250000 --out synthetic.pcap
//
// Defaults give ~2,000 nodes / ~15k edges / ~14 MB — a deliberately "very large" graph.
import { writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const arg = (k, d) => {
  const i = process.argv.indexOf('--' + k);
  if (i >= 0 && i + 1 < process.argv.length) return process.argv[i + 1];
  return process.env[k.toUpperCase()] ?? d;
};

const HUBS    = +arg('hubs', 60);        // "server" IPs many leaves talk to
const LEAVES  = +arg('leaves', 1940);    // "client" IPs
const FANOUT  = +arg('fanout', 4);       // how many hubs each leaf talks to → edge count
const PACKETS = +arg('packets', 250000); // total packets → file size
const SEED    = +arg('seed', 1234);
const OUT     = resolve(arg('out', resolve(HERE, 'synthetic.pcap')));

// Small deterministic PRNG so runs are byte-for-byte reproducible.
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

// proto → [servicePort, ipProtoNum]; mix of TCP and UDP so the legend gets several colors.
const SERVICES = [
  [80, 6], [443, 6], [22, 6], [3389, 6], // HTTP / HTTPS / SSH / RDP (TCP)
  [53, 17],                              // DNS (UDP)
];

const hubIP  = i => [10, 0, (i >> 8) & 255, i & 255];
const leafIP = i => [10, 1 + ((i >> 16) & 255), (i >> 8) & 255, i & 255];
// Each leaf is pinned to FANOUT hubs (deterministic) → bounded, realistic edge set.
const hubsForLeaf = i => Array.from({ length: FANOUT }, (_, k) => (i * 7 + k * 131) % HUBS);

const REC = 16;          // pcap record header
const FRAME = 42;        // eth(14) + ipv4(20) + ports/payload(8)
const PKT = REC + FRAME;
const total = 24 + PACKETS * PKT;
const buf = Buffer.alloc(total);

// ── Global header ──
buf.writeUInt32LE(0xa1b2c3d4, 0); // magic (LE)
buf.writeUInt16LE(2, 4);          // version major
buf.writeUInt16LE(4, 6);          // version minor
buf.writeInt32LE(0, 8);           // thiszone
buf.writeUInt32LE(0, 12);         // sigfigs
buf.writeUInt32LE(65535, 16);     // snaplen
buf.writeUInt32LE(1, 20);         // network = LINKTYPE_ETHERNET

let o = 24;
const tsBase = 1_000_000_000;
const seen = new Set();           // track distinct nodes / edges for an accurate summary
const edgeSet = new Set();

for (let p = 0; p < PACKETS; p++) {
  const leaf = ri(LEAVES);
  const hub = hubsForLeaf(leaf)[ri(FANOUT)];
  const leafToHub = ri(2) === 0;
  const src = leafToHub ? leafIP(leaf) : hubIP(hub);
  const dst = leafToHub ? hubIP(hub) : leafIP(leaf);
  const [port, ipProto] = SERVICES[ri(SERVICES.length)];
  const sport = leafToHub ? 1024 + ri(64000) : port;
  const dport = leafToHub ? port : 1024 + ri(64000);

  seen.add(src.join('.')); seen.add(dst.join('.'));
  edgeSet.add(src.join('.') + '>' + dst.join('.'));

  // record header
  buf.writeUInt32LE(tsBase + ((p / 1000) | 0), o);
  buf.writeUInt32LE((p % 1000) * 1000, o + 4);
  buf.writeUInt32LE(FRAME, o + 8);
  buf.writeUInt32LE(FRAME, o + 12);

  const f = o + REC;
  // Ethernet: dst MAC, src MAC (02:00:<ip>), ethertype IPv4
  buf[f] = 0x02; buf[f + 1] = 0x00; buf.set(dst, f + 2);
  buf[f + 6] = 0x02; buf[f + 7] = 0x00; buf.set(src, f + 8);
  buf[f + 12] = 0x08; buf[f + 13] = 0x00;
  // IPv4 header
  const ip = f + 14;
  buf[ip] = 0x45; buf[ip + 1] = 0x00;
  buf.writeUInt16BE(28, ip + 2);            // total length (20 + 8)
  buf.writeUInt16BE(p & 0xffff, ip + 4);    // id
  buf[ip + 6] = 0; buf[ip + 7] = 0;         // flags/frag
  buf[ip + 8] = 64;                         // ttl
  buf[ip + 9] = ipProto;                    // 6 (TCP) / 17 (UDP)
  buf[ip + 10] = 0; buf[ip + 11] = 0;       // checksum (ignored by app)
  buf.set(src, ip + 12);
  buf.set(dst, ip + 16);
  // L4 ports (parser reads first 4 bytes as src/dst port)
  buf.writeUInt16BE(sport, ip + 20);
  buf.writeUInt16BE(dport, ip + 22);

  o += PKT;
}

writeFileSync(OUT, buf);

const mb = (total / 1048576).toFixed(1);
console.log(`✓ wrote ${OUT}`);
console.log(`  packets: ${PACKETS.toLocaleString()}   size: ${mb} MB`);
console.log(`  distinct nodes: ${seen.size.toLocaleString()}   distinct directed edges: ${edgeSet.size.toLocaleString()}`);
console.log(`  topology: ${HUBS} hubs × ${LEAVES} leaves, fanout ${FANOUT}, seed ${SEED}`);
