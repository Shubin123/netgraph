const assert = require('node:assert/strict');
const inference = require('../browser-inference.js');
const { validate } = require('../classification.js');

function model() {
  return {
    kind: 'field-logistic-baseline-v1', schema_version: '80211-metadata-v1',
    feature_columns: [...inference.columns], window_size: 4, labels: ['small', 'large'], classes: [0, 1],
    coefficients: [Array(72).fill(0)], intercepts: [2], is_binary: true,
    preprocessing: { min_frames: 2, stride: 2, require_protected: true, deduplicate_retries: true, idle_timeout_seconds: 15 },
  };
}

function frame({ sequence = 1, down = false, retry = false, protectedFrame = true, radiotap = false, fcs = false, ds = null } = {}) {
  const packet = Buffer.alloc(42 + (fcs ? 4 : 0));
  packet[0] = 0x88;
  packet[1] = (ds ?? (down ? 2 : 1)) | (protectedFrame ? 64 : 0) | (retry ? 8 : 0);
  Buffer.from(down ? '020000000011' : '020000000001', 'hex').copy(packet, 4);
  Buffer.from(down ? '020000000001' : '020000000011', 'hex').copy(packet, 10);
  Buffer.from('0200000000aa', 'hex').copy(packet, 16);
  packet.writeUInt16LE(sequence << 4, 22);
  packet[24] = 3;
  if (!radiotap) return packet;
  const radio = Buffer.alloc(12);
  radio.writeUInt16LE(12, 2);
  radio.writeUInt32LE(0x26, 4);
  radio[8] = fcs ? 16 : 0;
  radio[9] = 12;
  radio.writeInt8(-42, 10);
  return Buffer.concat([radio, packet]);
}

function pcap(records, { little = true, nano = false, linkType = 105 } = {}) {
  const header = Buffer.alloc(24);
  const write32 = (buffer, value, offset) => little ? buffer.writeUInt32LE(value, offset) : buffer.writeUInt32BE(value, offset);
  write32(header, nano ? 0xa1b23c4d : 0xa1b2c3d4, 0);
  write32(header, 65535, 16);
  write32(header, linkType, 20);
  return Buffer.concat([header, ...records.flatMap(({ packet, time, original }) => {
    const record = Buffer.alloc(16);
    write32(record, Math.floor(time), 0);
    write32(record, Math.round((time % 1) * (nano ? 1e9 : 1e6)), 4);
    write32(record, packet.length, 8);
    write32(record, original ?? packet.length, 12);
    return [record, packet];
  })]);
}

function arrayBuffer(buffer) { return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength); }

function pcapng(packet, little = true) {
  const write32 = (buffer, value, offset) => little ? buffer.writeUInt32LE(value, offset) : buffer.writeUInt32BE(value, offset);
  const write16 = (buffer, value, offset) => little ? buffer.writeUInt16LE(value, offset) : buffer.writeUInt16BE(value, offset);
  function block(type, body) {
    const result = Buffer.alloc(12 + body.length);
    write32(result, type, 0); write32(result, result.length, 4);
    body.copy(result, 8); write32(result, result.length, result.length - 4);
    return result;
  }
  const section = Buffer.alloc(16);
  write32(section, 0x1a2b3c4d, 0); write16(section, 1, 4); section.fill(255, 8);
  const ethernet = Buffer.alloc(8); write16(ethernet, 1, 0);
  const radio = Buffer.alloc(20); write16(radio, 105, 0);
  write16(radio, 9, 8); write16(radio, 1, 10); radio[12] = 9;
  const body = Buffer.alloc(20 + Math.ceil(packet.length / 4) * 4);
  write32(body, 1, 0); write32(body, 0, 4); write32(body, 1234567890, 8);
  write32(body, packet.length, 12); write32(body, packet.length, 16); packet.copy(body, 20);
  return Buffer.concat([block(0x0a0d0d0a, section), block(1, ethernet), block(1, radio), block(6, body)]);
}

function run() {
  const records = Array.from({ length: 6 }, (_, index) => ({ packet: frame({ sequence: index + 1, down: index % 2 === 1 }), time: 100 + index * 0.05 }));
  for (const little of [true, false]) for (const nano of [true, false]) {
    const result = inference.infer(arrayBuffer(pcap(records, { little, nano })), model(), '02:00:00:00:00:01');
    assert.equal(validate(result), result);
    assert.equal(result.windows.length, 3);
    assert.equal(result.sessions[0].prediction, 'large');
    assert.equal(result.sessions[0].frames, 6);
    assert.equal(result.windows[0].valid_frames, 4);
    assert.ok(Math.abs(result.windows[0].end_timestamp - 100.15) < 1e-7);
  }
  const duplicate = [...records.slice(0, 1), { packet: frame({ retry: true }), time: 100.01 }, ...records.slice(1)];
  assert.equal(inference.infer(arrayBuffer(pcap(duplicate)), model(), '02:00:00:00:00:01').diagnostics.dropped_retries, 1);
  const lone = inference.infer(arrayBuffer(pcap([{ packet: frame({ retry: true }), time: 100 }])), model(), '02:00:00:00:00:01');
  assert.equal(lone.sessions[0].frames, 1);
  assert.equal(lone.sessions[0].status, 'insufficient_data');
  const gaps = [...records, ...records.map(record => ({ ...record, time: record.time + 20 }))];
  assert.equal(inference.infer(arrayBuffer(pcap(gaps)), model(), '02:00:00:00:00:01').sessions.length, 2);
  const unknownModel = { ...model(), unknown_threshold: 0.99 };
  assert.equal(inference.infer(arrayBuffer(pcap(records)), unknownModel, '02:00:00:00:00:01').sessions[0].prediction, 'unknown');
  assert.equal(inference.infer(arrayBuffer(pcap(records)), model(), '02:00:00:00:00:02').status, 'insufficient_data');
  for (const packet of [frame({ ds: 0 }), frame({ ds: 3 }), frame({ protectedFrame: false })]) {
    assert.equal(inference.infer(arrayBuffer(pcap([{ packet, time: 1 }])), model(), '02:00:00:00:00:01').sessions.length, 0);
  }
  const radioPacket = frame({ radiotap: true, fcs: true });
  const obs = inference.observation(new DataView(arrayBuffer(radioPacket)), 0, radioPacket.length, 1, 127);
  assert.equal(obs.mpduLength, 46); assert.equal(obs.payloadLength, 18);
  assert.equal(obs.signal, -42); assert.equal(obs.rate, 6);
  const row = inference.features([obs])[0];
  assert.equal(row[3], 0); assert.equal(row[6], 0); assert.equal(row[8], 1); assert.equal(row[13], 0); assert.equal(row[17], 1);
  for (const little of [true, false]) {
    const capture = pcapng(frame(), little);
    const timestamps = [];
    inference.packets(arrayBuffer(capture), (view, start, length, original, linkType, time) => { timestamps.push(time); assert.equal(linkType, 105); });
    assert.ok(Math.abs(timestamps[0] - 1.23456789) < 1e-9);
    assert.equal(inference.infer(arrayBuffer(capture), model(), '02:00:00:00:00:01').sessions.length, 1);
    const broken = Buffer.from(capture); broken[broken.length - 1] ^= 1;
    assert.throws(() => inference.infer(arrayBuffer(broken), model(), '02:00:00:00:00:01'), /length/);
  }
  const truncated = pcap([{ packet: frame(), time: 1, original: 100 }]);
  assert.equal(inference.infer(arrayBuffer(truncated), model(), '02:00:00:00:00:01').diagnostics.truncated_packets, 1);
  assert.throws(() => inference.infer(arrayBuffer(pcap(records, { linkType: 1 })), model(), '02:00:00:00:00:01'), /requires raw/);
  assert.throws(() => inference.infer(arrayBuffer(pcap(records).subarray(0, 40)), model(), '02:00:00:00:00:01'), /Truncated/);
  assert.throws(() => inference.validateModel({ ...model(), feature_columns: [] }), /feature order/);
  assert.throws(() => inference.validateModel({ ...model(), coefficients: [[NaN]] }), /coefficients/);
  assert.throws(() => inference.validateModel({ ...model(), preprocessing: { min_frames: 5 } }), /preprocessing/);
  const multiclass = inference.validateModel({ ...model(), is_binary: false, labels: ['first', 'second', 'third'], classes: [0, 1, 2], coefficients: Array.from({ length: 3 }, () => Array(72).fill(0)), intercepts: [1000, 1001, 1002] });
  assert.equal(inference.predict(multiclass, Array(72).fill(0)).prediction, 'third');

  // Monitor-mode samples from the example menu, scored with the bundled demo model.
  // Only protected ToDS/FromDS data frames may drive inference.
  const { readFileSync } = require('node:fs');
  const { resolve } = require('node:path');
  const { graphEntries } = require('../classification.js');
  const demoModel = JSON.parse(readFileSync(resolve(__dirname, 'demo-frame-size-model.json'), 'utf8'));
  assert.deepEqual(demoModel.feature_columns, inference.columns);

  function monitorSample(name, bssid) {
    const buffer = readFileSync(resolve(__dirname, name));
    const census = frameCensus(buffer, bssid);
    const result = inference.infer(arrayBuffer(buffer), demoModel, bssid, name);
    assert.equal(validate(result), result);
    assert.equal(result.status, 'ok');
    assert.ok(census.management > 0, `${name}: expected management frames alongside data`);
    assert.ok(census.data > census.scored, `${name}: expected unscored data frames (null/unprotected/multicast)`);
    const usedFrames = result.sessions.reduce((sum, session) => sum + session.frames, 0) + result.diagnostics.dropped_retries;
    assert.equal(usedFrames, census.scored, `${name}: inference must use exactly the protected unicast data frames`);
    const dataOnly = inference.infer(arrayBuffer(census.dataOnly), demoModel, bssid, name);
    assert.deepEqual(dataOnly.sessions, result.sessions, `${name}: non-data frames changed sessions`);
    assert.deepEqual(dataOnly.windows, result.windows, `${name}: non-data frames changed windows`);
    console.log(`  ${name}: ${census.total} frames (${census.management} mgmt, ${census.control} ctrl, ${census.data} data) → ${census.scored} scored data frames → ${result.sessions.length} sessions, ${result.windows.length} windows`);
    return result;
  }

  const fixture = monitorSample('80211-fixture.pcap', '02:00:00:00:00:01');
  assert.ok(fixture.diagnostics.dropped_retries > 0, 'expected retry dedup');
  const clients = new Set(fixture.sessions.map(s => s.client_mac));
  assert.equal(clients.size, 6);
  assert.ok([...clients].some(mac => fixture.sessions.filter(s => s.client_mac === mac).length > 1), 'expected an idle-gap session split');
  assert.ok(fixture.sessions.some(s => s.status === 'insufficient_data'));
  const windowLabels = mac => new Set(fixture.windows.filter(w => w.client_mac === mac).map(w => w.prediction));
  assert.deepEqual(windowLabels('02:00:00:00:00:10'), new Set(['small frames']));
  assert.deepEqual(windowLabels('02:00:00:00:00:11'), new Set(['mixed frames']));
  assert.deepEqual(windowLabels('02:00:00:00:00:14'), new Set(['bulk frames']));
  const entries = graphEntries(fixture);
  assert.equal(entries.get('02:00:00:00:00:01').label, 'AP · 6 clients');
  assert.match(entries.get('02:00:00:00:00:14').label, /^bulk frames · /);
  const observations = [];
  inference.packets(arrayBuffer(readFileSync(resolve(__dirname, '80211-fixture.pcap'))), (view, start, length, original, linkType, timestamp) => {
    const observation = inference.observation(view, start, length, timestamp, linkType);
    if (observation) observations.push(observation);
  });
  assert.ok(observations.every(o => o.signal !== null && o.rate !== null && o.mcs !== null), 'radiotap signal/rate/MCS expected');

  const wpa = monitorSample('wpa-induction.pcap', '00:0c:41:82:b2:55');
  assert.ok(wpa.diagnostics.dropped_retries >= 1, 'expected retry dedup in real capture');
  assert.ok(graphEntries(wpa).has('00:0c:41:82:b2:55'));
  console.log('Browser inference tests passed.');
}

// Classic-PCAP 802.11 census: frame counts by type, the number of data frames the
// classifier should score for `bssid`, and a copy holding only data-type frames.
function frameCensus(buffer, bssid) {
  const magic = buffer.readUInt32LE(0);
  const little = magic === 0xa1b2c3d4 || magic === 0xa1b23c4d;
  const read32 = offset => little ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
  const linkType = read32(20) & 0xffff;
  const census = { total: 0, management: 0, control: 0, data: 0, scored: 0 };
  const kept = [buffer.subarray(0, 24)];
  const mac = at => [...buffer.subarray(at, at + 6)].map(b => b.toString(16).padStart(2, '0')).join(':');
  for (let offset = 24; offset + 16 <= buffer.length;) {
    const length = read32(offset + 8);
    const start = offset + 16;
    const next = start + length;
    const frame = linkType === 127 ? start + buffer.readUInt16LE(start + 2) : start;
    census.total++;
    const fc = buffer[frame], flags = buffer[frame + 1], type = (fc >> 2) & 3, subtype = fc >> 4, ds = flags & 3;
    if (type === 0) census.management++;
    else if (type === 1) census.control++;
    else if (type === 2) {
      census.data++;
      kept.push(buffer.subarray(offset, next));
      const qos = subtype >= 8;
      if ([0, 1, 2, 3, 8, 9, 10, 11].includes(subtype) && (ds === 1 || ds === 2) && (flags & 0x40)
        && length === read32(offset + 12) && next - frame >= 24 + (qos ? 2 : 0)) {
        const client = mac(frame + (ds === 1 ? 10 : 4));
        if (mac(frame + (ds === 1 ? 4 : 10)) === bssid && !(parseInt(client.slice(0, 2), 16) & 1) && client !== bssid) census.scored++;
      }
    }
    offset = next;
  }
  return { ...census, dataOnly: Buffer.concat(kept) };
}

module.exports = { model, frame, pcap, pcapng, arrayBuffer };
if (require.main === module) run();
