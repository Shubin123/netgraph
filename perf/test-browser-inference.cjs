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

  // Multi-client radiotap fixture: exercises signal/rate/MCS parsing, session
  // splitting, retry dedup, and graph entry generation across several clients.
  const { readFileSync, existsSync } = require('node:fs');
  const { resolve, dirname } = require('node:path');
  const { graphEntries } = require('../classification.js');
  const fixturePath = resolve(dirname(__filename), '80211-fixture.pcap');
  if (!existsSync(fixturePath)) {
    require('node:child_process').execSync(`node ${resolve(dirname(__filename), 'gen-80211-pcap.cjs')}`, { stdio: 'inherit' });
  }
  const fixtureBuf = readFileSync(fixturePath);
  const fixtureAB = fixtureBuf.buffer.slice(fixtureBuf.byteOffset, fixtureBuf.byteOffset + fixtureBuf.byteLength);
  const fixtureModel = {
    kind: 'field-logistic-baseline-v1', schema_version: '80211-metadata-v1',
    feature_columns: [...inference.columns], window_size: 16, labels: ['streaming', 'browsing', 'voip'], classes: [0, 1, 2],
    coefficients: Array.from({ length: 3 }, (_, i) => Array.from({ length: 72 }, (_, j) => Math.sin(i * 7 + j * 3) * 0.1)),
    intercepts: [0.5, -0.2, 0.1], is_binary: false,
    preprocessing: { min_frames: 8, stride: 8, require_protected: true, deduplicate_retries: true, idle_timeout_seconds: 15 },
  };
  const fixtureResult = inference.infer(fixtureAB, fixtureModel, '02:00:00:00:00:01', '80211-fixture');
  assert.equal(validate(fixtureResult), fixtureResult);
  assert.equal(fixtureResult.status, 'ok');
  assert.ok(fixtureResult.sessions.length >= 10, `expected ≥10 sessions, got ${fixtureResult.sessions.length}`);
  assert.ok(fixtureResult.windows.length >= 30, `expected ≥30 windows, got ${fixtureResult.windows.length}`);
  assert.ok(fixtureResult.diagnostics.dropped_retries > 0, 'expected retry dedup');
  const clients = new Set(fixtureResult.sessions.map(s => s.client_mac));
  assert.ok(clients.size >= 5, `expected ≥5 clients, got ${clients.size}`);
  const multiSession = [...clients].some(mac => fixtureResult.sessions.filter(s => s.client_mac === mac).length > 1);
  assert.ok(multiSession, 'expected at least one client with multiple sessions (idle gap)');
  const hasInsufficient = fixtureResult.sessions.some(s => s.status === 'insufficient_data');
  assert.ok(hasInsufficient, 'expected at least one insufficient_data session');
  const entries = graphEntries(fixtureResult);
  assert.ok(entries.size >= 7, `expected ≥7 graph entries (AP + clients), got ${entries.size}`);
  const ap = entries.get('02:00:00:00:00:01');
  assert.ok(ap && ap.role === 'ap');
  for (const [mac, entry] of entries) {
    if (entry.role === 'client') {
      assert.ok(entry.label.length > 0);
      assert.ok(entry.description.includes(mac));
    }
  }
  const sampleObs = [];
  inference.packets(fixtureAB, (view, start, length, original, linkType, timestamp) => {
    if (sampleObs.length < 5) {
      const obs = inference.observation(view, start, length, timestamp, linkType);
      if (obs) sampleObs.push(obs);
    }
  });
  assert.ok(sampleObs.every(obs => obs.signal !== null), 'radiotap signal expected');
  assert.ok(sampleObs.every(obs => obs.rate !== null), 'radiotap rate expected');
  assert.ok(sampleObs.every(obs => obs.mcs !== null), 'radiotap MCS expected');
  console.log(`  fixture: ${fixtureResult.sessions.length} sessions, ${fixtureResult.windows.length} windows, ${clients.size} clients, ${fixtureResult.diagnostics.dropped_retries} retries deduped`);
  console.log('Browser inference tests passed.');
}

module.exports = { model, frame, pcap, pcapng, arrayBuffer };
if (require.main === module) run();
