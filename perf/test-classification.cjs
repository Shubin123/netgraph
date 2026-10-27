const assert = require('node:assert/strict');
const { validate, graphEntries, badge } = require('../classification.js');
const result = {
  schema_version: '80211-metadata-v1', model_kind: 'field-tcn-v1',
  bssid: 'aa:bb:cc:dd:ee:ff', status: 'ok',
  sessions: [{ session_id: 'capture:client:0', client_mac: '02:00:00:00:00:01', frames: 32, prediction: 'unknown', confidence: 0.4 }],
  windows: [{ session_id: 'capture:client:0', client_mac: '02:00:00:00:00:01', valid_frames: 32, prediction: 'unknown', confidence: 0.4, start_timestamp: 1, end_timestamp: 2 }],
};
assert.equal(validate(result), result);
assert.equal(validate({ ...result, status: 'insufficient_data', sessions: [], windows: [] }).status, 'insufficient_data');
assert.equal(validate({ ...result, windows: [], sessions: [{ ...result.sessions[0], status: 'insufficient_data', prediction: undefined, confidence: undefined }] }).sessions.length, 1);
for (const patch of [{ schema_version: 'legacy' }, { model_kind: 'legacy' }, { bssid: 'bad' }, { sessions: null }, { windows: {} }, { status: 'bad' }]) {
  assert.throws(() => validate({ ...result, ...patch }));
}
for (const patch of [{ confidence: 2 }, { confidence: NaN }, { start_timestamp: 3 }, { session_id: 'missing' }, { client_mac: '02:00:00:00:00:02' }, { valid_frames: -1 }]) {
  assert.throws(() => validate({ ...result, windows: [{ ...result.windows[0], ...patch }] }));
}
assert.throws(() => validate({ ...result, sessions: [...result.sessions, ...result.sessions] }));
const entries = graphEntries(result);
assert.equal(entries.get(result.bssid).role, 'ap');
assert.equal(entries.get(result.bssid).label, 'AP · 1 client');
assert.equal(entries.get(result.sessions[0].client_mac).label, 'unknown · 40.0%');
const multiple = graphEntries({ ...result, windows: [], sessions: [
  { ...result.sessions[0], session_id: 'later', prediction: 'video', confidence: 0.9, start_timestamp: 30, end_timestamp: 40 },
  { ...result.sessions[0], session_id: 'earlier', prediction: 'chat', confidence: 0.8, start_timestamp: 10, end_timestamp: 20 },
] });
assert.equal(multiple.get(result.sessions[0].client_mac).label, 'video · 90.0%');
assert.equal(multiple.get(result.sessions[0].client_mac).sessionCount, 2);
assert.match(multiple.get(result.sessions[0].client_mac).description, /independent of packet timeline/);
const insufficient = graphEntries({ ...result, windows: [], sessions: [{ ...result.sessions[0], status: 'insufficient_data', prediction: undefined, confidence: undefined }] });
assert.equal(insufficient.get(result.sessions[0].client_mac).label, 'Insufficient data');
assert.equal(badge({ label: 'a'.repeat(256) }).length, 40);
assert.equal(badge(undefined), '');
console.log('Classification contract tests passed.');
