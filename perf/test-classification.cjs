const assert = require('node:assert/strict');
const { validate } = require('../classification.js');
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
console.log('Classification contract tests passed.');
