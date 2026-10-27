'use strict';

const BrowserInference = (() => {
  const schema = '80211-metadata-v1';
  const columns = ['direction', 'mpdu_len', 'payload_len', 'iat_ms', 'log_iat', 'is_retry', 'seq_delta', 'qos_tid', 'has_qos', 'is_protected', 'subtype', 'duration', 'signal_dbm', 'signal_missing', 'data_rate', 'rate_missing', 'mcs_index', 'mcs_missing'];
  const macPattern = /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/;
  const fail = message => { throw new Error(message); };
  const positiveInteger = value => Number.isSafeInteger(value) && value > 0;

  function validateModel(model) {
    if (!model || model.kind !== 'field-logistic-baseline-v1') fail('Select an exported field logistic baseline JSON model. TCN/legacy checkpoints are not supported.');
    if (model.schema_version !== schema || JSON.stringify(model.feature_columns) !== JSON.stringify(columns)) fail('Model metadata schema or feature order mismatch.');
    if (!positiveInteger(model.window_size) || model.window_size > 65536) fail('Invalid model window size.');
    if (!Array.isArray(model.labels) || model.labels.length < 2 || model.labels.length > 1000 || model.labels.some(label => typeof label !== 'string' || !label || label.length > 256) || new Set(model.labels).size !== model.labels.length) fail('Invalid model labels.');
    if (!Array.isArray(model.classes) || model.classes.length !== model.labels.length || model.classes.some((value, index) => value !== index)) fail('Model classes must match label indices in order.');
    const binary = model.is_binary === true;
    if (typeof model.is_binary !== 'boolean' || (binary && model.labels.length !== 2)) fail('Invalid binary model flag.');
    const rows = binary ? 1 : model.labels.length;
    if (!Array.isArray(model.coefficients) || model.coefficients.length !== rows || model.coefficients.some(row => !Array.isArray(row) || row.length !== columns.length * 4 || row.some(value => !Number.isFinite(value)))) fail('Invalid model coefficients.');
    if (!Array.isArray(model.intercepts) || model.intercepts.length !== rows || model.intercepts.some(value => !Number.isFinite(value))) fail('Invalid model intercepts.');
    const pre = model.preprocessing || {};
    const preprocessing = {
      require_protected: pre.require_protected ?? true,
      deduplicate_retries: pre.deduplicate_retries ?? true,
      min_frames: pre.min_frames ?? Math.min(16, model.window_size),
      stride: pre.stride ?? Math.max(1, Math.floor(model.window_size / 2)),
      idle_timeout_seconds: pre.idle_timeout_seconds ?? 15,
    };
    if (typeof preprocessing.require_protected !== 'boolean' || typeof preprocessing.deduplicate_retries !== 'boolean' || !positiveInteger(preprocessing.min_frames) || preprocessing.min_frames > model.window_size || !positiveInteger(preprocessing.stride) || !Number.isFinite(preprocessing.idle_timeout_seconds) || preprocessing.idle_timeout_seconds <= 0) fail('Invalid model preprocessing.');
    const threshold = model.unknown_threshold ?? 0;
    if (!Number.isFinite(threshold) || threshold < 0 || threshold > 1) fail('Invalid unknown threshold.');
    return { ...model, preprocessing, unknown_threshold: threshold };
  }

  function packets(buffer, visit) {
    const view = new DataView(buffer);
    const size = view.byteLength;
    const requireBytes = (start, length) => {
      if (start < 0 || length < 0 || start + length > size) fail('Truncated capture.');
    };
    requireBytes(0, 4);
    const magic = view.getUint32(0, true);
    let little = true;
    if (magic !== 0x0a0d0d0a) {
      requireBytes(0, 24);
      if (![0xa1b2c3d4, 0xa1b23c4d, 0xd4c3b2a1, 0x4d3cb2a1].includes(magic)) fail('Invalid PCAP magic.');
      little = magic === 0xa1b2c3d4 || magic === 0xa1b23c4d;
      const resolution = magic === 0xa1b23c4d || magic === 0x4d3cb2a1 ? 1e-9 : 1e-6;
      const linkType = view.getUint32(20, little) & 0xffff;
      for (let offset = 24; offset < size;) {
        requireBytes(offset, 16);
        const length = view.getUint32(offset + 8, little);
        const original = view.getUint32(offset + 12, little);
        requireBytes(offset + 16, length);
        if (length > original) fail('Invalid captured packet length.');
        visit(view, offset + 16, length, original, linkType, view.getUint32(offset, little) + view.getUint32(offset + 4, little) * resolution);
        offset += 16 + length;
      }
      return;
    }
    let interfaces = [];
    for (let offset = 0; offset < size;) {
      requireBytes(offset, 12);
      const section = view.getUint32(offset, true) === 0x0a0d0d0a;
      if (section) {
        const bom = view.getUint32(offset + 8, true);
        if (bom !== 0x1a2b3c4d && bom !== 0x4d3c2b1a) fail('Invalid PCAPNG byte order.');
        little = bom === 0x1a2b3c4d;
      }
      const type = view.getUint32(offset, little);
      const length = view.getUint32(offset + 4, little);
      if (length < 12 || length % 4) fail('Invalid PCAPNG block length.');
      requireBytes(offset, length);
      if (view.getUint32(offset + length - 4, little) !== length) fail('PCAPNG block length mismatch.');
      const end = offset + length - 4;
      if (section) {
        if (length < 28) fail('Truncated PCAPNG section.');
        interfaces = [];
      } else if (type === 1) {
        if (length < 20) fail('Truncated PCAPNG interface.');
        const descriptor = { linkType: view.getUint16(offset + 8, little), resolution: 1e-6, timeOffset: 0 };
        for (let option = offset + 16; option + 4 <= end;) {
          const code = view.getUint16(option, little);
          const count = view.getUint16(option + 2, little);
          if (!code) break;
          if (option + 4 + count > end) fail('Truncated interface option.');
          if (code === 9 && count === 1) {
            const value = view.getUint8(option + 4);
            descriptor.resolution = value & 128 ? 2 ** -(value & 127) : 10 ** -value;
          }
          if (code === 14 && count === 8) descriptor.timeOffset = Number(view.getBigInt64(option + 4, little));
          option += 4 + Math.ceil(count / 4) * 4;
        }
        interfaces.push(descriptor);
      } else if (type === 6 || type === 2) {
        if (length < 32) fail('Truncated PCAPNG packet block.');
        const descriptor = interfaces[type === 6 ? view.getUint32(offset + 8, little) : view.getUint16(offset + 8, little)];
        if (!descriptor) fail('Unknown PCAPNG interface.');
        const captured = view.getUint32(offset + 20, little);
        const original = view.getUint32(offset + 24, little);
        if (captured > original || offset + 28 + Math.ceil(captured / 4) * 4 > end) fail('Invalid PCAPNG packet length.');
        const timestamp = (view.getUint32(offset + 12, little) * 4294967296 + view.getUint32(offset + 16, little)) * descriptor.resolution + descriptor.timeOffset;
        visit(view, offset + 28, captured, original, descriptor.linkType, timestamp);
      } else if (type === 3) {
        fail('PCAPNG Simple Packet Blocks lack timestamps; use timestamped Enhanced Packet Blocks for inference.');
      }
      offset += length;
    }
  }

  function observation(view, start, length, timestamp, linkType) {
    if (linkType !== 105 && linkType !== 127) return null;
    let offset = start;
    let signal = null, rate = null, mcs = null, flags = 0;
    if (linkType === 127) {
      if (length < 8 || view.getUint8(start) !== 0) fail('Invalid radiotap header.');
      const headerLength = view.getUint16(start + 2, true);
      if (headerLength < 8 || headerLength > length) fail('Truncated radiotap header.');
      let bitmapOffset = 4, bitmap;
      do {
        if (bitmapOffset + 4 > headerLength) fail('Truncated radiotap bitmap.');
        bitmap = view.getUint32(start + bitmapOffset, true);
        bitmapOffset += 4;
      } while (bitmap & 0x80000000);
      const present = view.getUint32(start + 4, true);
      const fields = [[8, 8], [1, 1], [1, 1], [2, 4], [2, 2], [1, 1], [1, 1], [2, 2], [2, 2], [2, 2], [1, 1], [1, 1], [1, 1], [1, 1], [2, 2], [2, 2], [1, 1], [1, 1], [4, 8], [1, 3]];
      let cursor = bitmapOffset;
      for (let bit = 0; bit <= 19; bit++) {
        if (!(present & (1 << bit))) continue;
        const [alignment, count] = fields[bit];
        cursor = Math.ceil(cursor / alignment) * alignment;
        if (cursor + count > headerLength) fail('Truncated radiotap field.');
        if (bit === 1) flags = view.getUint8(start + cursor);
        if (bit === 2) rate = view.getUint8(start + cursor) / 2;
        if (bit === 5) signal = view.getInt8(start + cursor);
        if (bit === 19) mcs = view.getUint8(start + cursor + 2);
        cursor += count;
      }
      if (flags & 0x20) fail('Radiotap data padding is unsupported; provide an unpadded capture.');
      offset += headerLength;
    }
    const available = length - (offset - start);
    if (available < 24) return null;
    const control = view.getUint8(offset);
    const subtype = control >> 4;
    if (((control >> 2) & 3) !== 2 || ![0, 1, 2, 3, 8, 9, 10, 11].includes(subtype)) return null;
    const frameFlags = view.getUint8(offset + 1);
    const ds = frameFlags & 3;
    if (ds !== 1 && ds !== 2) return null;
    const address = position => Array.from({ length: 6 }, (_, index) => view.getUint8(offset + position + index).toString(16).padStart(2, '0')).join(':');
    const bssid = address(ds === 1 ? 4 : 10);
    const client = address(ds === 1 ? 10 : 4);
    if ((parseInt(client.slice(0, 2), 16) & 1) || client === bssid) return null;
    const qos = subtype >= 8;
    if (available < 24 + (qos ? 2 : 0)) return null;
    const sequence = view.getUint16(offset + 22, true);
    const mpduLength = available;
    const payloadLength = available - 24 - ((flags & 0x10) ? 4 : 0);
    if (payloadLength < (qos ? 2 : 0)) return null;
    return { timestamp, bssid, client, direction: ds === 1 ? 1 : -1, mpduLength,
      payloadLength, retry: !!(frameFlags & 8), protected: !!(frameFlags & 64),
      sequence: sequence >> 4, fragment: sequence & 15, tid: qos ? view.getUint8(offset + 24) & 15 : null,
      subtype, duration: view.getUint16(offset + 2, true), signal, rate, mcs };
  }

  function features(frames) {
    let previousTime = null;
    const sequences = new Map();
    return frames.map(frame => {
      const iat = previousTime === null ? 0 : Math.min(60000, Math.max(0, frame.timestamp - previousTime) * 1000);
      previousTime = frame.timestamp;
      const previousSequence = sequences.get(frame.direction);
      const delta = previousSequence === undefined ? 0 : (frame.sequence - previousSequence + 4096) % 4096;
      sequences.set(frame.direction, frame.sequence);
      return [frame.direction, frame.mpduLength, frame.payloadLength, iat, Math.log1p(iat), Number(frame.retry), delta,
        frame.tid ?? 0, Number(frame.tid !== null), Number(frame.protected), frame.subtype, frame.duration,
        frame.signal ?? 0, Number(frame.signal === null), frame.rate ?? 0, Number(frame.rate === null), frame.mcs ?? 0, Number(frame.mcs === null)].map(Math.fround);
    });
  }

  function aggregate(rows) {
    const means = [], deviations = [], minima = [], maxima = [];
    for (let feature = 0; feature < columns.length; feature++) {
      const values = rows.map(row => row[feature]);
      const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
      means.push(Math.fround(mean));
      deviations.push(Math.fround(Math.sqrt(values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / values.length)));
      minima.push(Math.min(...values));
      maxima.push(Math.max(...values));
    }
    return [...means, ...deviations, ...minima, ...maxima];
  }

  function predict(model, values) {
    const scores = model.coefficients.map((weights, index) => weights.reduce((sum, weight, feature) => sum + weight * values[feature], model.intercepts[index]));
    if (scores.some(score => !Number.isFinite(score))) fail('Non-finite model output.');
    let probabilities;
    if (model.is_binary) {
      const probability = 1 / (1 + Math.exp(-scores[0]));
      probabilities = [1 - probability, probability];
    } else {
      const maximum = Math.max(...scores);
      const exponents = scores.map(score => Math.exp(score - maximum));
      const denominator = exponents.reduce((sum, value) => sum + value, 0);
      probabilities = exponents.map(value => value / denominator);
    }
    const confidence = Math.max(...probabilities);
    const known = model.labels[probabilities.indexOf(confidence)];
    return { prediction: confidence >= model.unknown_threshold ? known : 'unknown', known_prediction: known, confidence, threshold: model.unknown_threshold };
  }

  function infer(buffer, rawModel, rawBssid, captureName = 'capture') {
    const model = validateModel(rawModel);
    const bssid = String(rawBssid).trim().toLowerCase().replace(/-/g, ':');
    if (!macPattern.test(bssid) || (parseInt(bssid.slice(0, 2), 16) & 1)) fail('Enter a unicast AP radio BSSID.');
    const frames = [];
    let supportedPackets = 0, truncatedPackets = 0;
    packets(buffer, (view, start, length, original, linkType, timestamp) => {
      if (![105, 127].includes(linkType)) return;
      supportedPackets++;
      if (length < original) { truncatedPackets++; return; }
      const frame = observation(view, start, length, timestamp, linkType);
      if (frame && frame.bssid === bssid && (!model.preprocessing.require_protected || frame.protected)) frames.push(frame);
      if (frames.length > 1000000) fail('Capture exceeds one million scoped frames; split the capture.');
    });
    if (!supportedPackets) fail('Inference requires raw 802.11 (105) or radiotap (127), not Ethernet/IP traffic.');
    frames.sort((first, second) => first.timestamp - second.timestamp);
    const sessions = [], active = new Map(), ordinals = new Map(), seen = new Map();
    let droppedRetries = 0;
    for (const frame of frames) {
      const key = [frame.client, frame.direction, frame.tid, frame.sequence, frame.fragment].join('/');
      const prior = seen.get(key);
      if (model.preprocessing.deduplicate_retries && frame.retry && prior !== undefined && frame.timestamp - prior <= 1) { droppedRetries++; continue; }
      seen.set(key, frame.timestamp);
      let session = active.get(frame.client);
      if (!session || frame.timestamp - session.frames.at(-1).timestamp > model.preprocessing.idle_timeout_seconds) {
        const ordinal = (ordinals.get(frame.client) || 0) + 1;
        ordinals.set(frame.client, ordinal);
        session = { session_id: `${captureName}:${frame.client}:${String(ordinal).padStart(3, '0')}`, client_mac: frame.client, frames: [] };
        sessions.push(session);
        active.set(frame.client, session);
      }
      session.frames.push(frame);
    }
    const result = { schema_version: schema, pcap: captureName, bssid, model_kind: model.kind, window_size: model.window_size,
      min_frames: model.preprocessing.min_frames, status: 'insufficient_data', sessions: [], windows: [],
      diagnostics: { supported_packets: supportedPackets, truncated_packets: truncatedPackets, dropped_retries: droppedRetries } };
    for (const session of sessions) {
      const hits = [];
      for (let start = 0; start < session.frames.length; start += model.preprocessing.stride) {
        const chunk = session.frames.slice(start, start + model.window_size);
        if (chunk.length < model.preprocessing.min_frames) break;
        const windowResult = { session_id: session.session_id, client_mac: session.client_mac, start_timestamp: chunk[0].timestamp,
          end_timestamp: chunk.at(-1).timestamp, valid_frames: chunk.length, ...predict(model, aggregate(features(chunk))) };
        hits.push(windowResult);
        result.windows.push(windowResult);
        if (result.windows.length + sessions.length > 50000) fail('Too many inference records; split the capture.');
      }
      const summary = { session_id: session.session_id, client_mac: session.client_mac, start_timestamp: session.frames[0].timestamp,
        end_timestamp: session.frames.at(-1).timestamp, frames: session.frames.length };
      if (!hits.length) {
        result.sessions.push({ ...summary, status: 'insufficient_data' });
        continue;
      }
      const known = hits.filter(hit => hit.prediction !== 'unknown');
      const votes = new Map();
      for (const hit of known) votes.set(hit.prediction, (votes.get(hit.prediction) || 0) + 1);
      const prediction = known.length ? [...votes].sort((first, second) => second[1] - first[1])[0][0] : 'unknown';
      const scored = known.length ? known.filter(hit => hit.prediction === prediction) : hits;
      result.sessions.push({ ...summary, prediction, confidence: scored.reduce((sum, hit) => sum + hit.confidence, 0) / scored.length,
        windows: hits.length, unknown_windows: hits.length - known.length });
    }
    if (result.windows.length) result.status = 'ok';
    return result;
  }

  return { validateModel, packets, observation, features, aggregate, predict, infer, columns };
})();

if (typeof module !== 'undefined') module.exports = BrowserInference;
if (typeof WorkerGlobalScope !== 'undefined' && self instanceof WorkerGlobalScope) {
  self.onmessage = event => {
    try {
      const { buffer, model, bssid, name } = event.data;
      self.postMessage({ result: BrowserInference.infer(buffer, model, bssid, name) });
    } catch (error) {
      self.postMessage({ error: error.message });
    }
  };
}
