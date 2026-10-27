'use strict';

const ClassificationResults = (() => {
  const macPattern = /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
  const modelKinds = new Set(['field-logistic-baseline-v1', 'field-tcn-v1']);

  function validate(result) {
    const reject = message => { throw new Error(message); };
    if (!result || result.schema_version !== '80211-metadata-v1') reject('Unsupported 802.class metadata schema.');
    if (!modelKinds.has(result.model_kind)) reject('Expected a field-pipeline model, not a legacy checkpoint.');
    if (!macPattern.test(result.bssid)) reject('Invalid BSSID.');
    if (!['ok', 'insufficient_data'].includes(result.status)) reject('Invalid inference status.');
    if (!Array.isArray(result.sessions) || (result.windows !== undefined && !Array.isArray(result.windows))) reject('Invalid sessions or windows.');
    if (result.sessions.length + (result.windows || []).length > 50000) reject('Too many inference records.');
    const sessionIds = new Set();
    function validateRecord(record, windowRecord) {
      if (!record || !macPattern.test(record.client_mac) || typeof record.session_id !== 'string' || !record.session_id) reject('Invalid client session.');
      if (windowRecord || record.status !== 'insufficient_data') {
        if (typeof record.prediction !== 'string' || !record.prediction.trim() || record.prediction.length > 256) reject('Invalid prediction.');
        if (!Number.isFinite(record.confidence) || record.confidence < 0 || record.confidence > 1) reject('Invalid confidence.');
      }
      if (windowRecord || record.start_timestamp !== undefined || record.end_timestamp !== undefined) {
        if (!Number.isFinite(record.start_timestamp) || !Number.isFinite(record.end_timestamp) || record.end_timestamp < record.start_timestamp) reject('Invalid observation interval.');
      }
      const frames = windowRecord ? record.valid_frames : record.frames;
      if (!Number.isSafeInteger(frames) || frames < 0) reject('Invalid frame count.');
    }
    result.sessions.forEach(session => {
      validateRecord(session, false);
      if (sessionIds.has(session.session_id)) reject('Duplicate session ID.');
      sessionIds.add(session.session_id);
    });
    const sessions = new Map(result.sessions.map(session => [session.session_id, session]));
    (result.windows || []).forEach(windowRecord => {
      validateRecord(windowRecord, true);
      const session = sessions.get(windowRecord.session_id);
      if (!session || session.client_mac.toLowerCase() !== windowRecord.client_mac.toLowerCase()) reject('Window does not match its client session.');
    });
    return result;
  }

  function graphEntries(result) {
    validate(result);
    const entries = new Map();
    for (const session of result.sessions) {
      const mac = session.client_mac.toLowerCase();
      const existing = entries.get(mac);
      const count = (existing?.sessionCount || 0) + 1;
      const latest = existing && Number.isFinite(existing.session.end_timestamp) && Number.isFinite(session.end_timestamp) && existing.session.end_timestamp > session.end_timestamp ? existing.session : session;
      const prediction = latest.status === 'insufficient_data' ? 'insufficient_data' : latest.prediction;
      const label = prediction === 'insufficient_data' ? 'Insufficient data' : prediction;
      const confidence = latest.status === 'insufficient_data' ? '' : ` · ${(latest.confidence * 100).toFixed(1)}%`;
      entries.set(mac, { role: 'client', mac, session: latest, sessionCount: count,
        label: `${label}${confidence}`, color: prediction === 'insufficient_data' ? '#8b949e' : prediction === 'unknown' ? '#d29922' : '#3fb950',
        description: `${mac} · Latest session: ${label}${confidence} · ${count} session(s). Capture-wide inference, independent of packet timeline.` });
    }
    const mac = result.bssid.toLowerCase();
    const clients = entries.size;
    entries.set(mac, { role: 'ap', mac, label: `AP · ${clients} client${clients === 1 ? '' : 's'}`, color: '#58a6ff',
      description: `${mac} · Target AP radio BSSID · ${clients} observed client(s).` });
    return entries;
  }

  function badge(entry) {
    if (!entry) return '';
    return entry.label.length > 42 ? `${entry.label.slice(0, 39)}…` : entry.label;
  }

  function render(result, highlight) {
    const panel = document.getElementById('classification');
    const status = document.getElementById('classification-status');
    const list = document.getElementById('classification-list');
    panel.hidden = false;
    list.replaceChildren();
    const diagnostics = result.diagnostics;
    const quality = Number.isSafeInteger(diagnostics?.truncated_packets) ? ` · ${diagnostics.truncated_packets} truncated frames excluded · ${diagnostics.dropped_retries} retries deduplicated` : '';
    const summary = `${typeof result.pcap === 'string' ? result.pcap + ' · ' : ''}BSSID ${result.bssid.toLowerCase()} · ${result.model_kind} · ${result.status} · ${result.sessions.length} sessions · ${(result.windows || []).length} windows${quality}`;
    status.textContent = summary;
    function focusButton(mac, label) {
      const button = document.createElement('button');
      button.textContent = label;
      button.onclick = () => {
        status.textContent = highlight(mac.toLowerCase()) ? `${summary} · Highlighting ${mac}` : `${summary} · ${mac} not present in the loaded graph`;
      };
      return button;
    }
    list.append(focusButton(result.bssid, 'Highlight AP'));
    const windowsBySession = new Map();
    for (const windowRecord of result.windows || []) {
      if (!windowsBySession.has(windowRecord.session_id)) windowsBySession.set(windowRecord.session_id, []);
      windowsBySession.get(windowRecord.session_id).push(windowRecord);
    }
    for (const session of result.sessions) {
      const row = document.createElement('details');
      const heading = document.createElement('summary');
      const label = session.status === 'insufficient_data' ? 'insufficient_data' : `${session.prediction} (${(session.confidence * 100).toFixed(1)}%)`;
      heading.textContent = `${session.client_mac} · ${label} · ${session.frames} frames`;
      row.append(heading, focusButton(session.client_mac, 'Highlight client'));
      for (const windowRecord of windowsBySession.get(session.session_id) || []) {
        const text = document.createElement('p');
        text.textContent = `${windowRecord.start_timestamp}–${windowRecord.end_timestamp} · ${windowRecord.prediction} · ${(windowRecord.confidence * 100).toFixed(1)}% · ${windowRecord.valid_frames} frames`;
        row.append(text);
      }
      list.append(row);
    }
  }

  return { validate, render, graphEntries, badge };
})();

if (typeof module !== 'undefined') module.exports = ClassificationResults;
