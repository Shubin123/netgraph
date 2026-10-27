import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import puppeteer from 'puppeteer-core';

const require = createRequire(import.meta.url);
const { model, frame, pcap } = require('./test-browser-inference.cjs');
const root = fileURLToPath(new URL('../', import.meta.url));
const chrome = [process.env.CHROME_PATH, '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/google-chrome', '/usr/bin/chromium'].find(path => path && existsSync(path));
assert.ok(chrome, 'Set CHROME_PATH to a Chrome/Chromium executable.');
const temporary = await mkdtemp(join(tmpdir(), 'netgraph-inference-'));
const server = createServer(async (request, response) => {
  try {
    const pathname = new URL(request.url, 'http://localhost').pathname;
    const path = resolve(root, `.${pathname === '/' ? '/index.html' : pathname}`);
    if (!path.startsWith(root)) { response.writeHead(403).end(); return; }
    response.setHeader('Content-Type', extname(path) === '.js' ? 'text/javascript' : 'text/html');
    response.end(await readFile(path));
  } catch { response.writeHead(404).end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
  const capture = join(temporary, 'fixture.pcap');
  const modelPath = join(temporary, 'model.json');
  const badModel = join(temporary, 'invalid.json');
  const testModel = model();
  testModel.labels[1] = '<img src=x onerror=alert(1)>';
  await writeFile(modelPath, JSON.stringify(testModel));
  await writeFile(badModel, '{}');
  await writeFile(capture, pcap(Array.from({ length: 8 }, (_, index) => ({ packet: frame({ sequence: index + 1, down: index % 2 === 1 }), time: 100 + index * 0.05 }))));
  browser = await puppeteer.launch({ executablePath: chrome, headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'], defaultViewport: { width: 1400, height: 900 } });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(`http://127.0.0.1:${server.address().port}`, { waitUntil: 'load' });
  await page.waitForFunction(() => typeof window.d3 !== 'undefined');
  await page.click('#overlay .classifier-open');
  await (await page.$('#inference-model')).uploadFile(modelPath);
  await (await page.$('#inference-capture')).uploadFile(capture);
  await page.type('#inference-bssid', '02:00:00:00:00:01');
  await page.click('#inference-run');
  await page.waitForFunction(() => !document.getElementById('inference-run').disabled && !document.getElementById('inference-download').hidden);
  const state = await page.evaluate(() => ({
    status: document.getElementById('classification-status').textContent,
    text: document.getElementById('classification-list').textContent,
    injected: document.querySelectorAll('#classification-list img').length,
    ap: nodes.has('02:00:00:00:00:01'), client: nodes.has('02:00:00:00:00:11'),
    packets: globalPacketIndex, result: latestInference,
  }));
  assert.match(state.status, /4 windows/);
  assert.match(state.text, /<img src=x onerror=alert\(1\)>/);
  assert.equal(state.injected, 0);
  assert.ok(state.ap && state.client);
  assert.equal(state.packets, 8);
  assert.equal(state.result.sessions[0].prediction, testModel.labels[1]);
  assert.equal(await page.$eval('#classification', element => element.hidden), true);
  assert.equal(await page.$eval('#inference-view', element => element.hidden), false);
  assert.equal(await page.$$eval('.inference-label', elements => elements.length), 2);
  assert.equal(await page.$$eval('.inference-ring', elements => elements.length), 2);
  assert.match(await page.$$eval('.inference-label', elements => elements.map(element => element.textContent).join(' ')), /AP · 1 client/);
  assert.match(await page.$$eval('.inference-label', elements => elements.map(element => element.textContent).join(' ')), /onerror=alert/);
  assert.equal(await page.$$eval('.node img', elements => elements.length), 0);
  await page.waitForFunction(() => getComputedStyle(document.getElementById('progress-bar-wrap')).display === 'none');
  await page.evaluate(() => {
    const node = [...document.querySelectorAll('.node')].find(element => element.__data__.rawMac === '02:00:00:00:00:01');
    node.focus();
  });
  await page.keyboard.press('Enter');
  assert.match(await page.$eval('#inference-node-detail', element => element.textContent), /Target AP radio BSSID/);
  await page.evaluate(() => {
    const node = [...document.querySelectorAll('.node')].find(element => element.__data__.rawMac === '02:00:00:00:00:11');
    node.dispatchEvent(new MouseEvent('click', { bubbles: true }));
  });
  assert.match(await page.$eval('#inference-node-detail', element => element.textContent), /Latest session/);
  assert.match(await page.$eval('#inference-node-detail', element => element.textContent), /8 usable frames/);
  await page.click('#inference-badges');
  assert.equal(await page.$$eval('.inference-label', elements => elements.length), 0);
  await page.click('#inference-badges');
  assert.equal(await page.$$eval('.inference-label', elements => elements.length), 2);
  await page.screenshot({ path: join(tmpdir(), 'netgraph-integrated-inference.png') });
  await page.click('#inference-view .classifier-open');
  assert.match(await page.$eval('#inference-current-capture', element => element.textContent), /fixture.pcap/);
  assert.equal(await page.$eval('#inference-capture', element => element.files.length), 0);
  await page.click('#classification-list > button');
  assert.match(await page.$eval('#classification-status', element => element.textContent), /Highlighting/);
  const canvasLabels = await page.evaluate(() => {
    setRenderMode('canvas');
    const labels = [];
    const original = ctx.fillText;
    ctx.fillText = function(text, ...args) { labels.push(text); return original.call(this, text, ...args); };
    highlightInferenceMac('02:00:00:00:00:11');
    ctx.fillText = original;
    return labels;
  });
  assert.ok(canvasLabels.includes('AP · 1 client'));
  assert.ok(canvasLabels.some(label => label.includes('onerror=alert')));
  assert.equal(await page.evaluate(() => canvasHoveredId), '02:00:00:00:00:11');
  await page.click('#classification-close');
  const point = await page.evaluate(() => {
    const node = nodes.get('02:00:00:00:00:11');
    node.x = node.fx = 900; node.y = node.fy = 300;
    document.getElementById('inference-node-detail').textContent = 'Choose a client';
    drawCanvas();
    return { x: node.x * view.k + view.x, y: node.y * view.k + view.y };
  });
  await page.mouse.click(point.x, point.y);
  assert.match(await page.$eval('#inference-node-detail', element => element.textContent), /02:00:00:00:00:11/);
  await page.click('#inference-view .classifier-open');
  await page.evaluate(() => {
    document.getElementById('inference-run').click();
    document.getElementById('inference-cancel').click();
  });
  await new Promise(resolve => setTimeout(resolve, 100));
  assert.equal(await page.$eval('#classification-status', element => element.textContent), 'Inference cancelled.');
  assert.equal(await page.$eval('#inference-run', element => element.disabled), false);
  await page.click('#inference-run');
  await page.waitForFunction(() => !document.getElementById('inference-run').disabled && document.getElementById('classification').hidden);
  assert.equal(await page.evaluate(() => latestInference.windows.length), 4);
  await page.click('#inference-view .classifier-open');
  await (await page.$('#inference-model')).uploadFile(badModel);
  await page.click('#inference-run');
  await page.waitForFunction(() => document.getElementById('classification-status').textContent.startsWith('Inference failed:'));
  assert.equal(await page.$eval('#inference-download', element => element.hidden), true);
  assert.equal(await page.$eval('#classification-list', element => element.children.length), 0);
  await page.evaluate(async () => {
    ouiMap.set('020000', 'Vendor');
    const capture = currentGraphCapture;
    const bytes = await capture.arrayBuffer();
    const result = { schema_version: '80211-metadata-v1', model_kind: 'field-logistic-baseline-v1', bssid: '02:00:00:00:00:01', status: 'insufficient_data', sessions: [{ session_id: 'short', client_mac: '02:00:00:00:00:11', frames: 1, status: 'insufficient_data' }], windows: [] };
    await parsePCAPBuffer(bytes, { infrastructure: true, inferenceResult: result });
  });
  assert.equal(await page.evaluate(() => nodes.get('Vendor_00:00:11').inference.label), 'Insufficient data');
  assert.match(await page.$$eval('.inference-label', elements => elements.map(element => element.textContent).join(' ')), /Insufficient data/);
  await page.click('#classification-close');
  await page.click('#inference-clear');
  assert.equal(await page.evaluate(() => globalPacketIndex), 8);
  assert.equal(await page.evaluate(() => currentGraphCapture.name), 'PCAP');
  assert.equal(await page.$$eval('.inference-label', elements => elements.length), 0);
  assert.equal(await page.$eval('#inference-view', element => element.hidden), true);
  await page.evaluate(() => {
    attachGraphInference({ schema_version: '80211-metadata-v1', model_kind: 'field-tcn-v1', bssid: '02:00:00:00:00:01', status: 'insufficient_data', sessions: [], windows: [] });
    updateGraph();
  });
  assert.equal(await page.$$eval('.inference-label', elements => elements.length), 1);
  await page.evaluate(async () => {
    const capture = currentGraphCapture;
    await parsePCAPBuffer(await capture.arrayBuffer());
  });
  assert.equal(await page.$eval('#inference-view', element => element.hidden), true);
  assert.equal(await page.$$eval('.inference-label', elements => elements.length), 0);
  assert.equal(await page.evaluate(() => [...nodes.values()].some(node => node.inference)), false);
  assert.deepEqual(errors, []);
  console.log('Browser worker/UI tests passed: current-capture inference, graph badges, SVG/canvas/keyboard selection, inspector, vendor names, capture reset, safe labels, cancellation, invalid model.');
} finally {
  if (browser) await browser.close();
  await new Promise(resolve => server.close(resolve));
  await rm(temporary, { recursive: true, force: true });
}
