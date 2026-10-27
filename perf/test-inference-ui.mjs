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
  await page.click('#classification-list > button');
  assert.match(await page.$eval('#classification-status', element => element.textContent), /Highlighting/);
  await page.evaluate(() => { setRenderMode('canvas'); highlightInferenceMac('02:00:00:00:00:11'); });
  assert.equal(await page.evaluate(() => canvasHoveredId), '02:00:00:00:00:11');
  await page.evaluate(() => {
    document.getElementById('inference-run').click();
    document.getElementById('inference-cancel').click();
  });
  await new Promise(resolve => setTimeout(resolve, 100));
  assert.equal(await page.$eval('#classification-status', element => element.textContent), 'Inference cancelled.');
  assert.equal(await page.$eval('#inference-run', element => element.disabled), false);
  await (await page.$('#inference-model')).uploadFile(badModel);
  await page.click('#inference-run');
  await page.waitForFunction(() => document.getElementById('classification-status').textContent.startsWith('Inference failed:'));
  assert.equal(await page.$eval('#inference-download', element => element.hidden), true);
  assert.equal(await page.$eval('#classification-list', element => element.children.length), 0);
  assert.deepEqual(errors, []);
  console.log('Browser worker/UI tests passed: inference, graph links, safe labels, SVG/canvas highlighting, cancellation, invalid model.');
} finally {
  if (browser) await browser.close();
  await new Promise(resolve => server.close(resolve));
  await rm(temporary, { recursive: true, force: true });
}
