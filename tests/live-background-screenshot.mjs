// Live check for the screenshot hold in the browser reservation hook (meeting-guard/index.js).
//
//   node tests/live-background-screenshot.mjs [http://127.0.0.1:9222]
//
// Needs a Chrome with a window (not headless) and a debugging port: an agent box's own Chrome, run
// as `controlclaw`, or any desktop Chrome started with --remote-debugging-port. It opens two tabs,
// so the first is not in front, and takes four screenshots of it over the debugger, first as they
// are and then inside the hold. Without the hold Chrome answers some and never answers others; in
// the hold every one must answer. Exits 1 when one does not. It closes the tabs it opened.
import { createServer } from 'node:http';
import { keepTabsDrawn } from '../roles/controlclaw/files/meeting-guard/index.js';

const cdp = process.argv[2] ?? 'http://127.0.0.1:9222';
const WAIT_MS = 6000;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const json = async (path, method = 'GET') => (await fetch(cdp + path, { method })).json();

function session(url) {
  const ws = new WebSocket(url);
  const waiting = new Map();
  let id = 0;
  ws.addEventListener('message', (event) => { const msg = JSON.parse(event.data); waiting.get(msg.id)?.(msg); waiting.delete(msg.id); });
  const open = new Promise((resolve, reject) => { ws.addEventListener('open', resolve, { once: true }); ws.addEventListener('error', () => reject(new Error(`no debugger at ${url}`)), { once: true }); });
  return {
    send: async (method, params = {}) => {
      await open;
      const mine = ++id;
      ws.send(JSON.stringify({ id: mine, method, params }));
      return Promise.race([new Promise((resolve) => waiting.set(mine, resolve)), sleep(WAIT_MS).then(() => null)]);
    },
    close: () => ws.close(),
  };
}

async function round(label, hold) {
  // A page that keeps still: a capture with nothing new to draw is the one that goes unanswered.
  const back = await json(`/json/new?http://127.0.0.1:${port}/`, 'PUT');
  await sleep(1000);
  // Another site: with both tabs on one site every capture is answered and the check shows nothing.
  const front = await json(`/json/new?http://localhost:${port}/`, 'PUT');
  // Chrome stops drawing a tab a moment after it leaves the front. The debugger attaches only now,
  // as OpenClaw's does when the agent returns to a tab.
  await sleep(2500);
  const tab = session(back.webSocketDebuggerUrl);
  const release = hold ? await keepTabsDrawn({ cdp }) : () => {};
  const results = [];
  for (let i = 0; i < 4; i++) {
    const started = Date.now();
    const answer = await tab.send('Page.captureScreenshot', { format: 'png' });
    results.push(answer?.result?.data ? `${Date.now() - started} ms` : 'no answer');
    await sleep(300);
  }
  release();
  tab.close();
  for (const t of [back, front]) await fetch(`${cdp}/json/close/${t.id}`).catch(() => {});
  console.log(`${label.padEnd(18)} ${results.join(', ')}`);
  return results.every((r) => r !== 'no answer');
}

// Two sites served from here, so the check needs no internet.
const server = createServer((req, res) => res.end('<h1>screenshot check</h1>')).listen(0, '127.0.0.1');
await new Promise((resolve) => server.once('listening', resolve));
const { port } = server.address();

const version = await json('/json/version');
console.log(`${version.Browser} at ${cdp}`);
if (/headless/i.test(version['User-Agent'] ?? '')) console.log('This Chrome is headless: it has no tab "in front", so both rounds pass and nothing is checked.');
const bare = await round('as it is', false);
const held = await round('inside the hold', true);
console.log(bare ? 'This Chrome answered without the hold too (it does sometimes; run it again).' : 'Without the hold a screenshot of a background tab went unanswered, as on an agent box.');
console.log(held ? 'PASS: every screenshot inside the hold was answered.' : 'FAIL: a screenshot inside the hold was not answered.');
server.close();
process.exit(held ? 0 : 1);
