import test from 'node:test';
import assert from 'node:assert/strict';
import guard, { keepTabsDrawn } from '../roles/controlclaw/files/meeting-guard/index.js';

// A Chrome debugger endpoint with three targets, and sockets that record what they are sent.
function fakeChrome({ answer = true } = {}) {
  const sockets = [];
  const targets = [
    { type: 'page', id: 'A', webSocketDebuggerUrl: 'ws://127.0.0.1:9222/devtools/page/A' },
    { type: 'page', id: 'B', webSocketDebuggerUrl: 'ws://127.0.0.1:9222/devtools/page/B' },
    { type: 'browser_ui', id: 'C', webSocketDebuggerUrl: 'ws://127.0.0.1:9222/devtools/page/C' },
    { type: 'page', id: 'D', webSocketDebuggerUrl: 'ws://evil.example/devtools/page/D' },
  ];
  const fetchImpl = async (url) => ({ json: async () => (assert.equal(url, 'http://127.0.0.1:9222/json/list'), targets) });
  const connect = (url) => {
    const listeners = {};
    const ws = {
      url, sent: [], closed: false,
      addEventListener: (name, fn) => { (listeners[name] ??= []).push(fn); },
      emit: (name, event) => { for (const fn of listeners[name] ?? []) fn(event); },
      send: (data) => {
        const msg = JSON.parse(data);
        ws.sent.push(msg);
        if (answer && msg.id === 1) queueMicrotask(() => ws.emit('message', { data: JSON.stringify({ id: 1, result: {} }) }));
      },
      close: () => { ws.closed = true; },
    };
    sockets.push(ws);
    queueMicrotask(() => ws.emit('open', {}));
    return ws;
  };
  return { sockets, fetchImpl, connect };
}

test('a screencast is held on every tab of the loopback Chrome, and on nothing else', async () => {
  const chrome = fakeChrome();
  const release = await keepTabsDrawn(chrome);
  assert.deepEqual(chrome.sockets.map((s) => s.url), ['ws://127.0.0.1:9222/devtools/page/A', 'ws://127.0.0.1:9222/devtools/page/B']);
  for (const s of chrome.sockets) {
    assert.equal(s.sent[0].method, 'Page.startScreencast');
    assert.equal(s.closed, false);
  }
  // Chrome stops sending frames until the last one is acknowledged.
  chrome.sockets[0].emit('message', { data: JSON.stringify({ method: 'Page.screencastFrame', params: { sessionId: 7, data: 'x' } }) });
  assert.deepEqual(chrome.sockets[0].sent[1], { id: 2, method: 'Page.screencastFrameAck', params: { sessionId: 7 } });
  release();
  assert.ok(chrome.sockets.every((s) => s.closed));
});

test('a Chrome that is not there, or does not answer, never fails the tool call', async () => {
  const release = await keepTabsDrawn({ fetchImpl: async () => { throw new Error('ECONNREFUSED'); }, connect: () => assert.fail('no socket without a target list') });
  release();
  const silent = fakeChrome({ answer: false });
  const started = Date.now();
  (await keepTabsDrawn(silent))();
  assert.ok(Date.now() - started < 3000);
  assert.ok(silent.sockets.every((s) => s.closed));
});

// The plugin as OpenClaw loads it: collect its hooks, then drive them like a tool call would.
function load(chrome) {
  const hooks = { before_tool_call: [], after_tool_call: [] };
  const realFetch = globalThis.fetch, RealWebSocket = globalThis.WebSocket;
  globalThis.fetch = chrome.fetchImpl;
  globalThis.WebSocket = function (url) { return chrome.connect(url); };
  guard.register({ on: (name, fn) => hooks[name].push(fn) });
  return {
    before: async (event) => { for (const fn of hooks.before_tool_call) { const r = await fn(event, {}); if (r?.block) return r; } },
    after: async (event) => { for (const fn of hooks.after_tool_call) await fn(event, {}); },
    restore: () => { globalThis.fetch = realFetch; globalThis.WebSocket = RealWebSocket; },
  };
}
const settle = () => new Promise((resolve) => setImmediate(resolve));

test('the hold lasts for a screenshot of the agent\'s own browser, and only for that', async () => {
  const chrome = fakeChrome();
  const plugin = load(chrome);
  try {
    for (const params of [{ action: 'snapshot' }, { action: 'act', kind: 'click', ref: 'e1' }, { action: 'screenshot', profile: 'cc-meetings' }, { action: 'screenshot', profile: 'work' }])
      await plugin.before({ toolName: 'browser', params });
    await plugin.before({ toolName: 'exec', params: { action: 'screenshot' } });
    assert.equal(chrome.sockets.length, 0);

    const shot = { toolName: 'browser', params: { action: 'screenshot', targetId: 't2' } };
    assert.equal(await plugin.before(shot), undefined);
    assert.equal(chrome.sockets.length, 2);
    // A second screenshot started meanwhile shares the hold, and the first one ending keeps it.
    await plugin.before({ toolName: 'browser', params: { action: 'screenshot', profile: 'openclaw' } });
    assert.equal(chrome.sockets.length, 2);
    await plugin.after(shot);
    await settle();
    assert.ok(chrome.sockets.every((s) => !s.closed));
    await plugin.after(shot);
    await settle();
    assert.ok(chrome.sockets.every((s) => s.closed));

    // The next screenshot holds again.
    await plugin.before(shot);
    assert.equal(chrome.sockets.length, 4);
    await plugin.after(shot);
    await settle();
    assert.ok(chrome.sockets.every((s) => s.closed));
  } finally { plugin.restore(); }
});

test('the meeting reservation still refuses, before anything else', async () => {
  const chrome = fakeChrome();
  const plugin = load(chrome);
  try {
    assert.equal((await plugin.before({ toolName: 'google_meet', params: {} })).block, true);
    assert.equal((await plugin.before({ toolName: 'browser', params: { action: 'screenshot', profile: 'cc-meetings' } })).block, true);
    assert.equal(chrome.sockets.length, 0);
  } finally { plugin.restore(); }
});
