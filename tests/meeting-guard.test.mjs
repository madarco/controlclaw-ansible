import test from 'node:test';
import assert from 'node:assert/strict';
import guard, { keepTabsDrawn, ownCdpUrl } from '../roles/controlclaw/files/meeting-guard/index.js';

// A Chrome debugger endpoint with three targets, and sockets that record what they are sent.
const page = (id, port = 9222) => ({ type: 'page', id, webSocketDebuggerUrl: `ws://127.0.0.1:${port}/devtools/page/${id}` });
function fakeChrome({ answer = true, port = 9222, targets } = {}) {
  const sockets = [];
  targets ??= [
    page('AAAA1111'),
    page('BBBB2222'),
    { type: 'browser_ui', id: 'C', webSocketDebuggerUrl: 'ws://127.0.0.1:9222/devtools/page/C' },
    { type: 'page', id: 'D', webSocketDebuggerUrl: 'ws://evil.example/devtools/page/D' },
  ];
  const fetchImpl = async (url) => ({ json: async () => (assert.equal(url, `http://127.0.0.1:${port}/json/list`), targets) });
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
  assert.deepEqual(chrome.sockets.map((s) => s.url), ['ws://127.0.0.1:9222/devtools/page/AAAA1111', 'ws://127.0.0.1:9222/devtools/page/BBBB2222']);
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

test('only the tab the agent named is held, when Chrome knows it', async () => {
  for (const targetId of ['BBBB2222', 'bbbb']) {
    const chrome = fakeChrome();
    (await keepTabsDrawn({ ...chrome, targetId }))();
    assert.deepEqual(chrome.sockets.map((s) => s.url), ['ws://127.0.0.1:9222/devtools/page/BBBB2222']);
  }
  // One of OpenClaw's own names for a tab, a start two tabs share, too short a start: all of them.
  for (const targetId of ['t2', 'AAAA', 'B', '']) {
    const chrome = fakeChrome({ targets: [page('AAAA1111'), page('AAAA3333'), page('BBBB2222')] });
    (await keepTabsDrawn({ ...chrome, targetId }))();
    assert.equal(chrome.sockets.length, 3, targetId);
  }
});

test('every tab is held, however many there are', async () => {
  const chrome = fakeChrome({ targets: Array.from({ length: 150 }, (_, i) => page(`TAB${String(i).padStart(4, '0')}`)) });
  const release = await keepTabsDrawn(chrome);
  assert.equal(chrome.sockets.length, 150);
  assert.ok(chrome.sockets.every((s) => s.sent[0]?.method === 'Page.startScreencast'));
  release();
  assert.ok(chrome.sockets.every((s) => s.closed));
});

test('the debugger address comes from the profile the role wrote, then BROWSER_CDP_PORT, then 9222', () => {
  const config = (cdpUrl) => ({ browser: { profiles: { openclaw: { cdpUrl } } } });
  assert.equal(ownCdpUrl(config('http://127.0.0.1:9333'), {}), 'http://127.0.0.1:9333');
  assert.equal(ownCdpUrl(config('http://127.0.0.1:9333/'), { BROWSER_CDP_PORT: '9444' }), 'http://127.0.0.1:9333');
  assert.equal(ownCdpUrl(config('http://elsewhere.example:9222'), { BROWSER_CDP_PORT: '9444' }), 'http://127.0.0.1:9444');
  assert.equal(ownCdpUrl(undefined, { BROWSER_CDP_PORT: '9444' }), 'http://127.0.0.1:9444');
  assert.equal(ownCdpUrl({}, { BROWSER_CDP_PORT: 'x' }), 'http://127.0.0.1:9222');
});

// The plugin as OpenClaw loads it: collect its hooks, then drive them like a tool call would.
function load(chrome, config) {
  const hooks = { before_tool_call: [], after_tool_call: [] };
  const realFetch = globalThis.fetch, RealWebSocket = globalThis.WebSocket;
  globalThis.fetch = chrome.fetchImpl;
  globalThis.WebSocket = function (url) { return chrome.connect(url); };
  guard.register({ config, on: (name, fn) => hooks[name].push(fn) });
  return {
    before: async (event) => { for (const fn of hooks.before_tool_call) { const r = await fn(event, {}); if (r?.block) return r; } },
    after: async (event) => { for (const fn of hooks.after_tool_call) await fn(event, {}); },
    restore: () => { globalThis.fetch = realFetch; globalThis.WebSocket = RealWebSocket; },
  };
}
const settle = () => new Promise((resolve) => setImmediate(resolve));
const shot = (toolCallId, params = {}) => ({ toolName: 'browser', toolCallId, params: { action: 'screenshot', ...params } });
const open = (chrome) => chrome.sockets.filter((s) => !s.closed).length;

test('the hold lasts for a screenshot of the agent\'s own browser, and only for that', async () => {
  const chrome = fakeChrome();
  const plugin = load(chrome);
  try {
    for (const params of [{ action: 'snapshot' }, { action: 'act', kind: 'click', ref: 'e1' }, { action: 'screenshot', profile: 'cc-meetings' }, { action: 'screenshot', profile: 'work' }])
      await plugin.before({ toolName: 'browser', params });
    await plugin.before({ toolName: 'exec', params: { action: 'screenshot' } });
    assert.equal(chrome.sockets.length, 0);

    assert.equal(await plugin.before(shot('call-1', { targetId: 't2' })), undefined);
    assert.equal(open(chrome), 2);
    // OpenClaw reports the same call again under its wrapper's name: still one hold.
    await plugin.before(shot('call-1', { targetId: 't2' }));
    assert.equal(open(chrome), 2);
    // A second screenshot started meanwhile has its own hold, and the first one ending keeps it.
    await plugin.before(shot('call-2', { profile: 'openclaw', targetId: 'AAAA1111' }));
    assert.equal(open(chrome), 3);
    await plugin.after(shot('call-1'));
    await settle();
    assert.deepEqual(chrome.sockets.filter((s) => !s.closed).map((s) => s.url), ['ws://127.0.0.1:9222/devtools/page/AAAA1111']);
    await plugin.after(shot('call-2'));
    await settle();
    assert.equal(open(chrome), 0);
  } finally { plugin.restore(); }
});

test('an after_tool_call that arrives late ends its own hold and no newer one', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const chrome = fakeChrome();
  const plugin = load(chrome);
  try {
    await plugin.before(shot('old'));
    assert.equal(open(chrome), 2);
    // The old screenshot's hold runs out by itself.
    t.mock.timers.tick(29_999);
    await settle();
    assert.equal(open(chrome), 2);
    t.mock.timers.tick(1);
    await settle();
    assert.equal(open(chrome), 0);

    await plugin.before(shot('new'));
    assert.equal(open(chrome), 2);
    await plugin.after(shot('old'));
    await settle();
    assert.equal(open(chrome), 2);
    // And the new one's 30 seconds count from its own start.
    t.mock.timers.tick(29_999);
    await settle();
    assert.equal(open(chrome), 2);
    await plugin.after(shot('new'));
    await settle();
    assert.equal(open(chrome), 0);
  } finally { plugin.restore(); }
});

test('calls without an id are held and ended in order', async () => {
  const chrome = fakeChrome();
  const plugin = load(chrome);
  try {
    await plugin.before(shot(undefined, { targetId: 'AAAA1111' }));
    await plugin.before(shot(undefined, { targetId: 'BBBB2222' }));
    assert.equal(open(chrome), 2);
    await plugin.after(shot(undefined));
    await settle();
    assert.deepEqual(chrome.sockets.filter((s) => !s.closed).map((s) => s.url), ['ws://127.0.0.1:9222/devtools/page/BBBB2222']);
    await plugin.after(shot(undefined));
    await plugin.after(shot(undefined));
    await settle();
    assert.equal(open(chrome), 0);
  } finally { plugin.restore(); }
});

test('the hook asks the Chrome the role configured', async () => {
  const chrome = fakeChrome({ port: 9333, targets: [page('AAAA1111', 9333)] });
  const plugin = load(chrome, { browser: { profiles: { openclaw: { cdpUrl: 'http://127.0.0.1:9333' } } } });
  try {
    await plugin.before(shot('c'));
    assert.equal(open(chrome), 1);
    await plugin.after(shot('c'));
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
