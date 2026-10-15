// Presenting the agent's browser in a meeting (controlclaw docs/plans/meeting-present.md): present.js
// against a fake Meet tab, stage tab and agent browser.
import './fixtures/home.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createPresenter, PRESENT_SAY } from '../roles/controlclaw/files/meeting-voice/present.js';
import { parseAction, consultRules } from '../roles/controlclaw/files/meeting-voice/actions.js';

const MEETING = '0b9a3f43-5d0e-4c55-9d0c-3a1f2b4c5d6e';
/** `share`: 'ok' | 'disabled' | 'none'. `after`: what Meet shows once Share screen is clicked. */
function fixture({ share = 'ok', after = 'You are presenting', present = true, visible = true } = {}) {
  const calls = [], draws = [], closed = [], intervals = [], orphans = [];
  let leaseNow = { present, meetingId: MEETING };
  let meetText = 'fgx-ftqo-yys';
  const json = async (port, path, method = 'GET') => {
    calls.push(`${port} ${method} ${path}`);
    if (port === 9223 && path === '/json/list') return [{ type: 'page', id: 'm', title: 'Meet', url: 'https://meet.google.com/fgx-ftqo-yys?hl=en', webSocketDebuggerUrl: 'meet' }, ...orphans];
    if (port === 9223 && path.startsWith('/json/new')) return { id: 's', webSocketDebuggerUrl: 'stage' };
    if (path.startsWith('/json/close/')) { closed.push(path.slice(12)); meetText = 'fgx-ftqo-yys'; return {}; }
    if (port === 9222 && path === '/json/list') return [{ type: 'page', id: 'a', url: 'https://example.com/', webSocketDebuggerUrl: 'agent' }];
    return {};
  };
  const client = url => ({
    ready: Promise.resolve(),
    close: () => {},
    send: async (method, params = {}) => {
      if (url === 'meet') {
        if (method === 'Input.dispatchMouseEvent' && params.type === 'mouseReleased') { calls.push(`click ${params.x},${params.y}`); meetText = after; }
        if (method === 'Runtime.evaluate' && params.expression.includes('b.offsetParent')) return { result: { result: { value: share === 'ok' ? JSON.stringify([600, 700]) : share } } };
        // Meet's own "Stop presenting" control and its notices: never captions, chat or names.
        if (method === 'Runtime.evaluate' && params.expression.includes('JSON.stringify({ stop:')) return { result: { result: { value: JSON.stringify({ stop: /^(you are presenting|stop presenting)$/i.test(meetText), notices: meetText }) } } };
        return {};
      }
      if (url === 'stage') { if (method === 'Runtime.evaluate') draws.push(params.expression.slice(0, 20)); return {}; }
      if (url === 'agent') {
        if (method === 'Runtime.evaluate' && params.expression === 'document.visibilityState') return { result: { result: { value: visible ? 'visible' : 'hidden' } } };
        if (method === 'Runtime.evaluate') return { result: { result: { value: '[1920,1080,0,2400]' } } };
        if (method === 'Page.captureScreenshot') { calls.push(`shot scale=${params.clip.scale.toFixed(3)} q=${params.quality} at=${params.clip.x},${params.clip.y}`); return { result: { data: 'AAAA' } }; }
      }
      return {};
    },
  });
  const timers = { setInterval: (fn, ms) => { const t = { fn, ms }; intervals.push(t); return t; }, clearInterval: t => { if (t) t.cleared = true; } };
  const presenter = createPresenter({ json, connect: client, lease: () => leaseNow, sleep: async () => {}, timers, metric: () => {} });
  return { presenter, calls, draws, closed, intervals, orphans, setLease: l => { leaseNow = l; }, setMeet: t => { meetText = t; } };
}

test('CC_PRESENT: only as the whole answer, browser or stop, and only offered when the lease allows it', () => {
  assert.deepEqual(parseAction('CC_PRESENT {"mode":"browser"}'), { kind: 'present', mode: 'browser' });
  assert.deepEqual(parseAction('CC_PRESENT {"mode":"stop"}'), { kind: 'present', mode: 'stop' });
  assert.equal(parseAction('CC_PRESENT {"mode":"desktop"}').kind, 'invalid');
  assert.equal(parseAction('Here it is:\nCC_PRESENT {"mode":"browser"}'), null);
  assert.match(consultRules(true, new Date(), false, true), /CC_PRESENT \{"mode":"browser"\}[^]*CC_PRESENT \{"mode":"stop"\}/);
  assert.doesNotMatch(consultRules(true, new Date(), false, false), /CC_PRESENT/);
});

test('presenting: the stage opens, frames are drawn at 2 fps from the visible tab, Share screen is clicked, and "presenting" only once Meet says so', async () => {
  const f = fixture();
  assert.equal(await f.presenter.start(), 'presenting');
  assert.ok(f.calls.includes('9223 PUT /json/new?about:blank'), 'the stage tab opens in the meeting Chrome');
  assert.ok(f.calls.some(c => c === 'click 600,700'), 'Share screen clicked at its centre');
  assert.ok(f.calls.some(c => c === 'shot scale=0.667 q=60 at=0,2400'), 'what the agent sees (the page scrolled to 2400), 1280 wide, quality 60');
  assert.ok(f.draws.some(d => d.startsWith('draw(')), 'a frame drawn on the stage before the click');
  assert.equal(f.intervals[0].ms, 500, '2 frames a second');
  assert.equal(f.presenter.presenting(), true);
  assert.equal(await f.presenter.start(), 'already');
  // Stop: the stage tab closes, which ends the presentation in Meet.
  assert.equal(await f.presenter.stop(), 'stopped');
  assert.deepEqual(f.closed, ['s']);
  assert.ok(f.intervals.every(t => t.cleared));
  assert.equal(await f.presenter.stop(), 'not_presenting');
});

test('Meet does not let the agent present: refused, nothing left open', async () => {
  for (const scenario of [{ share: 'disabled' }, { share: 'none', after: '', }, { after: 'The host has turned off screen sharing for participants' }]) {
    const f = fixture(scenario);
    f.setMeet(scenario.share === 'none' ? 'Only the host can share their screen' : 'fgx-ftqo-yys');
    assert.equal(await f.presenter.start(), 'refused', JSON.stringify(scenario));
    assert.equal(f.presenter.presenting(), false);
    if (scenario.after) assert.deepEqual(f.closed, ['s'], 'the stage closed again');
  }
});

test('no "You are presenting" in time: not started, the stage closed again; never a claim of presenting', async () => {
  const f = fixture({ after: 'fgx-ftqo-yys' });
  assert.equal(await f.presenter.start(), 'not_started');
  assert.deepEqual(f.closed, ['s']);
  assert.equal(f.presenter.presenting(), false);
  assert.match(PRESENT_SAY.not_started, /^Not done/);
});

test('the setting off or a meeting without it: not allowed, nothing opened', async () => {
  for (const lease of [{ present: false, meetingId: MEETING }, { present: true, meetingId: '' }]) {
    const f = fixture(); f.setLease(lease);
    assert.equal(await f.presenter.start(), 'not_allowed');
    assert.equal(f.calls.length, 0);
  }
  assert.match(PRESENT_SAY.not_allowed, /Meetings settings/);
});

test('while presenting: the meeting ending, the setting turned off or Meet stopping it closes the stage', async () => {
  for (const change of [f => f.setLease({ present: true, meetingId: '' }), f => f.setLease({ present: false, meetingId: MEETING }), f => f.setMeet('fgx-ftqo-yys')]) {
    const f = fixture();
    assert.equal(await f.presenter.start(), 'presenting');
    change(f);
    await f.intervals.find(t => t.ms === 2000).fn();
    assert.equal(f.presenter.presenting(), false);
    assert.deepEqual(f.closed, ['s']);
  }
});

test('no tab in front in the agent browser: the stage says there is nothing to show', async () => {
  const f = fixture({ visible: false });
  assert.equal(await f.presenter.start(), 'presenting');
  assert.ok(f.draws.some(d => d.startsWith('card(')));
  await f.presenter.stop();
});

test('in the meeting: the consult is offered CC_PRESENT, and the room hears the outcome Meet showed', async () => {
  const { EventEmitter } = await import('node:events');
  const { mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { LiveBridge } = await import('../roles/controlclaw/files/meeting-voice/live.js');
  const { voiceRecord } = await import('../roles/controlclaw/files/meeting-voice/record.js');
  const dir = mkdtempSync(join(tmpdir(), 'cc-present-')), all = [], tools = [], asked = [];
  class WS extends EventEmitter {
    constructor() { super(); this.readyState = 1; this.bufferedAmount = 0; this.sent = []; all.push(this); setImmediate(() => this.emit('open')); }
    send(s) { const e = JSON.parse(s); this.sent.push(e); if (e.type === 'session.start') setImmediate(() => this.emit('message', JSON.stringify({ type: 'session.started', session: {} }))); }
    terminate() {}
  }
  const outcomes = ['refused', 'presenting', 'stopped'];
  const presenter = { start: async () => { asked.push('start'); return outcomes.shift(); }, stop: async () => { asked.push('stop'); return outcomes.shift(); } };
  const bridge = new LiveBridge({
    providerConfig: { provider: 'gateway', model: 'openai/gpt-live-1', placeholder: 'cc-speech-' + '0'.repeat(48), maxMinutes: 30, wake: { enabled: false, words: ['Jarvis'] } },
    onAudio: () => {}, onToolCall: t => tools.push(t), onClearAudio: () => {}, onClose: () => {}, onError: () => {},
  }, { WebSocket: WS, metric: () => {}, voiceDir: dir, record: voiceRecord('meeting', dir), presenter, lease: () => ({ at: new Date().toISOString(), meetingId: MEETING, present: true }), fetch: async () => ({ ok: true, json: async () => ({ token: 'tok' }) }) });
  await bridge.connect();
  const ws = all[0];
  const spoken = () => ws.sent.filter(e => e.type === 'session.commentary.append').map(e => e.content);
  const ask = (id, text) => { ws.emit('message', JSON.stringify({ type: 'session.delegation.created', delegation: { id } })); bridge.submitToolResult(id, { text }); };
  ask('d1', 'CC_PRESENT {"mode":"browser"}');
  assert.match(tools[0].args.context, /CC_PRESENT/);
  await new Promise(r => setTimeout(r, 20));
  assert.match(spoken()[0], /^Not done: Google Meet does not let you present/);
  ask('d2', 'CC_PRESENT {"mode":"browser"}');
  await new Promise(r => setTimeout(r, 20));
  assert.match(spoken()[1], /^Done: you are now presenting your browser/);
  ask('d3', 'CC_PRESENT {"mode":"stop"}');
  await new Promise(r => setTimeout(r, 20));
  assert.match(spoken()[2], /^Done: you stopped presenting/);
  assert.deepEqual(asked, ['start', 'start', 'stop']);
  bridge.close();
});

test('a plain request to share or stop is handled at once, without the consult; other requests still go to the consult', async () => {
  const { EventEmitter } = await import('node:events');
  const { mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { LiveBridge } = await import('../roles/controlclaw/files/meeting-voice/live.js');
  const { voiceRecord } = await import('../roles/controlclaw/files/meeting-voice/record.js');
  const dir = mkdtempSync(join(tmpdir(), 'cc-present-')), all = [], tools = [], asked = [];
  let present = true;
  class WS extends EventEmitter {
    constructor() { super(); this.readyState = 1; this.bufferedAmount = 0; this.sent = []; all.push(this); setImmediate(() => this.emit('open')); }
    send(s) { const e = JSON.parse(s); this.sent.push(e); if (e.type === 'session.start') setImmediate(() => this.emit('message', JSON.stringify({ type: 'session.started', session: {} }))); }
    terminate() {}
  }
  const presenter = { start: async () => { asked.push('start'); return 'presenting'; }, stop: async () => { asked.push('stop'); return 'stopped'; } };
  const bridge = new LiveBridge({
    providerConfig: { provider: 'gateway', model: 'openai/gpt-live-1', placeholder: 'cc-speech-' + '0'.repeat(48), maxMinutes: 30, wake: { enabled: false, words: ['Jarvis'] } },
    onAudio: () => {}, onToolCall: t => tools.push(t), onClearAudio: () => {}, onClose: () => {}, onError: () => {},
  }, { WebSocket: WS, metric: () => {}, voiceDir: dir, record: voiceRecord('meeting', dir), presenter, lease: () => ({ at: new Date().toISOString(), meetingId: MEETING, present }), fetch: async () => ({ ok: true, json: async () => ({ token: 'tok' }) }) });
  await bridge.connect();
  const ws = all[0];
  const said = (text) => ws.emit('message', JSON.stringify({ type: 'session.input_transcript.delta', delta: text }));
  const delegate = id => ws.emit('message', JSON.stringify({ type: 'session.delegation.created', delegation: { id } }));
  const spoken = () => ws.sent.filter(e => e.type === 'session.commentary.append').map(e => e.content);
  said('Jarvis, can you share your screen and show us the page?'); delegate('d1');
  await new Promise(r => setTimeout(r, 20));
  assert.deepEqual(asked, ['start']); assert.equal(tools.length, 0, 'no consult');
  assert.match(spoken()[0], /now presenting/);
  said(' Jarvis, stop presenting please.'); delegate('d2');
  await new Promise(r => setTimeout(r, 20));
  assert.deepEqual(asked, ['start', 'stop']); assert.equal(tools.length, 0);
  // Not plainly about presenting: the consult, as before. And with presenting off, never handled here.
  said(' Jarvis, what is the budget?'); await new Promise(r => setTimeout(r, 1300)); delegate('d3');
  assert.equal(tools.length, 1);
  present = false;
  said(' Jarvis, share your screen.'); delegate('d4');
  await new Promise(r => setTimeout(r, 20));
  assert.deepEqual(asked, ['start', 'stop']);
  bridge.close();
});

test('the lease file the vm-agent writes is read with its present flag (no injected lease)', async () => {
  const { mkdtempSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { meetingLease } = await import('../roles/controlclaw/files/meeting-voice/record.js');
  const dir = mkdtempSync(join(tmpdir(), 'cc-lease-'));
  writeFileSync(join(dir, 'lease.json'), JSON.stringify({ wakeSessions: 40, meetingId: MEETING, present: true, at: new Date().toISOString() }));
  assert.equal(meetingLease(dir).present, true);
  assert.equal(meetingLease(dir).full, false);
  writeFileSync(join(dir, 'lease.json'), JSON.stringify({ wakeSessions: 40, meetingId: MEETING, at: new Date().toISOString() }));
  assert.equal(meetingLease(dir).present, false);
  const presenter = createPresenter({ dir, json: async () => { throw new Error('no browser'); } });
  assert.equal(await presenter.start(), 'not_allowed', 'present.js reads the same file');
});

test('the request transcript arrives after the delegation: presenting still starts, once, and the consult answer is ignored', async t => {
  const { EventEmitter } = await import('node:events');
  const { mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { LiveBridge } = await import('../roles/controlclaw/files/meeting-voice/live.js');
  const { voiceRecord } = await import('../roles/controlclaw/files/meeting-voice/record.js');
  const dir = mkdtempSync(join(tmpdir(), 'cc-present-')), all = [], tools = [], asked = [];
  class WS extends EventEmitter {
    constructor() { super(); this.readyState = 1; this.bufferedAmount = 0; this.sent = []; all.push(this); setImmediate(() => this.emit('open')); }
    send(s) { const e = JSON.parse(s); this.sent.push(e); if (e.type === 'session.start') setImmediate(() => this.emit('message', JSON.stringify({ type: 'session.started', session: {} }))); }
    terminate() {}
  }
  const presenter = { start: async () => { asked.push('start'); return 'presenting'; }, stop: async () => 'stopped' };
  const bridge = new LiveBridge({
    providerConfig: { provider: 'gateway', model: 'openai/gpt-live-1', placeholder: 'cc-speech-' + '0'.repeat(48), maxMinutes: 30, wake: { enabled: false, words: ['Jarvis'] } },
    onAudio: () => {}, onToolCall: t => tools.push(t), onClearAudio: () => {}, onClose: () => {}, onError: () => {},
  }, { WebSocket: WS, metric: () => {}, voiceDir: dir, record: voiceRecord('meeting', dir), presenter, lease: () => ({ at: new Date().toISOString(), meetingId: MEETING, present: true }), fetch: async () => ({ ok: true, json: async () => ({ token: 'tok' }) }) });
  await bridge.connect();
  const ws = all[0];
  ws.emit('message', JSON.stringify({ type: 'session.delegation.created', delegation: { id: 'd1' } }));
  assert.equal(tools.length, 1, 'nothing heard yet: the consult starts');
  ws.emit('message', JSON.stringify({ type: 'session.input_transcript.delta', delta: 'Jarvis, share your screen please.' }));
  await new Promise(r => setTimeout(r, 1700));
  assert.deepEqual(asked, ['start']);
  bridge.submitToolResult('d1', { text: 'CC_NEEDS_OWNER {"request":"Share the screen","allowed":false}' });
  const spoken = ws.sent.filter(e => e.type === 'session.commentary.append').map(e => e.content);
  assert.equal(spoken.length, 1); assert.match(spoken[0], /now presenting/);
  bridge.close();
});

test('two starts at once open one stage; a stage left by a restart is closed first, and stop closes it when nothing else runs', async () => {
  const f = fixture();
  const [a, b] = await Promise.all([f.presenter.start(), f.presenter.start()]);
  assert.deepEqual([a, b], ['presenting', 'already']);
  assert.equal(f.calls.filter(c => c.includes('/json/new')).length, 1);
  await f.presenter.stop();
  const g = fixture();
  g.orphans.push({ type: 'page', id: 'old', title: 'CC Stage', url: 'data:text/html;base64,x' });
  assert.equal(await g.presenter.stop(), 'stopped', 'an orphaned stage is still a presentation to stop');
  assert.deepEqual(g.closed, ['old']);
});

test('the shortcut: only requests to the agent, and words used once are never used again', async () => {
  const { EventEmitter } = await import('node:events');
  const { mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { LiveBridge } = await import('../roles/controlclaw/files/meeting-voice/live.js');
  const { voiceRecord } = await import('../roles/controlclaw/files/meeting-voice/record.js');
  const dir = mkdtempSync(join(tmpdir(), 'cc-present-')), all = [], tools = [], asked = [];
  class WS extends EventEmitter {
    constructor() { super(); this.readyState = 1; this.bufferedAmount = 0; this.sent = []; all.push(this); setImmediate(() => this.emit('open')); }
    send(s) { const e = JSON.parse(s); this.sent.push(e); if (e.type === 'session.start') setImmediate(() => this.emit('message', JSON.stringify({ type: 'session.started', session: {} }))); }
    terminate() {}
  }
  const presenter = { start: async () => { asked.push('start'); return 'presenting'; }, stop: async () => { asked.push('stop'); return 'stopped'; } };
  const bridge = new LiveBridge({
    providerConfig: { provider: 'gateway', model: 'openai/gpt-live-1', placeholder: 'cc-speech-' + '0'.repeat(48), maxMinutes: 30, wake: { enabled: false, words: ['Jarvis'] } },
    onAudio: () => {}, onToolCall: t => tools.push(t), onClearAudio: () => {}, onClose: () => {}, onError: () => {},
  }, { WebSocket: WS, metric: () => {}, voiceDir: dir, record: voiceRecord('meeting', dir), presenter, lease: () => ({ at: new Date().toISOString(), meetingId: MEETING, present: true }), fetch: async () => ({ ok: true, json: async () => ({ token: 'tok' }) }) });
  await bridge.connect();
  const ws = all[0];
  const said = text => ws.emit('message', JSON.stringify({ type: 'session.input_transcript.delta', delta: text }));
  const delegate = id => ws.emit('message', JSON.stringify({ type: 'session.delegation.created', delegation: { id } }));
  // People talking about their own screens, then a question to the agent: the consult, no presenting.
  said("Okay, I'll share my screen in a minute. Can you show me the first page? Jarvis, what's the budget?"); delegate('d1');
  await new Promise(r => setTimeout(r, 1700));
  assert.deepEqual(asked, []); assert.equal(tools.length, 1);
  bridge.submitToolResult('d1', { text: 'The budget is ten.' });
  // A request whose words came late: presented once, and the next question is not taken for it again.
  await new Promise(r => setTimeout(r, 1300));
  delegate('d2'); said(' Jarvis, share your screen.');
  await new Promise(r => setTimeout(r, 1700));
  assert.deepEqual(asked, ['start']);
  bridge.submitToolResult('d2', { text: 'CC_PRESENT {"mode":"browser"}' });
  await new Promise(r => setTimeout(r, 1300));
  said(' Jarvis, what time is it in Rome?'); delegate('d3');
  await new Promise(r => setTimeout(r, 1700));
  assert.deepEqual(asked, ['start'], 'neither the consult answer of d2 nor d3 presents again');
  assert.equal(tools.length, 3, 'd3 went to the consult');
  bridge.close();
});

test("a participant named like Meet's words fools nothing: only Meet's own control counts", async () => {
  const f = fixture({ after: 'You are presenting (a participant\'s name)' });
  assert.equal(await f.presenter.start(), 'not_started');
});

test('always listening: only a request with the agent\'s name presents ("Bob, can you share your screen?" does not)', async () => {
  const { EventEmitter } = await import('node:events');
  const { mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { LiveBridge } = await import('../roles/controlclaw/files/meeting-voice/live.js');
  const { voiceRecord } = await import('../roles/controlclaw/files/meeting-voice/record.js');
  const dir = mkdtempSync(join(tmpdir(), 'cc-present-')), all = [], tools = [], asked = [];
  class WS extends EventEmitter {
    constructor() { super(); this.readyState = 1; this.bufferedAmount = 0; this.sent = []; all.push(this); setImmediate(() => this.emit('open')); }
    send(s) { const e = JSON.parse(s); this.sent.push(e); if (e.type === 'session.start') setImmediate(() => this.emit('message', JSON.stringify({ type: 'session.started', session: {} }))); }
    terminate() {}
  }
  const presenter = { start: async () => { asked.push('start'); return 'presenting'; }, stop: async () => 'stopped', reset: async () => {} };
  const bridge = new LiveBridge({
    providerConfig: { provider: 'gateway', model: 'openai/gpt-live-1', placeholder: 'cc-speech-' + '0'.repeat(48), maxMinutes: 30, wake: { enabled: false, words: ['Jarvis'] }, always: true },
    onAudio: () => {}, onToolCall: t => tools.push(t), onClearAudio: () => {}, onClose: () => {}, onError: () => {},
  }, { WebSocket: WS, metric: () => {}, voiceDir: dir, record: voiceRecord('meeting', dir), presenter, lease: () => ({ at: new Date().toISOString(), meetingId: MEETING, present: true }), fetch: async () => ({ ok: true, json: async () => ({ token: 'tok' }) }) });
  await bridge.connect();
  const ws = all[0];
  const said = text => ws.emit('message', JSON.stringify({ type: 'session.input_transcript.delta', delta: text }));
  const delegate = id => ws.emit('message', JSON.stringify({ type: 'session.delegation.created', delegation: { id } }));
  said('Bob, can you share your screen?'); delegate('d1');
  await new Promise(r => setTimeout(r, 1700));
  assert.deepEqual(asked, []);
  await new Promise(r => setTimeout(r, 1300));
  said(' Jarvis, share your screen please.'); delegate('d2');
  await new Promise(r => setTimeout(r, 50));
  assert.deepEqual(asked, ['start']);
  bridge.close();
});

test('the outcome is said even when the model delegated again for the same request', async () => {
  const { EventEmitter } = await import('node:events');
  const { mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { LiveBridge } = await import('../roles/controlclaw/files/meeting-voice/live.js');
  const { voiceRecord } = await import('../roles/controlclaw/files/meeting-voice/record.js');
  const dir = mkdtempSync(join(tmpdir(), 'cc-present-')), all = [];
  class WS extends EventEmitter {
    constructor() { super(); this.readyState = 1; this.bufferedAmount = 0; this.sent = []; all.push(this); setImmediate(() => this.emit('open')); }
    send(s) { const e = JSON.parse(s); this.sent.push(e); if (e.type === 'session.start') setImmediate(() => this.emit('message', JSON.stringify({ type: 'session.started', session: {} }))); }
    terminate() {}
  }
  let finish; const presenter = { start: () => new Promise(r => { finish = r; }), stop: async () => 'stopped', reset: async () => {} };
  const bridge = new LiveBridge({
    providerConfig: { provider: 'gateway', model: 'openai/gpt-live-1', placeholder: 'cc-speech-' + '0'.repeat(48), maxMinutes: 30, wake: { enabled: false, words: ['Jarvis'] }, always: true },
    onAudio: () => {}, onToolCall: () => {}, onClearAudio: () => {}, onClose: () => {}, onError: () => {},
  }, { WebSocket: WS, metric: () => {}, voiceDir: dir, record: voiceRecord('meeting', dir), presenter, lease: () => ({ at: new Date().toISOString(), meetingId: MEETING, present: true }), fetch: async () => ({ ok: true, json: async () => ({ token: 'tok' }) }) });
  await bridge.connect();
  const ws = all[0];
  ws.emit('message', JSON.stringify({ type: 'session.input_transcript.delta', delta: 'Jarvis, share your screen.' }));
  ws.emit('message', JSON.stringify({ type: 'session.delegation.created', delegation: { id: 'd1' } }));
  ws.emit('message', JSON.stringify({ type: 'session.delegation.created', delegation: { id: 'd2' } }));
  finish('presenting'); await new Promise(r => setTimeout(r, 30));
  const said = ws.sent.filter(e => e.type === 'session.commentary.append' && e.delegation_id === 'd1');
  assert.equal(said.length, 1); assert.match(said[0].content, /now presenting/);
  bridge.close();
});

test('"leave the meeting", said to the agent: a goodbye and a leave line for the vm-agent, no consult and no task', async () => {
  const { EventEmitter } = await import('node:events');
  const { mkdtempSync, readFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { LiveBridge } = await import('../roles/controlclaw/files/meeting-voice/live.js');
  const { voiceRecord } = await import('../roles/controlclaw/files/meeting-voice/record.js');
  const dir = mkdtempSync(join(tmpdir(), 'cc-leave-')), all = [], tools = [];
  class WS extends EventEmitter {
    constructor() { super(); this.readyState = 1; this.bufferedAmount = 0; this.sent = []; all.push(this); setImmediate(() => this.emit('open')); }
    send(s) { const e = JSON.parse(s); this.sent.push(e); if (e.type === 'session.start') setImmediate(() => this.emit('message', JSON.stringify({ type: 'session.started', session: {} }))); }
    terminate() {}
  }
  const bridge = new LiveBridge({
    providerConfig: { provider: 'gateway', model: 'openai/gpt-live-1', placeholder: 'cc-speech-' + '0'.repeat(48), maxMinutes: 30, wake: { enabled: false, words: ['Jarvis'] }, always: true },
    onAudio: () => {}, onToolCall: t => tools.push(t), onClearAudio: () => {}, onClose: () => {}, onError: () => {},
  }, { WebSocket: WS, metric: () => {}, voiceDir: dir, record: voiceRecord('meeting', dir), presenter: { reset: async () => {} }, lease: () => ({ at: new Date().toISOString(), meetingId: MEETING, full: true }), fetch: async () => ({ ok: true, json: async () => ({ token: 'tok' }) }) });
  await bridge.connect();
  const ws = all[0];
  const said = text => ws.emit('message', JSON.stringify({ type: 'session.input_transcript.delta', delta: text }));
  const delegate = id => ws.emit('message', JSON.stringify({ type: 'session.delegation.created', delegation: { id } }));
  said("Bob, I think we should leave the meeting soon."); delegate('d1');
  await new Promise(r => setTimeout(r, 50));
  assert.equal(tools.length, 1, 'not said to the agent: the consult, as before');
  bridge.submitToolResult('d1', { text: 'Okay.' });
  await new Promise(r => setTimeout(r, 1300));
  said(' Jarvis, you can leave the meeting now.'); delegate('d2');
  await new Promise(r => setTimeout(r, 50));
  assert.equal(tools.length, 1, 'no consult, no task');
  assert.match(readFileSync(join(dir, 'meeting.jsonl'), 'utf8'), /"kind":"leave"/);
  assert.match(ws.sent.filter(e => e.type === 'session.commentary.append').at(-1).content, /leaving the meeting now/);
  bridge.close();
});
