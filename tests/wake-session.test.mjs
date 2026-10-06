import './fixtures/home.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { WakeSessionBridge, resampler } from '../roles/controlclaw/files/meeting-voice/wake-session.js';

const wait = (ms = 5) => new Promise(r => setTimeout(r, ms));
async function until(check, ms = 2000) { const end = Date.now() + ms; while (!check()) { if (Date.now() > end) throw new Error('timed out'); await wait(); } }

/** A fake cc-wake process: says ready, records what it was fed, emits what the test tells it. */
function detector({ ready = true } = {}) {
  const child = new EventEmitter();
  child.stdout = new EventEmitter(); child.fed = 0; child.killed = false;
  child.stdin = { writable: true, writableLength: 0, write: b => { child.fed += b.length; }, on: () => {} };
  child.kill = () => { child.killed = true; };
  child.say = event => child.stdout.emit('data', JSON.stringify(event) + '\n');
  if (ready) setImmediate(() => child.say({ type: 'ready' })); else setImmediate(() => child.emit('exit', 1));
  return child;
}
/** Fake gpt-live sockets: each answers session.start with session.started. */
function sockets() {
  const all = [];
  class WS extends EventEmitter {
    constructor(url) { super(); this.url = url; this.readyState = 1; this.bufferedAmount = 0; this.sent = []; all.push(this); setImmediate(() => this.emit('open')); }
    send(s) { const e = JSON.parse(s); this.sent.push(e); if (e.type === 'session.start') setImmediate(() => this.emit('message', JSON.stringify({ type: 'session.started', session: {} }))); if (e.type === 'session.close') setImmediate(() => this.emit('message', JSON.stringify({ type: 'session.closed', usage: { seconds: 21 } }))); }
    terminate() { this.readyState = 3; this.emit('close'); }
  }
  return { WS, all, audio: ws => ws.sent.filter(e => e.type === 'session.input_audio.append').reduce((n, e) => n + Buffer.from(e.audio, 'base64').length, 0) };
}
function fixture({ wakeSessions = 40, timing = {}, ready = true } = {}) {
  const ws = sockets(), out = { audio: [], ready: 0, errors: 0, closed: [], tools: [], mints: 0 };
  const lines = [];
  let child;
  const req = {
    providerConfig: { provider: 'gateway', model: 'openai/gpt-live-1', placeholder: 'cc-speech-' + '0'.repeat(48), maxMinutes: 30, wake: { enabled: true, words: ['Jarvis', 'Maria Rossi'] }, wakeSessions },
    onAudio: a => out.audio.push(a), onReady: () => out.ready++, onError: () => out.errors++, onClose: r => out.closed.push(r), onToolCall: t => out.tools.push(t), onClearAudio: () => {},
  };
  const deps = {
    WebSocket: ws.WS, metric: () => {}, record: { usage: (s, f) => lines.push({ kind: 'usage', seconds: s, family: f }), line: () => {} },
    fetch: async () => { out.mints++; return { ok: true, json: async () => ({ token: 'tok' }) }; },
    spawn: (cmd, args) => { child = detector({ ready }); child.args = args; return child; },
    timing: { idle: 200, confirm: 100, startGap: 0, retry: 20, tick: 10, ...timing },
  };
  const bridge = new WakeSessionBridge(req, deps);
  return { bridge, ws, out, lines, child: () => child };
}
const pcm = (ms, level = 2000) => { const b = Buffer.alloc(ms * 48); for (let i = 0; i < b.length; i += 2) b.writeInt16LE(i % 4 ? level : -level, i); return b; };

test('24 kHz meeting audio reaches the detector at 16 kHz', () => {
  const r = resampler(); let n = 0;
  for (let k = 0; k < 10; k++) n += r(pcm(100)).length;
  assert.equal(n, 16000 * 2);
});

test('nobody calls it: the detector hears everything, no session is opened, nothing is billed', async () => {
  const f = fixture();
  await f.bridge.connect();
  assert.equal(f.out.ready, 1);
  assert.deepEqual(f.child().args.slice(1), ['Jarvis', 'Maria Rossi']);
  for (let i = 0; i < 50; i++) f.bridge.sendAudio(pcm(100));
  assert.equal(f.child().fed, 50 * 3200);
  assert.equal(f.out.mints, 0); assert.equal(f.ws.all.length, 0);
  f.bridge.close();
  assert.equal(f.child().killed, true);
});

test('a partial opens a silent session early; the confirmed name replays the last seconds, then live audio follows', async () => {
  const f = fixture();
  await f.bridge.connect();
  for (let i = 0; i < 100; i++) f.bridge.sendAudio(pcm(100)); // 10 s: only the last 8 s are kept
  f.child().say({ type: 'partial', name: 'Jarvis' });
  await until(() => f.bridge.session?.ready);
  const ws = f.ws.all[0];
  assert.equal(f.out.mints, 1); assert.equal(f.ws.audio(ws), 0, 'an unconfirmed session gets no audio');
  assert.match(ws.sent[0].session.instructions, /seemed to call you by one of your names \(Jarvis or Maria Rossi\)/);
  f.child().say({ type: 'wake', name: 'Jarvis', conf: 0.93, stop: false });
  await until(() => f.ws.audio(ws) >= 8 * 48000);
  assert.equal(f.ws.audio(ws), 8 * 48000);
  f.bridge.sendAudio(pcm(100));
  await until(() => f.ws.audio(ws) === 8 * 48000 + 4800);
  // The model answers; its audio goes to the meeting.
  ws.emit('message', JSON.stringify({ type: 'session.output_audio.delta', delta: pcm(100).toString('base64') }));
  assert.equal(f.out.audio.length, 1);
  f.bridge.close();
});

test('names heard during a session open nothing new; "<name>, stop" ends it; quiet ends it too', async () => {
  const f = fixture();
  await f.bridge.connect();
  f.child().say({ type: 'wake', name: 'Jarvis', conf: 0.9, stop: false });
  await until(() => f.bridge.session?.ready);
  f.child().say({ type: 'partial', name: 'Maria Rossi' });
  f.child().say({ type: 'wake', name: 'Maria Rossi', conf: 0.9, stop: false });
  await wait(20);
  assert.equal(f.out.mints, 1, 'the agent echoed back from a speaker cannot open a second session');
  f.child().say({ type: 'wake', name: 'Jarvis', conf: 0.9, stop: true });
  assert.equal(f.bridge.session, null);
  assert.ok(f.ws.all[0].sent.some(e => e.type === 'session.close'));
  await until(() => f.lines.length === 1);
  assert.deepEqual(f.lines[0], { kind: 'usage', seconds: 21, family: 'live' });
  // A new request opens a new session, which closes itself after the quiet time.
  f.child().say({ type: 'wake', name: 'Maria Rossi', conf: 0.9, stop: false });
  await until(() => f.bridge.session?.ready);
  assert.equal(f.out.mints, 2);
  await until(() => f.bridge.session === null, 1000);
  assert.ok(f.ws.all[1].sent.some(e => e.type === 'session.close'));
  assert.equal(f.out.errors, 0); assert.deepEqual(f.out.closed, [], 'the meeting voice stays connected between sessions');
  f.bridge.close();
});

test('an unconfirmed early session closes unused; a running lookup keeps a quiet session open', async () => {
  const f = fixture();
  await f.bridge.connect();
  f.child().say({ type: 'partial', name: 'Jarvis' });
  await until(() => f.bridge.session?.ready);
  await until(() => f.bridge.session === null, 1000);
  assert.equal(f.ws.audio(f.ws.all[0]), 0);
  f.child().say({ type: 'wake', name: 'Jarvis', conf: 0.9, stop: false });
  await until(() => f.bridge.session?.ready);
  f.ws.all[1].emit('message', JSON.stringify({ type: 'session.delegation.created', delegation: { id: 'd1' } }));
  assert.equal(f.out.tools.length, 1);
  await wait(400);
  assert.ok(f.bridge.session, 'still open while the lookup runs');
  f.bridge.submitToolResult('d1', { text: 'Lemon shortbread.' });
  assert.ok(f.ws.all[1].sent.some(e => e.type === 'session.commentary.append' && /Lemon/.test(e.content)));
  await until(() => f.bridge.session === null, 1000);
  f.bridge.close();
});

test('the firewall limit: sessions stop opening at wakeSessions; a refused open is retried once', async () => {
  const f = fixture({ wakeSessions: 2 });
  await f.bridge.connect();
  for (let i = 0; i < 3; i++) {
    f.child().say({ type: 'wake', name: 'Jarvis', conf: 0.9, stop: false });
    await wait(30);
    f.child().say({ type: 'wake', name: 'Jarvis', conf: 0.9, stop: true });
    await wait(10);
  }
  assert.equal(f.out.mints, 2);
  f.bridge.close();
  const g = fixture();
  let refuse = true;
  const fetch = g.bridge.deps.fetch;
  g.bridge.deps.fetch = async (...a) => { if (refuse) { refuse = false; g.out.mints++; return { ok: false }; } return fetch(...a); };
  await g.bridge.connect();
  g.child().say({ type: 'wake', name: 'Jarvis', conf: 0.9, stop: false });
  await until(() => g.bridge.session?.ready);
  assert.equal(g.out.mints, 2);
  g.bridge.close();
});

test('without the local detector, the meeting falls back to one transcript-gated session', async () => {
  const f = fixture({ ready: false });
  await f.bridge.connect();
  assert.ok(f.bridge.fallback);
  assert.equal(f.out.mints, 1);
  assert.match(f.ws.all[0].sent[0].session.instructions, /Speak only when someone's request starts with one of your names: Jarvis or Maria Rossi/);
  f.bridge.close();
});

test('the adapter reports local wake detection', () => {
  const caps = JSON.parse(readFileSync(join(import.meta.dirname, '../roles/controlclaw/files/meeting-voice/capabilities.json'), 'utf8'));
  assert.equal(caps.wakeLocal, true);
});

test('the meeting allowance comes from the firewall lease the vm-agent wrote, and only while fresh', async () => {
  const { meetingWakeSessions } = await import('../roles/controlclaw/files/meeting-voice/record.js');
  const { mkdtempSync, writeFileSync } = await import('node:fs');
  const dir = mkdtempSync(join(process.env.HOME, 'lease-'));
  assert.equal(meetingWakeSessions(dir), 0);
  writeFileSync(join(dir, 'lease.json'), JSON.stringify({ wakeSessions: 40, at: new Date().toISOString() }));
  assert.equal(meetingWakeSessions(dir), 40);
  for (const bad of [{ wakeSessions: 41, at: new Date().toISOString() }, { wakeSessions: 1, at: new Date().toISOString() }, { wakeSessions: 40, at: new Date(Date.now() - 6 * 3600000).toISOString() }, { wakeSessions: '40', at: new Date().toISOString() }]) {
    writeFileSync(join(dir, 'lease.json'), JSON.stringify(bad)); assert.equal(meetingWakeSessions(dir), 0, JSON.stringify(bad));
  }
});
