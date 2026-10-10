import './fixtures/home.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtempSync, writeFileSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AlwaysBridge } from '../roles/controlclaw/files/meeting-voice/always-session.js';

const wait = (ms = 5) => new Promise(r => setTimeout(r, ms));
async function until(check, ms = 2000) { const end = Date.now() + ms; while (!check()) { if (Date.now() > end) throw new Error('timed out'); await wait(); } }

/** Fake gpt-live sockets: each answers session.start with session.started. */
function sockets() {
  const all = [];
  class WS extends EventEmitter {
    constructor(url) { super(); this.url = url; this.readyState = 1; this.bufferedAmount = 0; this.sent = []; all.push(this); setImmediate(() => this.emit('open')); }
    send(s) { const e = JSON.parse(s); this.sent.push(e); if (e.type === 'session.start') setImmediate(() => this.emit('message', JSON.stringify({ type: 'session.started', session: {} }))); }
    terminate() { this.readyState = 3; this.emit('close'); }
  }
  const frames = ws => ws.sent.filter(e => e.type === 'session.input_audio.append');
  return { WS, all, frames, audio: ws => frames(ws).reduce((n, e) => n + Buffer.from(e.audio, 'base64').length, 0) };
}
function fixture({ sessions, timing = {}, voiceDir, mint = () => true } = {}) {
  const ws = sockets(), out = { audio: [], tones: [], ready: 0, errors: 0, closed: [], tools: [], mints: 0 };
  const metrics = [], usage = [];
  const req = {
    providerConfig: { provider: 'gateway', model: 'openai/gpt-live-1', placeholder: 'cc-speech-' + '0'.repeat(48), maxMinutes: 30, wake: { enabled: false, words: ['Jarvis', 'Maria Rossi'] }, sessions },
    instructions: 'Respond when someone addresses you.',
    onAudio: (a, m) => (m?.itemId?.startsWith('cc_tone_') ? out.tones : out.audio).push(a), onReady: () => out.ready++, onError: () => out.errors++, onClose: r => out.closed.push(r), onToolCall: t => out.tools.push(t), onClearAudio: () => {},
  };
  const deps = {
    WebSocket: ws.WS, metric: m => metrics.push(m), voiceDir, record: { usage: s => usage.push(s), line: () => {}, end: () => {} },
    fetch: async () => { out.mints++; return { ok: mint(out.mints), json: async () => ({ token: 'tok' }) }; },
    timing: { pause: 150, tick: 10, context: 30, startGap: 0, speech: 300, window: 1500, replay: 4000, lost: 0, ...timing },
  };
  return { bridge: new AlwaysBridge(req, deps), ws, out, metrics, usage };
}
const pcm = (ms, level = 2000) => { const b = Buffer.alloc(ms * 48); for (let i = 0; i < b.length; i += 2) b.writeInt16LE(i % 4 ? level : -level, i); return b; };
const silence = ms => Buffer.alloc(ms * 48);

test('one session for the meeting, opened at once, with the always-listening rules and no wake word', async () => {
  const f = fixture();
  await f.bridge.connect();
  assert.equal(f.out.ready, 1); assert.equal(f.out.mints, 1); assert.equal(f.ws.all.length, 1);
  const instructions = f.ws.all[0].sent[0].session.instructions;
  assert.match(instructions, /Your default is silence/);
  assert.match(instructions, /by name \(Jarvis or Maria Rossi\)/);
  assert.match(instructions, /"I asked Jarvis yesterday"/);
  assert.doesNotMatch(instructions, /starts with one of your names|seemed to call you/);
  f.bridge.close();
  assert.deepEqual(f.out.closed, ['completed']);
});

test('meeting audio goes out in 100 ms frames, whatever size it arrives in; what the model says is played; no tones', async () => {
  const f = fixture();
  await f.bridge.connect();
  const ws = f.ws.all[0];
  for (let i = 0; i < 100; i++) f.bridge.sendAudio(pcm(20));
  assert.equal(f.ws.audio(ws), 100 * 20 * 48);
  assert.equal(f.ws.frames(ws).length, 20);
  ws.emit('message', JSON.stringify({ type: 'session.input_transcript.delta', delta: 'Jarvis, what day is it?' }));
  ws.emit('message', JSON.stringify({ type: 'session.output_audio.delta', delta: pcm(100).toString('base64') }));
  assert.equal(f.out.audio.length, 1); assert.equal(f.out.tones.length, 0);
  f.bridge.close();
});

test('silence pauses the voice and stops billing; a click does not reconnect, speech does, replaying the last seconds', async () => {
  const f = fixture();
  await f.bridge.connect();
  f.bridge.sendAudio(pcm(100));
  // Quiet audio keeps arriving; the session is closed after the pause time.
  const quiet = setInterval(() => f.bridge.sendAudio(silence(20)), 5);
  await until(() => f.bridge.paused);
  clearInterval(quiet);
  assert.ok(f.ws.all[0].sent.some(e => e.type === 'session.close'));
  assert.equal(f.usage.length, 1, 'the closed session is recorded');
  assert.equal(f.out.errors, 0); assert.deepEqual(f.out.closed, [], 'the meeting voice stays up while paused');
  f.bridge.sendAudio(pcm(100));
  await wait(20);
  assert.equal(f.out.mints, 1, 'a short noise does not reconnect');
  for (let i = 0; i < 5; i++) f.bridge.sendAudio(pcm(100));
  await until(() => f.bridge.session?.ready);
  assert.equal(f.out.mints, 2);
  const ws = f.ws.all[1];
  await until(() => f.ws.audio(ws) >= 6 * 4800);
  assert.ok(f.ws.audio(ws) >= 6 * 4800, 'what was said while it was paused is heard');
  f.bridge.sendAudio(pcm(100));
  await until(() => f.ws.audio(ws) >= 7 * 4800);
  assert.ok(f.metrics.some(m => m.phase === 'paused') && f.metrics.some(m => m.phase === 'resumed'));
  f.bridge.close();
});

test('the agent talking, someone talking or a running lookup keeps the session', async () => {
  const f = fixture({ timing: { pause: 80 } });
  await f.bridge.connect();
  const ws = f.ws.all[0];
  ws.emit('message', JSON.stringify({ type: 'session.input_transcript.delta', delta: 'Jarvis, what is the snack?' }));
  ws.emit('message', JSON.stringify({ type: 'session.delegation.created', delegation: { id: 'd1' } }));
  assert.equal(f.out.tools.length, 1);
  await wait(200);
  assert.ok(f.bridge.session, 'open while the lookup runs');
  f.bridge.submitToolResult('d1', { text: 'Lemon shortbread.' });
  assert.ok(ws.sent.some(e => e.type === 'session.commentary.append' && /Lemon/.test(e.content)));
  const talk = setInterval(() => f.bridge.sendAudio(pcm(20)), 5);
  await wait(200);
  assert.ok(f.bridge.session, 'open while someone speaks');
  clearInterval(talk);
  await until(() => f.bridge.paused);
  f.bridge.close();
});

test('a session the provider ends is replaced; two that end at once stop the voice', async () => {
  const f = fixture({ timing: { pause: 60000, lost: 0 } });
  await f.bridge.connect();
  f.ws.all[0].emit('message', JSON.stringify({ type: 'session.closed', usage: { seconds: 12 } }));
  await until(() => f.ws.all.length === 2 && f.bridge.session?.ready);
  assert.equal(f.out.errors, 0);
  f.bridge.sendAudio(pcm(100));
  assert.equal(f.ws.audio(f.ws.all[1]), 4800);
  f.bridge.close();

  const g = fixture({ timing: { pause: 60000, lost: 60000 } });
  await g.bridge.connect();
  g.ws.all[0].terminate();
  await until(() => g.ws.all.length === 2 && g.bridge.session?.ready);
  g.ws.all[1].terminate();
  await until(() => g.out.errors === 1);
  assert.deepEqual(g.out.closed, ['completed']);
});

test('the session allowance: when it is used up, the voice stops instead of reconnecting', async () => {
  const f = fixture({ sessions: 2, timing: { pause: 40 } });
  await f.bridge.connect();
  for (let round = 0; round < 2; round++) {
    await until(() => f.bridge.paused);
    for (let i = 0; i < 5; i++) f.bridge.sendAudio(pcm(100));
    if (round === 0) await until(() => f.bridge.session?.ready);
  }
  await until(() => f.out.errors === 1);
  assert.equal(f.out.mints, 2);
});

test('a refused reconnect is tried once more', async () => {
  const f = fixture({ timing: { pause: 40 }, mint: n => n !== 2 });
  await f.bridge.connect();
  await until(() => f.bridge.paused);
  for (let i = 0; i < 5; i++) f.bridge.sendAudio(pcm(100));
  await until(() => f.bridge.session?.ready);
  assert.equal(f.out.mints, 3); assert.equal(f.out.errors, 0);
  f.bridge.close();
});

test('a refused first session fails the join', async () => {
  const f = fixture({ mint: () => false });
  await assert.rejects(f.bridge.connect());
  assert.equal(f.out.ready, 0);
});

test('captions: the meeting so far starts a session, finished lines follow as quiet context', async () => {
  const voiceDir = mkdtempSync(join(tmpdir(), 'cc-always-'));
  const at = s => new Date(Date.now() - s * 1000).toISOString();
  writeFileSync(join(voiceDir, 'captions.jsonl'), JSON.stringify({ at: at(60), speaker: 'Anna', text: 'The launch moved to Thursday.' }) + '\n');
  const f = fixture({ voiceDir, timing: { pause: 60000 } });
  await f.bridge.connect();
  const ws = f.ws.all[0];
  assert.match(ws.sent[0].session.instructions, /Anna: The launch moved to Thursday\./);
  appendFileSync(join(voiceDir, 'captions.jsonl'), JSON.stringify({ at: at(1), speaker: 'Bob', text: 'Fine by me.' }) + '\n');
  await until(() => ws.sent.some(e => e.type === 'session.thinking.append'));
  const note = ws.sent.find(e => e.type === 'session.thinking.append');
  assert.equal(note.delegation_id, null);
  assert.match(note.content, /Bob: Fine by me\./); assert.doesNotMatch(note.content, /Thursday/);
  await wait(100);
  assert.equal(ws.sent.filter(e => e.type === 'session.thinking.append').length, 1, 'a line is sent once');
  f.bridge.close();
});

test('the second opinion: what the model says is played only after a name, a follow-up to its own words, or a lookup', async () => {
  const f = fixture({ timing: { pause: 60000 } });
  await f.bridge.connect();
  const ws = f.ws.all[0];
  const hear = text => ws.emit('message', JSON.stringify({ type: 'session.input_transcript.delta', delta: text }));
  const say = () => ws.emit('message', JSON.stringify({ type: 'session.output_audio.delta', delta: pcm(100).toString('base64') }));
  // Two people talk; the model answers a question that was not for it: not played, and counted.
  hear('Bob, can you send me the mockups after lunch?');
  say(); say();
  assert.equal(f.out.audio.length, 0);
  assert.equal(f.metrics.filter(m => m.phase === 'suppressed').length, 1);
  // A name in the middle of a sentence opens it (whether to answer is the model's call).
  hear(' Yesterday I asked Maria Rossi about it.');
  say();
  assert.equal(f.out.audio.length, 1);
  // Having spoken, a follow-up without the name is played too.
  hear(' And can you check that for us?');
  say();
  assert.equal(f.out.audio.length, 2);
  f.bridge.close();

  // A lookup nobody asked for is answered quietly.
  const g = fixture({ timing: { pause: 60000 } });
  await g.bridge.connect();
  const quiet = g.ws.all[0];
  quiet.emit('message', JSON.stringify({ type: 'session.delegation.created', delegation: { id: 'd1' } }));
  g.bridge.submitToolResult('d1', { text: 'Thursday.' });
  assert.ok(quiet.sent.some(e => e.type === 'session.thinking.append' && /Thursday/.test(e.content)));
  assert.ok(!quiet.sent.some(e => e.type === 'session.commentary.append'));
  g.bridge.close();
});
