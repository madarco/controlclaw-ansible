// A meeting consult carries the whole meeting the first time and only what is new after that
// (consult-delta): live.js offers both, the patched OpenClaw consult (meeting-runtime-patch.py,
// realtime-session-harness) picks. The patch half runs the patched functions themselves, cut out
// of the pinned host archive in MEET_UPSTREAM (tests/README-meetings.md).
import './fixtures/home.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { runInNewContext } from 'node:vm';
import { LiveBridge } from '../roles/controlclaw/files/meeting-voice/live.js';

// ---- live.js: what each consult carries ----

function bridge(dir, meetingId = 'm1') {
  const tools = [];
  const req = { providerConfig: { provider: 'gateway', model: 'openai/gpt-live-1', surface: 'meeting', wake: { enabled: false, words: ['Jarvis'] } }, onAudio: () => {}, onToolCall: t => tools.push(t), onTranscript: () => {}, onClose: () => {}, onClearAudio: () => {} };
  const b = new LiveBridge(req, { metric: () => {}, voiceDir: dir, lease: () => ({ at: '', owner: null, meetingId, full: false, present: false }) });
  b.ws = { readyState: 1, bufferedAmount: 0, send: () => {}, terminate: () => {} }; b.ready = true;
  let n = 0;
  const ask = (q = 'Jarvis, a question?') => {
    b.event({ type: 'session.input_transcript.delta', delta: q });
    b.event({ type: 'session.delegation.created', delegation: { id: `d${++n}` } });
    return tools.at(-1);
  };
  return { b, tools, ask };
}
const at = s => new Date(Date.parse('2026-10-15T10:00:00Z') + s * 1000).toISOString();
const caption = (dir, s, speaker, text) => appendFileSync(join(dir, 'captions.jsonl'), JSON.stringify({ at: at(s), speaker, text }) + '\n');
const live = (dir, rows) => writeFileSync(join(dir, 'captions-live.json'), JSON.stringify({ rows: rows.map(([s, speaker, text]) => ({ at: at(s), speaker, text })) }));
const own = (dir, s, text) => appendFileSync(join(dir, 'meeting.jsonl'), JSON.stringify({ at: at(s), kind: 'line', role: 'assistant', text }) + '\n');
const rules = ctx => ctx.slice(0, ctx.indexOf('\n\n'));

test('the first consult carries the whole meeting; a later one only what finished since the last answer', () => {
  const dir = mkdtempSync(join(process.env.HOME, 'delta-'));
  caption(dir, 1, 'Alice', 'The launch moved to Thursday.');
  caption(dir, 2, 'Bob', 'Budget is twelve thousand.');
  const f = bridge(dir);
  const first = f.ask().args;
  assert.match(first.context, /The meeting so far[\s\S]*launch moved to Thursday[\s\S]*twelve thousand/);
  assert.equal(first.ccMeetingDelta, undefined, 'nothing is known to be in the consult session yet');

  f.b.submitToolResult('d1', { text: 'Thursday.', ccRecorded: true });
  caption(dir, 3, 'Carol', 'Marketing wants a demo video.');
  own(dir, 4, 'The launch is on Thursday.');
  const second = f.ask().args;
  assert.match(second.context, /launch moved to Thursday[\s\S]*demo video/, 'the whole meeting is still offered, for a session that turns out new');
  const delta = second.ccMeetingDelta;
  assert.match(delta, /More of the meeting since your last answer[\s\S]*Carol: Marketing wants a demo video\./);
  assert.doesNotMatch(delta, /launch moved to Thursday|twelve thousand/, 'not what the session already has');
  assert.match(delta, /Jarvis: The launch is on Thursday/, 'the agent\'s own line too: OpenClaw\'s recent voice lines keep only the last few');
  assert.equal(rules(delta), rules(second.context), 'the rules come first and unchanged, so they cache');
  assert.match(rules(delta), /^How to handle this request/);

  f.b.submitToolResult('d2', { text: 'ok', ccRecorded: true });
  const third = f.ask().args;
  assert.match(third.ccMeetingDelta, /Nothing more was said in the meeting since your last answer\./);
  f.b.close();
});

test('a failed consult is not counted, a restart starts over, a long gap sends the whole meeting', () => {
  const dir = mkdtempSync(join(process.env.HOME, 'delta-'));
  caption(dir, 1, 'Alice', 'First point.');
  const f = bridge(dir);
  f.ask(); f.b.submitToolResult('d1', { text: 'ok', ccRecorded: true });
  caption(dir, 2, 'Bob', 'Second point.');
  assert.match(f.ask().args.ccMeetingDelta, /Second point/);
  f.b.submitToolResult('d2', { error: 'Main-agent lookup failed' });
  caption(dir, 3, 'Carol', 'Third point.');
  const after = f.ask().args.ccMeetingDelta;
  assert.match(after, /Second point[\s\S]*Third point/, 'what the failed consult carried is sent again');
  f.b.close();

  // A new voice session of the same meeting (the next wake word, or after a pause): it goes on from
  // what the meeting's earlier sessions delivered, as they share one consult session.
  const g = bridge(dir);
  const next = g.ask().args.ccMeetingDelta;
  assert.match(next, /Second point[\s\S]*Third point/, 'the unanswered consult of the last session is not counted');
  assert.doesNotMatch(next, /First point/);
  g.b.submitToolResult('d1', { text: 'ok', ccRecorded: true });
  // Another meeting in the same folder: nothing known.
  const h = bridge(dir, 'm2');
  assert.equal(h.ask().args.ccMeetingDelta, undefined);
  h.b.close();
  for (let i = 0; i < 300; i++) caption(dir, 10 + i, 'Dave', `A long stretch of meeting, line ${i}, with enough words to add up quickly.`);
  const long = g.ask().args;
  assert.equal(long.ccMeetingDelta, undefined, 'more than the delta limit: the whole meeting instead');
  assert.match(long.context, /The meeting so far/);
  g.b.close();
});

test('what is being said now goes in; a line said twice is two lines; a consult that never ran is not counted', async () => {
  const dir = mkdtempSync(join(process.env.HOME, 'delta-'));
  caption(dir, 1, 'Alice', 'Yes.');
  const f = bridge(dir);
  f.ask(); f.b.submitToolResult('d1', { text: 'ok', ccRecorded: true });
  caption(dir, 70, 'Alice', 'Yes.');
  live(dir, [[75, 'Bob', 'And the budget is']]);
  const d = f.ask().args.ccMeetingDelta;
  assert.match(d, /Alice: Yes\.[\s\S]*Bob: And the budget is/, 'the same words later are new, and the caption being written is in');
  f.b.submitToolResult('d2', { text: 'ok', ccRecorded: true });
  assert.match(f.ask().args.ccMeetingDelta, /Bob: And the budget is/, 'an unfinished caption goes in each time until it is finished');
  f.b.submitToolResult('d3', { text: 'ok', ccRecorded: true });

  // The tool call itself refused: nothing pending is left behind, and its lines come again.
  writeFileSync(join(dir, 'captions-live.json'), '{"rows":[]}');
  caption(dir, 80, 'Carol', 'Shipping on Monday.');
  f.b.req.onToolCall = () => Promise.reject(new Error('down'));
  f.ask();
  await new Promise(r => setImmediate(r));
  assert.equal([...f.b.consultRecord({ meetingId: 'm1' }).pending.keys()].length, 0);
  f.b.req.onToolCall = t => f.tools.push(t);
  assert.match(f.ask().args.ccMeetingDelta, /Carol: Shipping on Monday/);
  f.b.close();
});

test('lines count only when OpenClaw recorded the consult', () => {
  const dir = mkdtempSync(join(process.env.HOME, 'delta-'));
  caption(dir, 1, 'Alice', 'First point.');
  const f = bridge(dir);
  f.ask(); f.b.submitToolResult('d1', { text: 'busy, try again' });
  assert.equal(f.ask().args.ccMeetingDelta, undefined, 'an answer OpenClaw did not record (a refusal, no patch): nothing delivered');
  f.b.submitToolResult('d2', { text: 'ok', ccRecorded: true });
  caption(dir, 2, 'Bob', 'Second point.');
  f.ask(); f.b.submitToolResult('d3', { text: 'ok' });
  const d = f.ask().args.ccMeetingDelta;
  assert.match(d, /Bob: Second point/, 'the unrecorded consult\'s lines are sent again');
  assert.doesNotMatch(d, /First point/);
  f.b.close();
});

test('a consult the next voice session takes over counts there', () => {
  const dir = mkdtempSync(join(process.env.HOME, 'delta-'));
  caption(dir, 1, 'Alice', 'First point.');
  const f = bridge(dir);
  f.ask(); f.b.close();
  // The answer reaches the next session of the meeting (adopted, or a late result).
  const g = bridge(dir);
  g.b.submitToolResult('d1', { text: 'ok', ccRecorded: true });
  caption(dir, 2, 'Bob', 'Second point.');
  const d = g.ask().args.ccMeetingDelta;
  assert.match(d, /Bob: Second point/);
  assert.doesNotMatch(d, /First point/);
  g.b.close();
});

test('a consult past the voice\'s time limit still counts when its answer comes', () => {
  const dir = mkdtempSync(join(process.env.HOME, 'delta-'));
  caption(dir, 1, 'Alice', 'First point.');
  const f = bridge(dir);
  f.ask();
  f.b.timeout(f.b.jobs.get('d1'));
  f.b.submitToolResult('d1', { text: 'late', ccRecorded: true });
  f.b.settle('d1');  // the grace after a timeout
  caption(dir, 2, 'Bob', 'Second point.');
  const d = f.ask().args.ccMeetingDelta;
  assert.match(d, /Bob: Second point/);
  assert.doesNotMatch(d, /First point/);
  f.b.close();
});

test('no captions yet: what the voice just said is the context', () => {
  const dir = mkdtempSync(join(process.env.HOME, 'delta-'));
  const f = bridge(dir);
  f.b.event({ type: 'session.output_transcript.delta', delta: 'Let me look that up.' });
  const ctx = f.ask().args.context;
  assert.match(ctx, /The voice assistant just said: Let me look that up\./);
  assert.doesNotMatch(ctx, /The meeting so far/);
  f.b.close();
});

test('a phone consult carries no meeting and no delta', () => {
  const tools = [];
  const req = { providerConfig: { provider: 'gateway', model: 'openai/gpt-live-1', surface: 'phone' }, onAudio: () => {}, onToolCall: t => tools.push(t), onTranscript: () => {}, onClose: () => {}, onClearAudio: () => {} };
  const b = new LiveBridge(req, { metric: () => {} });
  b.ws = { readyState: 1, bufferedAmount: 0, send: () => {}, terminate: () => {} }; b.ready = true;
  b.event({ type: 'session.input_transcript.delta', delta: 'check my notes' });
  b.event({ type: 'session.delegation.created', delegation: { id: 'p1' } });
  b.submitToolResult('p1', { text: 'ok' });
  b.event({ type: 'session.input_transcript.delta', delta: 'and again' });
  b.event({ type: 'session.delegation.created', delegation: { id: 'p2' } });
  assert.equal(tools[1].args.ccMeetingDelta, undefined);
  assert.doesNotMatch(tools[1].args.context ?? '', /meeting/);
  b.close();
});

// ---- the patched OpenClaw consult: which of the two it uses ----

const upstream = process.env.MEET_UPSTREAM || '/tmp/meet-upstream';
const noUpstream = existsSync(join(upstream, 'host/package')) ? false : 'needs the pinned host archive in MEET_UPSTREAM';
const patched = noUpstream ? '' : execFileSync('python3', ['-c', `
import importlib.util, shutil, sys, tempfile, contextlib, io
from pathlib import Path
s = importlib.util.spec_from_file_location('p', 'roles/controlclaw/files/meeting-runtime-patch.py'); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
up = Path(sys.argv[1])
with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    for p in m.PATCHES:
        t = root / p['kind'] / p['path']; t.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(up / ('host/package' if p['kind'] == 'host' else 'package') / p['path'], t)
    with contextlib.redirect_stdout(io.StringIO()): m.patch(root / 'host', root / 'plugin')
    spec = [p for p in m.PATCHES if 'realtime-session-harness' in p['path']][0]
    print((root / 'host' / spec['path']).read_text())
`, upstream], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });

function patchedFunctions() {
  const start = patched.indexOf('/** ControlClaw (consult-delta)');
  const end = patched.indexOf('async function consultRealtimeVoiceAgent(params) {');
  assert.ok(start > 0 && end > start, 'the patched helpers are in the file');
  // A fresh copy of the helpers: a fresh process, with nothing remembered.
  return runInNewContext(`${patched.slice(start, end)}; ({ ccMeetingContextChoice, ccMeetingContextRecord })`, {});
}

test('the patched prompt is built from the choice, and the record follows an answered consult', { skip: noUpstream }, () => {
  assert.match(patched, /args: ccMeetingContext\.args,\n\t+transcript: ccMeetingContext\.transcript,/);
  assert.match(patched, /assertRealtimeVoiceConsultNotInterrupted\(abortSignal, result\.meta\);\n\t+const ccRecorded = ccMeetingContextRecord\(params, agentId, storePath, ccMeetingContext\) \? \{ ccRecorded: true \} : \{\};/);
  // Every answer of the run says whether it was recorded.
  assert.equal(patched.match(/\.\.\.ccRecorded\n/g)?.length, 3);
});

const KEY = 'agent:main:subagent:google-meet:meet_1';
function runtime(entry) {
  return { session: { getSessionEntry: () => entry.current } };
}
const consult = (args, transcript = []) => ({ sessionKey: KEY, args, transcript, logger: { info: () => {} } });
const full = 'RULES\n\nTIME\n\nThe meeting so far, from its captions:\nA\nB';
const delta = 'RULES\n\nTIME\n\nMore of the meeting since your last answer:\nC';

test('first, later, reset, compaction, restart', { skip: noUpstream }, () => {
  const { ccMeetingContextChoice: choose, ccMeetingContextRecord: record } = patchedFunctions();
  const store = { current: { sessionId: 's1', compactionCount: 0 } };
  const answered = (p, c) => record({ ...p, agentRuntime: runtime(store) }, 'main', '/store', c);
  const voice1 = [{ role: 'user', text: 'when is the launch' }, { role: 'assistant', text: 'let me check' }];

  // First consult: no record, the whole meeting (live.js offers no delta yet anyway).
  let p = consult({ question: 'q1', context: full }, voice1);
  let c = choose(p, store.current);
  assert.equal(c.used, false); assert.equal(c.args.context, full); assert.equal(c.args.ccMeetingDelta, undefined);
  answered(p, c);

  // Later, same session: the new part, and only voice lines it has not carried.
  const voice2 = [...voice1, { role: 'user', text: 'and the budget' }];
  p = consult({ question: 'q2', context: full, ccMeetingDelta: delta }, voice2);
  c = choose(p, store.current);
  assert.equal(c.used, true); assert.equal(c.args.context, delta); assert.equal('ccMeetingDelta' in c.args, false);
  assert.deepEqual(c.transcript, [{ role: 'user', text: 'and the budget' }]);
  answered(p, c);

  // A line said again ("yes") is a new turn, not one already carried.
  const voice3 = [...voice2, { role: 'assistant', text: 'let me check' }];
  p = consult({ question: 'q2b', context: full, ccMeetingDelta: delta }, voice3);
  c = choose(p, store.current);
  assert.deepEqual(c.transcript, [{ role: 'assistant', text: 'let me check' }]);
  answered(p, c);

  // The window moved on: an old line sliding out does not hide the same words said again.
  const window1 = [{ role: 'user', text: 'yes' }, { role: 'user', text: 'the budget' }, { role: 'assistant', text: 'let me check' }];
  p = consult({ question: 'q2c', context: full }, window1);
  c = choose(p, store.current); answered(p, c);
  const window2 = [{ role: 'user', text: 'the budget' }, { role: 'assistant', text: 'let me check' }, { role: 'user', text: 'yes' }];
  p = consult({ question: 'q2d', context: full, ccMeetingDelta: delta }, window2);
  c = choose(p, store.current);
  assert.deepEqual(c.transcript, [{ role: 'user', text: 'yes' }]);
  answered(p, c);
  // No overlap at all: every line is new.
  const window3 = [{ role: 'user', text: 'something else' }];
  p = consult({ question: 'q2e', context: full, ccMeetingDelta: delta }, window3);
  assert.deepEqual(choose(p, store.current).transcript, window3);

  // Reset: a new session id. The whole meeting, and the full voice lines.
  store.current = { sessionId: 's2', compactionCount: 0 };
  p = consult({ question: 'q3', context: full, ccMeetingDelta: delta }, voice2);
  c = choose(p, store.current);
  assert.equal(c.used, false); assert.equal(c.args.context, full); assert.equal(c.transcript, voice2);
  answered(p, c);

  // Compaction since the last answer: the first message may be gone from the history.
  store.current = { sessionId: 's2', compactionCount: 1 };
  c = choose(consult({ question: 'q4', context: full, ccMeetingDelta: delta }), store.current);
  assert.equal(c.used, false);
  answered(consult({ question: 'q4', context: full }), c);
  assert.equal(choose(consult({ question: 'q5', context: full, ccMeetingDelta: delta }), store.current).used, true, 'after an answered full consult, the delta again');

  // Compaction during the run: what was recorded is dropped, the next consult sends everything.
  p = consult({ question: 'q6', context: full, ccMeetingDelta: delta });
  c = choose(p, store.current);
  assert.equal(c.used, true);
  store.current = { sessionId: 's2', compactionCount: 2 };
  answered(p, c);
  assert.equal(choose(consult({ question: 'q7', context: full, ccMeetingDelta: delta }), store.current).used, false);

  // The session gone (deleted) after a run: forgotten.
  p = consult({ question: 'q8', context: full });
  c = choose(p, store.current); answered(p, c);
  store.current = undefined;
  answered(p, c);
  assert.equal(choose(consult({ question: 'q9', context: full, ccMeetingDelta: delta }), { sessionId: 's3', compactionCount: 0 }).used, false);

  // A restart of the gateway: a new process remembers nothing.
  const fresh = patchedFunctions();
  assert.equal(fresh.ccMeetingContextChoice(consult({ question: 'q', context: full, ccMeetingDelta: delta }), { sessionId: 's2', compactionCount: 2 }).used, false);
});

test('a history-turn limit on the subagent key: no delta', { skip: noUpstream }, () => {
  const { ccMeetingContextChoice: choose, ccMeetingContextRecord: record } = patchedFunctions();
  const store = { current: { sessionId: 's1', compactionCount: 0 } };
  const p = { ...consult({ question: 'q', context: full }), agentRuntime: runtime(store) };
  assert.equal(record(p, 'main', '/store', choose(p, store.current)), true);
  const later = { ...consult({ question: 'q2', context: full, ccMeetingDelta: delta }), cfg: { channels: { subagent: { historyLimit: 5 } } } };
  assert.equal(choose(later, store.current).used, false);
  assert.equal(choose({ ...later, cfg: {} }, store.current).used, true);
});

test('only meeting consults: another surface keeps its args, whatever it carries', { skip: noUpstream }, () => {
  const { ccMeetingContextChoice: choose, ccMeetingContextRecord: record } = patchedFunctions();
  const store = { current: { sessionId: 's1', compactionCount: 0 } };
  const p = { sessionKey: 'agent:main:subagent:talk:x', args: { question: 'q', context: 'C', ccMeetingDelta: 'D' }, transcript: [], logger: { info: () => {} }, agentRuntime: runtime(store) };
  const c = choose(p, store.current);
  assert.equal(c.meeting, false); assert.equal(c.used, false); assert.equal(c.args.context, 'C');
  record(p, 'main', '/store', c);
  assert.equal(choose(p, store.current).used, false, 'nothing recorded for it');
});
