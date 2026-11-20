import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { STATE, SPOOL, MAX_FILE_BYTES, captureEnabled, isConversation, lastTurn, markEnded, recordTurn, spoolFile } from '../roles/controlclaw/files/cc-instructions-plugin/brain-capture.js';

const on = () => true;
const off = () => false;
const turn = (user, answer) => ({ success: true, messages: [
  { role: 'user', content: 'earlier' }, { role: 'assistant', content: 'earlier answer' },
  { role: 'user', content: [{ type: 'text', text: user }, { type: 'image', data: 'xx' }] },
  { role: 'assistant', content: [{ type: 'toolCall', name: 'search' }] },
  { role: 'toolResult', content: [{ type: 'text', text: 'tool output stays out' }] },
  { role: 'assistant', content: [{ type: 'text', text: answer }] },
] });
const lines = (f) => readFileSync(f, 'utf8').trim().split('\n').map((l) => JSON.parse(l));

test('the switch and the spool are in the vm-agent state directory (inside the container)', () => {
  assert.equal(STATE, '/opt/controlclaw/state/brain-capture.json');
  assert.equal(SPOOL, '/opt/controlclaw/state/brain-capture');
});

test('the switch: only {"enabled": true} is on; no file or a bad file is off', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ccbc-'));
  const f = join(dir, 'state.json');
  assert.equal(captureEnabled(f), false);
  writeFileSync(f, '{"enabled": true}');
  assert.equal(captureEnabled(f), true);
  writeFileSync(f, 'nope');
  assert.equal(captureEnabled(f), false);
  rmSync(dir, { recursive: true });
});

test('conversations only: not hooks (the save runs), cron, sub-agents or heartbeats', () => {
  assert.equal(isConversation('agent:main:main', 'user'), true);
  assert.equal(isConversation('agent:main:telegram:direct:42', undefined), true);
  for (const k of ['hook:1f2e', 'agent:main:hook:abc', 'cron:job1', 'agent:main:subagent:x', 'agent:main:heartbeat']) {
    assert.equal(isConversation(k, 'user'), false, k);
  }
  assert.equal(isConversation('agent:main:main', 'heartbeat'), false);
  assert.equal(isConversation('agent:main:main', 'cron'), false);
  assert.equal(isConversation(undefined, 'user'), false);
});

test('the turn is the last user message and the text the agent answered, no tools', () => {
  assert.deepEqual(lastTurn(turn('Anna moved to Lisbon', 'Noted.').messages), { user: 'Anna moved to Lisbon', assistant: 'Noted.' });
  assert.equal(lastTurn([{ role: 'user', content: 'hi' }]), null);
  assert.equal(lastTurn('x'), null);
});

test('switch off: nothing is written', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ccbc-'));
  assert.equal(recordTurn(turn('a', 'b'), { sessionKey: 'agent:main:main', trigger: 'user' }, dir, off), false);
  assert.deepEqual(readdirSync(dir), []);
  rmSync(dir, { recursive: true });
});

test('turns go to one file per conversation, named by a hash of its key, then the end', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ccbc-'));
  const ctx = { sessionKey: 'agent:main:telegram:direct:42', trigger: 'user', channel: 'telegram' };
  assert.equal(recordTurn(turn('one', 'first'), ctx, dir, on), true);
  assert.equal(recordTurn(turn('two', 'second'), ctx, dir, on), true);
  assert.equal(recordTurn({ ...turn('x', 'y'), success: false }, ctx, dir, on), false);
  const f = spoolFile(ctx.sessionKey, dir);
  assert.ok(!f.includes('42'));
  let l = lines(f);
  assert.deepEqual(l[0], { session: ctx.sessionKey, channel: 'telegram' });
  assert.deepEqual(l.slice(1).map((x) => x.user), ['one', 'two']);
  assert.equal(markEnded({ reason: 'shutdown', sessionKey: ctx.sessionKey }, {}, dir, on), false);
  assert.equal(markEnded({ reason: 'new', sessionKey: ctx.sessionKey }, {}, dir, on), true);
  l = lines(f);
  assert.equal(l.at(-1).ended, 'new');
  assert.equal(markEnded({ reason: 'new', sessionKey: 'agent:main:other' }, {}, dir, on), false);
  assert.equal(existsSync(spoolFile('agent:main:other', dir)), false);
  rmSync(dir, { recursive: true });
});

test('a long conversation keeps its newest turns under the cap, and its first line', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ccbc-'));
  const ctx = { sessionKey: 'agent:main:main', trigger: 'user' };
  for (let i = 0; i < 60; i++) recordTurn(turn(`question ${i} ${'x'.repeat(900)}`, 'ok'), ctx, dir, on);
  const f = spoolFile(ctx.sessionKey, dir);
  assert.ok(readFileSync(f).length <= MAX_FILE_BYTES + 1);
  const l = lines(f);
  assert.equal(l[0].session, ctx.sessionKey);
  assert.match(l.at(-1).user, /^question 59/);
  rmSync(dir, { recursive: true });
});
