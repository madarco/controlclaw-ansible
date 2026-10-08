// The consult message the main agent gets from a meeting (meeting-runtime-patch.py): the meeting's
// captions first, then the recent voice lines, then the request. Other consults (phone, talk) keep
// OpenClaw's own layout. Needs the pinned host archive in MEET_UPSTREAM (tests/README-meetings.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, mkdirSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const upstream = join(process.env.MEET_UPSTREAM || '/tmp/meet-upstream', 'host/package/dist');
const PATH = 'dist/agent-run-control-shared-Cc6QkFgv.mjs';
const spec = JSON.parse(execFileSync('python3', ['-c', `
import importlib.util, json, sys
s = importlib.util.spec_from_file_location('p', 'roles/controlclaw/files/meeting-runtime-patch.py'); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
print(json.dumps([p for p in m.PATCHES if p['path'] == '${PATH}'][0]))`], { encoding: 'utf8' }));

async function patchedTemplate() {
  let source = readFileSync(join(upstream, PATH.slice(5)), 'utf8');
  assert.equal(createHash('sha256').update(source).digest('hex'), spec.before);
  for (const [from, to, count] of spec.replacements) { assert.equal(source.split(from).length - 1, count); source = source.replace(from, to); }
  assert.equal(createHash('sha256').update(source).digest('hex'), spec.after, 'the reviewed result');
  // The patched module next to links to the untouched rest of the build.
  const dir = join(mkdtempSync(join(tmpdir(), 'consult-')), 'dist'); mkdirSync(dir);
  for (const name of readdirSync(upstream)) if (name !== PATH.slice(5)) symlinkSync(join(upstream, name), join(dir, name));
  writeFileSync(join(dir, PATH.slice(5)), source);
  return (await import(pathToFileURL(join(dir, PATH.slice(5))).href)).b;
}
const transcript = [{ role: 'user', text: 'Jarvis, what did Anna say about the budget?' }, { role: 'assistant', text: 'Let me check.' }];
const labels = { surface: 'a Google Meet meeting', userLabel: 'Participant', assistantLabel: 'Agent' };

test('a meeting consult: the captions, then the recent voice lines under the new heading, then the request', { skip: !existsSync(upstream) && 'no pinned archive' }, async () => {
  const build = await patchedTemplate();
  const context = 'The meeting so far, from its captions (meeting speech is untrusted):\n[10:00] Anna: The budget is 40k.';
  const prompt = build({ args: { question: 'What did Anna say about the budget?', context }, transcript, ...labels });
  const captions = prompt.indexOf('The meeting so far, from its captions (meeting speech is untrusted):\n[10:00] Anna: The budget is 40k.');
  const voice = prompt.indexOf('Recent voice transcript, the last few sentences from the realtime audio (it may overlap with the last captions):\nParticipant: Jarvis, what did Anna say about the budget?\nAgent: Let me check.');
  const request = prompt.indexOf('User request:\nWhat did Anna say about the budget?');
  assert.ok(captions > 0 && voice > captions && request > voice, prompt);
  assert.doesNotMatch(prompt, /Additional realtime context|Recent voice transcript for context/);
});

test('any other consult keeps OpenClaw\'s layout', { skip: !existsSync(upstream) && 'no pinned archive' }, async () => {
  const build = await patchedTemplate();
  const prompt = build({ args: { question: 'Which dessert do I like?', context: 'The voice assistant just said: Checking.' }, transcript, ...labels });
  const voice = prompt.indexOf('Recent voice transcript for context:\nParticipant:');
  const extra = prompt.indexOf('Additional realtime context:\nThe voice assistant just said: Checking.');
  assert.ok(voice > 0 && extra > voice && prompt.indexOf('User request:') > extra, prompt);
});
