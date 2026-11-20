import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import plugin, { FILE, readInstructions, promptContext } from '../roles/controlclaw/files/cc-instructions-plugin/index.js';

test('the file is the root-owned one outside the workspace', () => {
  assert.equal(FILE, '/var/lib/controlclaw-instructions/AGENTS.md');
});

test('no file, an empty file: nothing is added to the run', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ccins-'));
  const file = join(dir, 'AGENTS.md');
  assert.equal(promptContext(readInstructions(file)), undefined);
  writeFileSync(file, '  \n');
  assert.equal(promptContext(readInstructions(file)), undefined);
  rmSync(dir, { recursive: true });
});

test('the file goes into the system context, read again when it changes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ccins-'));
  const file = join(dir, 'AGENTS.md');
  writeFileSync(file, '# ControlClaw\n\n- Team: `/home/controlclaw/drive/Team` (read-only)\n');
  const first = promptContext(readInstructions(file));
  assert.match(first.appendSystemContext, /^# ControlClaw/);
  assert.match(first.appendSystemContext, /\/home\/controlclaw\/drive\/Team/);
  writeFileSync(file, '# ControlClaw\n\n- Archive: `/home/controlclaw/drive/Archive` (read-write) and more\n');
  assert.match(promptContext(readInstructions(file)).appendSystemContext, /Archive/);
  rmSync(dir, { recursive: true });
});

test('it registers the instructions hook and the two brain capture hooks', () => {
  const hooks = [];
  plugin.register({ on: (name, fn) => hooks.push([name, fn]) });
  assert.deepEqual(hooks.map(([n]) => n), ['before_prompt_build', 'agent_end', 'session_end']);
});
