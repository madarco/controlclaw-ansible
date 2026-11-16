import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import plugin, { contextFile, readContext, promptContext } from '../roles/controlclaw/files/workspace-context/index.js';

test('the file is the one the vm-agent writes, under the box user\'s home', () => {
  assert.equal(contextFile({ HOME: '/home/controlclaw' }), '/home/controlclaw/.openclaw/workspace/controlclaw/AGENTS.md');
});

test('no file, an empty file: nothing is added to the turn', () => {
  const home = mkdtempSync(join(tmpdir(), 'wsctx-'));
  const file = contextFile({ HOME: home });
  assert.equal(promptContext(readContext(file)), undefined);
  mkdirSync(join(home, '.openclaw/workspace/controlclaw'), { recursive: true });
  writeFileSync(file, '  \n');
  assert.equal(promptContext(readContext(file)), undefined);
  rmSync(home, { recursive: true });
});

test('the file goes into the system context, read again when it changes', () => {
  const home = mkdtempSync(join(tmpdir(), 'wsctx-'));
  const file = contextFile({ HOME: home });
  mkdirSync(join(home, '.openclaw/workspace/controlclaw'), { recursive: true });
  writeFileSync(file, '# ControlClaw\n\n- Team: `/home/controlclaw/drive/Team` (read-only)\n');
  const first = promptContext(readContext(file));
  assert.match(first.appendSystemContext, /\/home\/controlclaw\/drive\/Team/);
  assert.match(first.appendSystemContext, /^## ControlClaw \(controlclaw\/AGENTS\.md\)/);
  writeFileSync(file, '# ControlClaw\n\n- Archive: `/home/controlclaw/drive/Archive` (read-write) and more\n');
  assert.match(promptContext(readContext(file)).appendSystemContext, /Archive/);
  rmSync(home, { recursive: true });
});

test('it registers one before_prompt_build hook', () => {
  const hooks = [];
  plugin.register({ on: (name, fn) => hooks.push([name, fn]) });
  assert.deepEqual(hooks.map(([n]) => n), ['before_prompt_build']);
});
