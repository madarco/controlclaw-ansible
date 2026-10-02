#!/usr/bin/env python3
"""Narrow compatibility patches for integrity-pinned OpenClaw/Meet 2026.9.7.

Local Meet ignored chrome.browserProfile. Route its requests to the ephemeral guest
profile without changing ordinary browser defaults. Native automatic summaries are
local heuristics; vm-agent alone sends cleaned captions to owner-managed inference.
Filter native caption UI artifacts before they enter the transcript database.
Refuse any unreviewed upstream build. This file must be retired as upstream fixes land.
"""
import hashlib
import json
from pathlib import Path
import sys
PATCHES = json.loads(r'''[{"kind": "host", "path": "dist/plugin-sdk/meeting-runtime.js", "before": "6475751b08b9ee36d92f7410edf7f66ecc10ba24d20bf167a6567d67d5548c3f", "after": "446261f48c8d5ac28905a8ad043b68845a75d7480a0a8c9f22b2b95b70bf5bed", "replacements": [["body: params.body,\n\t\ttimeoutMs: params.timeoutMs\n\t}, { progress: false });", "body: params.body,\n\t\tquery: { profile: \"cc-meetings\" },\n\t\ttimeoutMs: params.timeoutMs\n\t}, { progress: false });", 1], ["return async (params) => await runtime.gateway.request(\"browser.request\", {\n\t\tmethod: params.method,", "return async (params) => await runtime.gateway.request(\"browser.request\", {\n\t\tquery: { profile: \"cc-meetings\" },\n\t\tmethod: params.method,", 1]]}, {"kind": "host", "path": "dist/transcripts-bridge.runtime-B9TtIF_x.mjs", "before": "eabb53fdd9e802f6c2d5b6838bd4dc1c1a30b32f5b0c50c74c3eddb33755d0ae", "after": "ccfd70f3c5d7ad10434405a9784fe31a1b657f6028d9f63c6146986e2ac53d89", "replacements": [["cfg: params.options.openclawConfig,", "cfg: {}, // ControlClaw generates cleaned, private notes through vm-agent.", 2]]}, {"kind": "plugin", "path": "dist/.setup/google-meet-platform-adapter-gosgbMIM.mjs", "before": "acac1d308af1ab25941c581b876dec8307fd658a5dffa796790ce7923323f953", "after": "17f339d93899611ccc95ebc86d91ff4ac9b6e69a3db0f6c32a0e122e9c253e42", "replacements": [["if (/^(turn on captions|turn off captions|captions)$/i.test(clean)) return undefined;", "if (/^(turn (on|off) (captions|microphone|camera)|(captions|microphone|camera) (on|off)|(your )?microphone is (on|off|muted)|caption settings|change caption language|captions|mic_off|videocam_off)$/i.test(clean)) return undefined;", 1], ["  const join = !readOnly && ${JSON.stringify(params.autoJoin)}", "  let camera = findCallControlButton(/^\\\\s*turn (?:off|on) camera\\\\b/i);\n  if (!readOnly && camera && /turn off camera/i.test(buttonLabel(camera))) {\n    camera.click();\n    await waitForUi();\n    camera = findCallControlButton(/^\\\\s*turn (?:off|on) camera\\\\b/i);\n  }\n  const join = !readOnly && ${JSON.stringify(params.autoJoin)}", 1], ["    micMuted: mic ? /turn on microphone/i.test(buttonLabel(mic)) : undefined,", "    micMuted: mic ? /turn on microphone/i.test(buttonLabel(mic)) : undefined,\n    cameraOff: camera ? /turn on camera/i.test(buttonLabel(camera)) : undefined,", 1]], "previous": "263bbca53647433c715c4aa698deec2011df7ba3bb27d4fe4918ded55098f8ae", "upgradeReplacements": [["  const join = !readOnly && ${JSON.stringify(params.autoJoin)}", "  let camera = findCallControlButton(/^\\\\s*turn (?:off|on) camera\\\\b/i);\n  if (!readOnly && camera && /turn off camera/i.test(buttonLabel(camera))) {\n    camera.click();\n    await waitForUi();\n    camera = findCallControlButton(/^\\\\s*turn (?:off|on) camera\\\\b/i);\n  }\n  const join = !readOnly && ${JSON.stringify(params.autoJoin)}", 1], ["    micMuted: mic ? /turn on microphone/i.test(buttonLabel(mic)) : undefined,", "    micMuted: mic ? /turn on microphone/i.test(buttonLabel(mic)) : undefined,\n    cameraOff: camera ? /turn on camera/i.test(buttonLabel(camera)) : undefined,", 1]]}]''')

def patch(host, plugin):
    changes = []
    for spec in PATCHES:
        path = Path(host if spec['kind'] == 'host' else plugin) / spec['path']
        source = path.read_text()
        digest = hashlib.sha256(source.encode()).hexdigest()
        if digest == spec['after']:
            continue
        if digest not in (spec['before'], spec.get('previous')):
            raise RuntimeError('Unexpected Meet runtime build: ' + str(path))
        replacements = spec['upgradeReplacements'] if digest == spec.get('previous') else spec['replacements']
        for old, new, count in replacements:
            if source.count(old) != count:
                raise RuntimeError('Unexpected runtime structure')
            source = source.replace(old, new)
        assert hashlib.sha256(source.encode()).hexdigest() == spec['after']
        changes.append((path, source))
    # Check every file before modifying any.
    for path, source in changes:
        path.write_text(source)
    if changes:
        print('changed')

if __name__ == '__main__':
    plugin = Path(sys.argv[2])
    if not (plugin / 'dist/.setup').is_dir():
        candidates = list(plugin.glob('extensions/google-meet/package.json')) + list(plugin.glob('**/node_modules/@openclaw/google-meet/package.json'))
        if len(candidates) != 1:
            raise RuntimeError('Expected exactly one installed Google Meet package')
        plugin = candidates[0].parent
    patch(sys.argv[1], plugin)
