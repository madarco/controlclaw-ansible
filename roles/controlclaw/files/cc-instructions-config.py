#!/usr/bin/env python3
"""Load the cc-instructions plugin (files/cc-instructions-plugin) in OpenClaw's config. Idempotent.

It adds ControlClaw's instructions (/var/lib/controlclaw-instructions/AGENTS.md, which the vm-agent
writes through cc-instructions: the Drive folders, the meeting orders) to the system context of every
run. Its before_prompt_build hook only runs for a plugin from outside OpenClaw's bundle when
hooks.allowConversationAccess is set (OpenClaw 2026.11), and so does its agent_end hook, which keeps a
finished conversation's turns for the brain while the owner's switch is on (brain-capture.js). It
changes nothing else. Also drops cc-workspace-context, its name on the builds before it moved out of the workspace.
"""
import json
import os
import sys

PLUGIN = 'cc-instructions'
DIR = '/usr/local/lib/controlclaw/openclaw-plugins/cc-instructions'
OLD = ('cc-workspace-context', '/opt/controlclaw/workspace-context')
path = sys.argv[1]
if not os.path.exists(path):
    sys.exit(0)  # OpenClaw writes its config on the first start; the next run of the role adds this.
with open(path) as f:
    config = json.load(f)
before = json.dumps(config, sort_keys=True)
plugins = config.setdefault('plugins', {})
entries = plugins.setdefault('entries', {})
entries.pop(OLD[0], None)
entry = entries.setdefault(PLUGIN, {})
entry['enabled'] = True
entry.setdefault('hooks', {})['allowConversationAccess'] = True
if isinstance(plugins.get('allow'), list):
    plugins['allow'] = [p for p in plugins['allow'] if p != OLD[0]]
    if PLUGIN not in plugins['allow']:
        plugins['allow'].append(PLUGIN)
load = plugins.setdefault('load', {})
paths = [p for p in load.get('paths') or [] if p != OLD[1]]
if DIR not in paths:
    paths.append(DIR)
load['paths'] = paths
if json.dumps(config, sort_keys=True) != before:
    tmp = path + '.cc-instructions.tmp'
    with open(tmp, 'w') as f:
        json.dump(config, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    print('changed')
