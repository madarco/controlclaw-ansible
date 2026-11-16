#!/usr/bin/env python3
"""Load the cc-workspace-context plugin (files/workspace-context) in OpenClaw's config. Idempotent.

It adds controlclaw/AGENTS.md, which the vm-agent writes (the Drive folders, the meeting orders), to
the system context of every turn. Its before_prompt_build hook only runs for a plugin from outside
OpenClaw's bundle when hooks.allowConversationAccess is set (OpenClaw 2026.11); the plugin reads one
file and changes nothing else.
"""
import json
import os
import sys

PLUGIN = 'cc-workspace-context'
DIR = '/opt/controlclaw/workspace-context'
path = sys.argv[1]
if not os.path.exists(path):
    sys.exit(0)  # OpenClaw writes its config on the first start; the next run of the role adds this.
with open(path) as f:
    config = json.load(f)
before = json.dumps(config, sort_keys=True)
plugins = config.setdefault('plugins', {})
entry = plugins.setdefault('entries', {}).setdefault(PLUGIN, {})
entry['enabled'] = True
entry.setdefault('hooks', {})['allowConversationAccess'] = True
if isinstance(plugins.get('allow'), list) and PLUGIN not in plugins['allow']:
    plugins['allow'].append(PLUGIN)
paths = plugins.setdefault('load', {}).setdefault('paths', [])
if DIR not in paths:
    paths.append(DIR)
if json.dumps(config, sort_keys=True) != before:
    tmp = path + '.workspace-context.tmp'
    with open(tmp, 'w') as f:
        json.dump(config, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    print('changed')
