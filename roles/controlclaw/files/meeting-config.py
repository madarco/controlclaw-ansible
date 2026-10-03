#!/usr/bin/env python3
"""Initialize the installed plugin disabled. Never widen an existing meeting grant."""
import json
import os
import sys
path = sys.argv[1]
with open(path) as f:
    config = json.load(f)
before = json.dumps(config, sort_keys=True)
config.setdefault('plugins', {}).setdefault('entries', {})['cc-meeting-guard'] = {'enabled': True}
config['plugins']['entries']['cc-meeting-voice'] = {'enabled': True}
if isinstance(config['plugins'].get('allow'), list):
    config['plugins']['allow'] = list(dict.fromkeys(config['plugins']['allow'] + ['google-meet', 'cc-meeting-guard', 'cc-meeting-voice']))
paths = config['plugins'].setdefault('load', {}).setdefault('paths', [])
if '/opt/controlclaw/meeting-guard' not in paths:
    paths.append('/opt/controlclaw/meeting-guard')
if '/opt/controlclaw/meeting-voice' not in paths:
    paths.append('/opt/controlclaw/meeting-voice')
entry = config.setdefault('plugins', {}).setdefault('entries', {}).setdefault('google-meet', {})
# A fresh install may auto-enable the plugin. The vm-agent's accepted signed settings are
# the only marker that allows preserving enabled across reprovisioning.
try:
    with open('/opt/controlclaw/state/meetings.json') as f:
        approved = json.load(f)['applied']['policy']['enabled'] is True
except (OSError, ValueError, KeyError, TypeError):
    approved = False
entry['enabled'] = approved
entry.setdefault('config', {}).update({'defaultMode': 'transcribe', 'defaultTransport': 'chrome'})
entry['config']['chrome'] = {'browserProfile': 'cc-meetings', 'guestName': 'ControlClaw meeting assistant', 'audioBackend': 'pipewire-pulse', 'reuseExistingTab': True}
config.setdefault('browser', {}).setdefault('profiles', {})['cc-meetings'] = {'cdpUrl': 'http://127.0.0.1:9223', 'attachOnly': True}
if json.dumps(config, sort_keys=True) != before:
    with open(path + '.meetings.tmp', 'w') as f:
        json.dump(config, f, indent=2)
    os.chmod(path + '.meetings.tmp', 0o600)
    os.replace(path + '.meetings.tmp', path)
    print('changed')
