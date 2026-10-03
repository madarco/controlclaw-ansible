#!/usr/bin/env python3
"""One-time enrollment only. No remote shell, updater, or reusable claim channel."""
import glob
import json
import os
from pathlib import Path
import re
import subprocess
import time
import threading
import urllib.error
import urllib.request

CONFIG = Path('/root/cc-pool-worker.json')
PAYLOAD = Path('/root/cc-pool-claim.json')
CLAIMED = Path('/etc/controlclaw/pool-claimed')
ALLOWED = {
    'vm_id', 'vm_hostname', 'vm_bootstrap_token', 'register_api_url', 'saas_public_key',
    'ready_api_url', 'config_api_url', 'controlclaw_url', 'org_id', 'box_role',
    'mitm_private_subnet', 'proxy_ip', 'mitm_box_private_ip', 'mitm_vm_public_key',
    'disk_encryption', 'luks_recovery_pubkey', 'ansible_repo_url', 'ansible_branch',
    'update_allow_unverified', 'ssh_debug', 'handle_hostname',
}
UNITS = ['openclaw', 'controlclaw-agent', 'browser-stream', 'caddy', 'controlclaw-mitmproxy',
         'controlclaw-mitm-agent', 'controlclaw-connector', 'tangd.socket', 'dnsmasq']


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def verify_idle(config):
    run(['nft', 'list', 'table', 'inet', 'controlclaw_metadata'], stdout=subprocess.DEVNULL)
    denied = subprocess.run(['runuser', '-u', 'nobody', '--', 'curl', '--noproxy', '*', '-fsS', '--max-time', '2',
                             'http://169.254.169.254/hetzner/v1/userdata'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if denied.returncode == 0:
        raise ValueError('metadata accessible to non-root')
    if Path('/root/.ssh/authorized_keys').exists() and Path('/root/.ssh/authorized_keys').stat().st_size:
        raise ValueError('operator SSH key present')
    marker = Path('/etc/controlclaw/base-image').read_text()
    if config['commit'] not in marker:
        raise ValueError('image mismatch')


def local(config, action, value=None):
    return subprocess.run(['node', str(Path(config['checkout']) / 'roles/controlclaw/files/cc-pool-local.cjs'), action],
                          input=json.dumps(value) if value is not None else None, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=40)


def warm(config):
    if Path('/etc/controlclaw/pool-warmed').exists():
        return
    base = config['url'].split('/api/internal/ready-pool/poll')[0]
    variables = {'pool_unclaimed': True, 'vm_id': config['boxId'], 'vm_hostname': config['hostname'],
                 'box_role': config['role'], 'disk_encryption': True, 'org_id': 'unclaimed',
                 'controlclaw_url': base, 'config_api_url': base + '/api/vm-agent/config',
                 'proxy_ip': config['proxyIp'], 'mitm_box_private_ip': config['firewallIp'],
                 'ansible_repo_url': config['repo'], 'ansible_branch': config['branch'],
                 'update_allow_unverified': False, 'ssh_debug': False}
    path = Path('/root/cc-pool-warm-vars.json')
    path.write_text(json.dumps(variables))
    os.chmod(path, 0o600)
    with open('/var/log/cc-pool-warm.log', 'a') as log:
        result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', 'playbook.yml', '-e', '@' + str(path)],
                                cwd=config['checkout'], stdout=log, stderr=log, umask=0o022)
    if result.returncode:
        Path('/etc/controlclaw/pool-failed').touch(mode=0o600)
    else:
        Path('/etc/controlclaw/pool-warmed').touch(mode=0o600)
    path.unlink(missing_ok=True)


def validate(payload, config):
    if set(payload) != {'action', 'vars', 'progress'} or payload['action'] != 'claim':
        raise ValueError('invalid claim')
    variables = payload['vars']
    if not isinstance(variables, dict) or not set(variables) <= ALLOWED:
        raise ValueError('unknown variable')
    if any(not isinstance(value, str) for value in variables.values()):
        raise ValueError('invalid variable')
    if variables.get('box_role') != config['role'] or variables.get('disk_encryption') != 'true':
        raise ValueError('role/encryption mismatch')
    if variables.get('ansible_repo_url') != config['repo'] or variables.get('ansible_branch') != config['branch']:
        raise ValueError('source mismatch')
    base = config['url'].split('/api/internal/ready-pool/poll')[0]
    for key, path in [('ready_api_url', '/api/vm-agent/ready'), ('register_api_url', '/api/vm-agent/register')]:
        if variables.get(key) != base + path:
            raise ValueError('callback mismatch')
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,250}', variables.get('vm_hostname', '')):
        raise ValueError('invalid hostname')
    if config['role'] == 'openclaw' and variables.get('config_api_url') != base + '/api/vm-agent/config':
        raise ValueError('config callback mismatch')
    if config['role'] == 'mitm' and variables.get('controlclaw_url') != base:
        raise ValueError('control callback mismatch')
    if variables.get('vm_id') != config['boxId'] or variables.get('vm_hostname') != config['hostname']:
        raise ValueError('identity mismatch')
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', variables.get('org_id', '')):
        raise ValueError('invalid organization')
    if not re.fullmatch(r'[A-Za-z0-9+/]{43}=', variables.get('luks_recovery_pubkey', '')):
        raise ValueError('invalid recovery public key')
    alias = variables.get('handle_hostname', '')
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', alias.split('.')[0]) or alias.split('.', 1)[-1] != config['hostname'].split('.', 1)[-1]:
        raise ValueError('invalid alias')
    if not variables.get('luks_recovery_pubkey') or variables.get('ssh_debug') != 'false' or variables.get('update_allow_unverified') != 'false':
        raise ValueError('claim hardening missing')
    progress = payload['progress']
    if set(progress) != {'url', 'token', 'vmId'} or progress['url'] != base + '/api/vm-agent/provision' or progress['vmId'] != variables['vm_id']:
        raise ValueError('progress mismatch')
    if not re.fullmatch(r'[a-f0-9]{64}', progress['token']):
        raise ValueError('progress token invalid')
    return variables


def report_progress(payload, stage, rc=None, task="Ready-pool claim"):
    progress = payload['progress']
    request = urllib.request.Request(progress['url'], method='POST',
        data=json.dumps({'vm_id': progress['vmId'], 'stage': stage, 'rc': rc,
                         'task': task}).encode(),
        headers={'Authorization': 'Bearer ' + progress['token'], 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=2):
            pass
    except (OSError, ValueError):
        pass


def claim(config):
    payload = json.loads(PAYLOAD.read_text())
    variables = validate(payload, config)
    # Retain only the API-verified root claim as the immutable identity source for later updates.
    original = Path('/root/cc-ansible-vars.json')
    original.write_text(json.dumps(variables))
    os.chmod(original, 0o600)
    # Never put the token in argv or stdout. Only this root-owned file reaches Ansible.
    varfile = Path('/root/cc-pool-vars.json')
    varfile.write_text(json.dumps(variables))
    os.chmod(varfile, 0o600)
    report_progress(payload, 'started', task='Sealing existing disk and registering prepared identity')
    result = local(config, 'activate')
    report_progress(payload, 'finished', result.returncode)
    if result.returncode:
        Path('/etc/controlclaw/pool-failed').touch(mode=0o600)
        subprocess.run(['systemctl', 'disable', 'cc-pool-worker'], check=False)
        return
    # Tang binding and a valid certificate are claim requirements, beyond process startup.
    proof = subprocess.run(['node', str(Path(config['checkout']) / 'roles/controlclaw/files/cc-pool-complete.cjs'), str(varfile)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if proof.returncode:
        report_progress(payload, 'finished', 1)
        Path('/etc/controlclaw/pool-failed').touch(mode=0o600)
        return
    Path('/etc/controlclaw/pool-activating').unlink(missing_ok=True)
    CLAIMED.write_text(variables['vm_id'])
    for path in [PAYLOAD, CONFIG, varfile]:
        path.unlink(missing_ok=True)
    subprocess.run(['systemctl', 'disable', 'cc-pool-worker'], check=False)


def main():
    os.umask(0o077)
    if CLAIMED.exists() or Path('/etc/controlclaw/pool-failed').exists():
        return
    config = json.loads(CONFIG.read_text())
    if PAYLOAD.exists():
        claim(config)
        return
    threading.Thread(target=warm, args=(config,), daemon=True).start()
    while True:
        if Path('/etc/controlclaw/pool-failed').exists():
            return
        verify_idle(config)
        facts_result = local(config, 'facts')
        facts = json.loads(facts_result.stdout) if facts_result.returncode == 0 else None
        ready = local(config, 'health').returncode == 0
        request = urllib.request.Request(config['url'], method='POST',
            data=json.dumps({'boxId': config['boxId'], 'protocol': 2, 'ready': ready, **({'facts': facts} if facts else {})}).encode(),
            headers={'Authorization': 'Bearer ' + config['token'], 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                payload = json.loads(response.read(65536))
        except urllib.error.HTTPError as error:
            if error.code in (401, 403, 410):
                # A lost consumed response cannot be redelivered. Cold fallback owns recovery.
                subprocess.run(['systemctl', 'disable', 'cc-pool-worker'], check=False)
                return
            time.sleep(2)
            continue
        except (OSError, ValueError):
            time.sleep(2)
            continue
        if payload.get('action') == 'wait':
            if payload.get('peer'):
                local(config, 'peer', payload['peer'])
            time.sleep(2)
            continue
        validate(payload, config)
        temporary = PAYLOAD.with_suffix('.tmp')
        with open(temporary, 'w') as output:
            json.dump(payload, output)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(PAYLOAD)
        subprocess.run(['systemctl', 'disable', 'cc-pool-worker'], check=False)
        claim(config)
        return


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Never serialize requests, tokens, variables, or subprocess output into journal logs.
        print('Pool worker failed a local assertion', flush=True)
        raise SystemExit(1)
