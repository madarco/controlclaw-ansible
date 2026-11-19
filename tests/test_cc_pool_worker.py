#!/usr/bin/env python3
"""The ready-pool worker takes a real organization's claim, and says why when it refuses one.

Run from the repo root: python3 -m unittest tests/test_cc_pool_worker.py

Organization ids are Better Auth's own (32 of a-z, A-Z and 0-9). The worker allowed lowercase only,
so every real sign-up's claim was refused after the console had spent the box's one-time enrollment:
the worker exited, its next poll got 401, and the console waited out its three-minute deadline with
nothing to go on (controlclaw T-poolclaim). The worker is loaded from the shipped file; nothing here
needs root, a network or Ansible.
"""
import copy
import importlib.machinery
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('cc_pool_worker', str(ROOT / 'roles/controlclaw/files/cc-pool-worker.py'))
spec = importlib.util.spec_from_loader('cc_pool_worker', loader)
worker = importlib.util.module_from_spec(spec)
loader.exec_module(worker)

# What Better Auth's generateId() gives an organization (a real one's shape, not a real one).
BETTER_AUTH_ORG = 'Qx7mR2pLk9TzWb4NvC8sJd1HfY6gAe3U'


class Fixture(unittest.TestCase):
    def setUp(self):
        self.config = {'role': 'openclaw', 'boxId': 'box', 'hostname': 'p-box.vm.example.com', 'repo': 'https://source.test/repo',
                       'branch': 'main', 'url': 'https://app.test/api/internal/ready-pool/poll', 'checkout': '/pinned/source', 'token': 'b' * 64}
        self.payload = {'action': 'claim', 'vars': {
            'box_role': 'openclaw', 'disk_encryption': 'true', 'ansible_repo_url': self.config['repo'], 'ansible_branch': 'main',
            'config_api_url': 'https://app.test/api/vm-agent/config', 'ready_api_url': 'https://app.test/api/vm-agent/ready',
            'register_api_url': 'https://app.test/api/vm-agent/register', 'vm_hostname': 'p-box.vm.example.com',
            'luks_recovery_pubkey': 'a' * 43 + '=', 'org_id': BETTER_AUTH_ORG, 'handle_hostname': 'handle.vm.example.com',
            'ssh_debug': 'false', 'update_allow_unverified': 'false', 'vm_id': 'box'},
            'progress': {'url': 'https://app.test/api/vm-agent/provision', 'token': 'a' * 64, 'vmId': 'box'}}


class OrganizationIds(Fixture):
    def test_a_better_auth_organization_is_accepted(self):
        self.assertEqual(worker.validate(self.payload, self.config)['org_id'], BETTER_AUTH_ORG)

    def test_an_older_lowercase_id_still_is(self):
        self.payload['vars']['org_id'] = 'r6ztwyevd5g5xyo2xf78fvx2'
        worker.validate(self.payload, self.config)

    def test_anything_that_is_not_an_id_is_refused(self):
        for value in ['', '-lead', 'org id', 'org;id', 'org/id', 'org_id', 'a' * 64, 'ORG\nX=1']:
            with self.subTest(value=value):
                bad = copy.deepcopy(self.payload)
                bad['vars']['org_id'] = value
                with self.assertRaisesRegex(ValueError, 'invalid organization'):
                    worker.validate(bad, self.config)


class Refusal(Fixture):
    """A claim the box refuses is reported, with its reason, on the claim's own progress callback."""

    def run_poll(self, payload):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'etc/controlclaw').mkdir(parents=True)
            (root / 'root').mkdir()
            config_path = root / 'root/cc-pool-worker.json'
            config_path.write_text(json.dumps(self.config))
            reports, systemctl = [], []

            def local_path(value):
                return root / str(value).lstrip('/')

            class Response:
                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return False

                def read(self, _limit):
                    return json.dumps(payload).encode()

            def report(_payload, stage, rc=None, task='Ready-pool claim'):
                reports.append((stage, rc, task))

            with patch.object(worker, 'Path', local_path), patch.object(worker, 'CONFIG', config_path), \
                 patch.object(worker, 'PAYLOAD', root / 'root/cc-pool-claim.json'), \
                 patch.object(worker, 'CLAIMED', root / 'etc/controlclaw/pool-claimed'), \
                 patch.object(worker, 'verify_idle'), patch.object(worker, 'warm'), \
                 patch.object(worker, 'local', return_value=worker.subprocess.CompletedProcess([], 1, stdout='')), \
                 patch.object(worker, 'report_progress', side_effect=report), \
                 patch.object(worker, 'claim') as claim, \
                 patch.object(worker.urllib.request, 'urlopen', return_value=Response()), \
                 patch.object(worker.subprocess, 'run', side_effect=lambda args, **_: systemctl.append(args)):
                worker.main()
                return {'reports': reports, 'systemctl': systemctl, 'claimed': claim.called,
                        'failed': (root / 'etc/controlclaw/pool-failed').exists(),
                        'payload_written': (root / 'root/cc-pool-claim.json').exists()}

    def test_a_valid_claim_is_run(self):
        result = self.run_poll(self.payload)
        self.assertTrue(result['claimed'])
        self.assertTrue(result['payload_written'])
        self.assertEqual(result['reports'], [])

    def test_a_refused_claim_says_why_and_stops(self):
        bad = copy.deepcopy(self.payload)
        bad['vars']['org_id'] = 'org;id'
        result = self.run_poll(bad)
        self.assertFalse(result['claimed'])
        self.assertFalse(result['payload_written'])
        self.assertTrue(result['failed'])
        self.assertEqual(result['reports'], [('finished', 1, 'Ready-pool claim refused by the box: invalid organization')])
        self.assertIn(['systemctl', 'disable', 'cc-pool-worker'], result['systemctl'])

    def test_a_refusal_never_reports_to_another_address(self):
        bad = copy.deepcopy(self.payload)
        bad['vars']['org_id'] = 'org;id'
        bad['progress']['url'] = 'https://elsewhere.test/api/vm-agent/provision'
        result = self.run_poll(bad)
        self.assertEqual(result['reports'], [])
        self.assertTrue(result['failed'])

    def test_something_that_is_not_a_claim_is_not_a_refusal(self):
        # The enrollment is only spent by a claim: anything else keeps the box polling after a restart.
        with self.assertRaises(ValueError):
            self.run_poll({'action': 'other', 'vars': {}, 'progress': {}})


class ActivationTimeout(Fixture):
    def test_a_timed_out_activation_is_reported_as_one(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ['root', 'etc/controlclaw']:
                (root / name).mkdir(parents=True)
            (root / 'root/cc-pool-claim.json').write_text(json.dumps(self.payload))
            reports = []

            def local_path(value):
                return root / str(value).lstrip('/')

            def timeout(*_args, **_kwargs):
                raise worker.subprocess.TimeoutExpired('node', 40)

            with patch.object(worker, 'Path', local_path), patch.object(worker, 'PAYLOAD', root / 'root/cc-pool-claim.json'), \
                 patch.object(worker, 'local', side_effect=timeout), \
                 patch.object(worker, 'report_progress', side_effect=lambda _p, stage, rc=None, task='': reports.append((stage, rc, task))), \
                 patch.object(worker.subprocess, 'run'):
                worker.claim(self.config)
            self.assertEqual(reports[-1], ('finished', 1, 'Ready-pool claim: activation did not finish in time'))
            self.assertTrue((root / 'etc/controlclaw/pool-failed').exists())


if __name__ == '__main__':
    unittest.main()
