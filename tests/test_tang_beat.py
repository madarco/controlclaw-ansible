#!/usr/bin/env python3
"""The disk report beat must not start a tangd instance each time it runs (T-tang).

Run from the repo root: python3 -m unittest tests/test_tang_beat.py

tangd.socket is Accept=yes, so every connection to 127.0.0.1:3921 starts a tangd@ unit. The beat
asked /adv for the thumbprint every minute on every box, and every two seconds on a pool box whose
activation had failed, which put tens of thousands of tangd@ instances in a week-old firewall's
journal. Functions are cut out of the shipped scripts, so the tests exercise the shipped text.

The thumbprint test needs root, `jose`, `tang` (for `_tang` and tangd-keygen) and `socat`; it skips
without them.
"""
import json
import os
import pwd
import re
import shutil
import socket
import subprocess
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / 'roles/controlclaw/files'
CC_SECURE = (FILES / 'cc-secure').read_text()
DAEMON = (FILES / 'cc-secure-daemon').read_text()


def shell_function(name):
    return re.search(r'^' + name + r'\(\) \{(?: [^\n]*\}\n|\n.*?^\}\n)', CC_SECURE, re.S | re.M).group(0)


class StatusAsksNoTangd(unittest.TestCase):
    def test_mount_clears_old_tangd_failures_before_its_real_check(self):
        mount = shell_function('cmd_mount')
        self.assertLess(mount.index("reset-failed 'tangd@*'"), mount.index('/adv'))

    def test_status_reads_the_thumbprint_locally(self):
        status = shell_function('cmd_status')
        self.assertIn('tang_thumbprint_local', status)
        self.assertNotIn('cmd_thumbprint', status)
        self.assertNotIn('curl', status)
        self.assertNotIn('curl', shell_function('tang_thumbprint_local'))

    def test_the_beat_calls_status_and_nothing_that_asks_tangd(self):
        loop = re.search(r'^async function reportLoop\(.*?^\}\n', DAEMON, re.S | re.M).group(0)
        self.assertIn('shAsync(["status"])', loop)
        self.assertNotIn('"thumbprint"]', loop)


def have_tang():
    try:
        pwd.getpwnam('_tang')
    except KeyError:
        return False
    return os.geteuid() == 0 and all(shutil.which(t) for t in ['jose', 'socat', 'ss', 'setpriv']) \
        and Path('/usr/libexec/tangd-keygen').exists()


@unittest.skipUnless(have_tang(), 'needs root, jose, tang, socat')
class LocalThumbprintMatchesTheAdvertisement(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        os.chmod(self.dir, 0o755)
        self.db = self.dir / 'tang'
        self.db.mkdir()
        subprocess.run(['/usr/libexec/tangd-keygen', str(self.db)], check=True, capture_output=True)
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            self.port = s.getsockname()[1]
        self.tangd = subprocess.Popen(['socat', f'TCP-LISTEN:{self.port},bind=127.0.0.1,reuseaddr,fork',
                                       f'EXEC:/usr/libexec/tangd {self.db}'], stderr=subprocess.DEVNULL)
        for _ in range(50):
            if subprocess.run(['ss', '-lntH', f'sport = :{self.port}'], capture_output=True, text=True).stdout:
                break
            time.sleep(0.1)

    def tearDown(self):
        self.tangd.kill()
        self.tangd.wait()
        shutil.rmtree(self.dir)

    def local(self, port=None, failed_units=''):
        # systemctl is faked: the socket here is socat, not systemd, and the test decides whether a
        # tangd@ instance has failed.
        fake = self.dir / 'bin'
        fake.mkdir(exist_ok=True)
        (fake / 'systemctl').write_text(f'#!/bin/sh\nprintf %s "{failed_units}"\n')
        os.chmod(fake / 'systemctl', 0o755)
        script = 'set -euo pipefail\n' + shell_function('as_tang') + shell_function('tang_thumbprint_local') + \
            'tang_thumbprint_local 2>/dev/null || true\n'
        env = {**os.environ, 'TANGD_PORT': str(port or self.port), 'TANG_DB': str(self.db),
               'PATH': f"{fake}:{os.environ['PATH']}"}
        return subprocess.run(['bash', '-c', script], env=env, capture_output=True, text=True, check=True).stdout.strip()

    def advertised(self):
        script = (f'curl -sf http://127.0.0.1:{self.port}/adv | jose fmt -j- -g payload -y -o- '
                  '| jose jwk use -i- -r -u verify -o- | jose jwk thp -i-')
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True, check=True).stdout.strip()

    def own(self, user):
        shutil.chown(self.db, user, user)
        for f in self.db.iterdir():
            shutil.chown(f, user, user)

    def test_same_as_the_advertisement_and_after_a_rotation(self):
        self.own('_tang')
        self.assertEqual(self.local(), self.advertised())
        self.assertNotEqual(self.local(), '')
        subprocess.run(['/usr/libexec/tangd-rotate-keys', '-d', str(self.db)], check=True, capture_output=True)
        self.own('_tang')
        self.assertEqual(self.local(), self.advertised())

    def test_empty_when_tangd_could_not_serve_it(self):
        self.own('_tang')
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            idle = s.getsockname()[1]
        self.assertEqual(self.local(port=idle), '', 'nothing listening')
        self.own('root')
        for f in self.db.iterdir():
            os.chmod(f, 0o400)
        self.assertEqual(self.local(), '', 'key unreadable by _tang')
        self.own('_tang')
        os.chmod(self.dir, 0o700)
        self.assertEqual(self.local(), '', 'database not reachable by _tang')
        os.chmod(self.dir, 0o755)
        self.assertNotEqual(self.local(), '')
        self.assertEqual(self.local(failed_units='tangd@3-127.0.0.1:3921-127.0.0.1:5000.service loaded failed'), '',
                         'a tangd@ instance failed')

    def keys(self, use):
        found = []
        for f in self.db.glob('*.jwk'):
            if subprocess.run(['jose', 'jwk', 'use', '-i', str(f), '-r', '-u', use], capture_output=True).returncode == 0:
                found.append(f)
        return found

    def test_empty_without_a_readable_exchange_key(self):
        self.own('_tang')
        exchange = self.keys('deriveKey')[0]
        os.chown(exchange, 0, 0)
        self.assertEqual(self.local(), '', 'exchange key unreadable by _tang')
        exchange.unlink()
        self.assertEqual(self.local(), '', 'no exchange key')

    def test_empty_with_a_corrupt_key(self):
        self.own('_tang')
        bad = self.db / 'corrupt.jwk'
        bad.write_text('not a key')
        shutil.chown(bad, '_tang', '_tang')
        self.assertEqual(self.local(), '')


class PoolBeat(unittest.TestCase):
    """poolBeat() decides the two-second beat. Run in node with the marker files faked."""

    def beat(self, files, now=1_000_000_000):
        consts = re.search(r'^const POOL_BEAT_MS = .*;\n', DAEMON, re.M).group(0)
        fn = re.search(r'^function poolBeat\(\) \{\n.*?^\}\n', DAEMON, re.S | re.M).group(0)
        script = f'''
const files = {json.dumps(files)};
const fs = {{
  existsSync: (p) => p in files,
  statSync: (p) => {{ if (!(p in files)) throw new Error("ENOENT"); return {{ mtimeMs: files[p] }}; }},
}};
Date.now = () => {now};
{consts}{fn}
process.stdout.write(JSON.stringify(poolBeat()));
'''
        return json.loads(subprocess.run(['node', '-e', script], capture_output=True, text=True, check=True).stdout)

    def test_fast_while_unclaimed_or_freshly_activating(self):
        now = 1_000_000_000
        self.assertTrue(self.beat({'/etc/controlclaw/pool-unclaimed': 0}, now))
        self.assertTrue(self.beat({'/etc/controlclaw/pool-activating': now - 60_000}, now))

    def test_ordinary_beat_otherwise(self):
        now = 1_000_000_000
        self.assertFalse(self.beat({}, now))
        self.assertFalse(self.beat({'/etc/controlclaw/pool-activating': now - 16 * 60_000}, now), 'stale marker')
        self.assertFalse(self.beat({'/etc/controlclaw/pool-activating': now, '/etc/controlclaw/pool-failed': now}, now))
        self.assertFalse(self.beat({'/etc/controlclaw/pool-unclaimed': now, '/etc/controlclaw/pool-failed': now}, now))


class FailedActivationLeavesTheFastBeat(unittest.TestCase):
    def load_worker(self):
        worker = types.ModuleType('pool_worker')
        exec(compile((FILES / 'cc-pool-worker.py').read_text(), 'cc-pool-worker.py', 'exec'), worker.__dict__)
        return worker

    def claim(self, activate_rc, proof_rc):
        worker = self.load_worker()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def local_path(value):
                return root / str(value).lstrip('/')
            for name in ['root', 'etc/controlclaw']:
                (root / name).mkdir(parents=True)
            local_path('/etc/controlclaw/pool-activating').write_text('box')
            payload = local_path('/root/cc-pool-claim.json')
            payload.write_text(json.dumps({'vars': {'vm_id': 'box'}, 'progress': {}}))

            def run(args, **kwargs):
                rc = proof_rc if args[0] == 'node' else 0
                return subprocess.CompletedProcess(args, rc)
            config = local_path('/root/cc-pool-worker.json')
            config.write_text('{}')
            with patch.object(worker, 'PAYLOAD', payload), patch.object(worker, 'CONFIG', config), \
                 patch.object(worker, 'CLAIMED', local_path('/etc/controlclaw/pool-claimed')), \
                 patch.object(worker, 'Path', local_path), patch.object(worker, 'report_progress'), \
                 patch.object(worker, 'validate', side_effect=lambda p, c: p['vars']), \
                 patch.object(worker, 'local', return_value=subprocess.CompletedProcess([], activate_rc)), \
                 patch.object(worker.subprocess, 'run', side_effect=run):
                worker.claim({'checkout': '/pinned/source'})
            return {name: local_path('/etc/controlclaw/' + name).exists()
                    for name in ['pool-activating', 'pool-failed', 'pool-claimed']}

    def test_activation_failed(self):
        self.assertEqual(self.claim(1, 0), {'pool-activating': False, 'pool-failed': True, 'pool-claimed': False})

    def test_completion_proof_failed(self):
        self.assertEqual(self.claim(0, 1), {'pool-activating': False, 'pool-failed': True, 'pool-claimed': False})

    def test_success(self):
        self.assertEqual(self.claim(0, 0), {'pool-activating': False, 'pool-failed': False, 'pool-claimed': True})


if __name__ == '__main__':
    unittest.main()
