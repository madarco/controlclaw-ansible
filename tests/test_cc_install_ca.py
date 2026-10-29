#!/usr/bin/env python3
"""cc-install-ca must not wait for Caddy to restart (the control plane's CA refresh, "fetch failed").

The vm-agent runs cc-install-ca from POST /mitm-ca/refresh, a request that came in through Caddy. A
blocking `systemctl try-restart caddy.service` waits for Caddy to stop, and Caddy waits for that
request, so the reply never went out. The script is rendered from openclaw-egress.yml and run with
fake system commands; the fake systemctl hangs on a blocking Caddy restart, as the real one does.

Run from the repo root: python3 -m unittest tests/test_cc_install_ca.py
"""
import os
import pathlib
import signal
import subprocess
import tempfile
import unittest

import jinja2
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
TASKS = yaml.safe_load((ROOT / 'roles/controlclaw/tasks/openclaw-egress.yml').read_text())
TEMPLATE = next(t for t in TASKS if t.get('name', '').startswith('Deploy cc-install-ca'))['ansible.builtin.copy']['content']

# Logs every call; a Caddy restart without --no-block blocks until the test gives up, like the real
# one does while Caddy is still serving the request that ran this script.
FAKE_SYSTEMCTL = """#!/bin/sh
echo "$*" >> "$CALLS"
case " $* " in
  *" caddy.service "*) case " $* " in *" --no-block "*) ;; *) sleep 30 ;; esac ;;
esac
exit 0
"""
FAKE_OK = '#!/bin/sh\nexit 0\n'


def run(box_role):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        bin_dir = tmp / 'bin'
        bin_dir.mkdir()
        (bin_dir / 'systemctl').write_text(FAKE_SYSTEMCTL)
        for name in ('install', 'update-ca-certificates', 'su', 'certutil'):
            (bin_dir / name).write_text(FAKE_OK)
        for f in bin_dir.iterdir():
            f.chmod(0o755)
        (tmp / 'etc/systemd/system').mkdir(parents=True)
        (tmp / 'etc/profile.d').mkdir(parents=True)
        script = jinja2.Template(TEMPLATE).render(
            box_role=box_role,
            mitm_ca_path='/usr/local/share/ca-certificates/controlclaw-mitm.crt',
            controlclaw_user='controlclaw',
            controlclaw_home='/home/controlclaw',
        ).replace('/etc/', f'{tmp}/etc/')
        calls = tmp / 'calls'
        env = {**os.environ, 'PATH': f'{bin_dir}:{os.environ["PATH"]}', 'CALLS': str(calls)}
        proc = subprocess.Popen(['sh', '-c', script], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, start_new_session=True)
        try:
            _, stderr = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            raise AssertionError('cc-install-ca waited for Caddy to restart: the refresh reply would never go out')
        return proc.returncode, stderr, calls.read_text().splitlines()


class InstallCa(unittest.TestCase):
    def test_the_script_returns_without_waiting_for_caddy(self):
        for role in ('openclaw', 'gbrain'):
            with self.subTest(role=role):
                code, stderr, calls = run(role)
                self.assertEqual(code, 0, stderr)
                caddy = [c for c in calls if 'caddy.service' in c.split()]
                self.assertEqual(caddy, ['try-restart --no-block caddy.service'])
                # Last: the stop starts as soon as it is queued, so nothing slow may follow it while
                # the request that ran this script is still open.
                self.assertEqual(calls[-1], 'try-restart --no-block caddy.service')

    def test_openclaw_and_the_browser_are_still_restarted(self):
        _, _, calls = run('openclaw')
        self.assertIn('daemon-reload', calls)
        self.assertIn('try-restart openclaw.service', calls)
        self.assertIn('try-restart browser-stream.service', calls)

    def test_gbrain_is_still_restarted(self):
        _, _, calls = run('gbrain')
        self.assertIn('try-restart gbrain.service', calls)


if __name__ == '__main__':
    unittest.main()
