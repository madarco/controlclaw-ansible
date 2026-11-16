#!/usr/bin/env python3
"""roles/controlclaw/files/cc-openclaw-migrate, with doctor, systemctl and the mount table stood in (T-oc114).

Run from the repo root: python3 -m unittest tests/test_cc_openclaw_migrate.py
"""
import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'roles/controlclaw/files/cc-openclaw-migrate'

# What a doctor that migrates does to the databases: their schema version.
MIGRATE = "python3 -c \"import sqlite3,glob,sys; [sqlite3.connect(p).execute('pragma user_version = %d' % v) for p, v in [(p, 27) for p in glob.glob(sys.argv[1] + '/.openclaw/agents/*/agent/openclaw-agent.sqlite')] + [(sys.argv[1] + '/.openclaw/state/openclaw.sqlite', 22)]]\" \"$HOME_DIR\""


def database(path, version):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute('create table t (x)')
    con.execute(f'pragma user_version = {version}')
    con.commit()
    con.close()


def version(path):
    return sqlite3.connect(path).execute('pragma user_version').fetchone()[0]


class Migrate(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.home = self.tmp / 'home'
        state = self.home / '.openclaw'
        database(state / 'agents/main/agent/openclaw-agent.sqlite', 24)
        database(state / 'state/openclaw.sqlite', 19)
        # A leftover agent the config does not name: the gateway skips it, so does the verdict.
        database(state / 'agents/openclaw/agent/openclaw-agent.sqlite', 24)
        (state / 'openclaw.json').write_text(json.dumps({'agents': {'entries': {'main': {'name': 'main'}}}}))
        build = self.tmp / 'openclaw/dist'
        build.mkdir(parents=True)
        (build / 'contract.mjs').write_text('const OPENCLAW_AGENT_SCHEMA_VERSION = 27;\nconst OPENCLAW_STATE_SCHEMA_VERSION = 22;\n')
        self.calls = self.tmp / 'systemctl.calls'
        systemctl = self.tmp / 'systemctl'
        systemctl.write_text('#!/bin/sh\necho "$*" >> "%s"\n' % self.calls)
        systemctl.chmod(0o755)
        self.mountinfo = self.tmp / 'mountinfo'
        self.mountinfo.write_text('22 1 0:21 / / rw - ext4 /dev/sda1 rw\n')
        self.state_file = self.tmp / 'update.json'
        self.env = {**os.environ, 'HOME_DIR': str(self.home), 'CC_OPENCLAW_DIR': str(self.tmp / 'openclaw'),
                    'CC_UPDATE_STATE': str(self.state_file), 'CC_MITM_CA': str(self.tmp / 'none'),
                    'CC_MIGRATE_LOG': str(self.tmp / 'migrate.log'), 'CC_SYSTEMCTL': str(systemctl),
                    'CC_MOUNTINFO': str(self.mountinfo),
                    'CC_MIGRATE_EVERY_S': '1'}

    def run_it(self, doctor, *args, **env):
        r = subprocess.run(['python3', str(SCRIPT), *args, str(self.home)], env={**self.env, 'CC_MIGRATE_DOCTOR': doctor, **env},
                           capture_output=True, text=True, timeout=120)
        return r.returncode, json.loads(r.stdout.strip().splitlines()[-1]) if r.stdout.strip() else None

    def systemctl_calls(self):
        return self.calls.read_text().splitlines() if self.calls.exists() else []

    def test_a_migration_that_worked_is_0_even_when_doctor_exits_1(self):
        code, out = self.run_it(MIGRATE + '; exit 1')
        self.assertEqual(code, 0, out)
        self.assertEqual(out['doctor_exit'], 1)
        self.assertEqual(out['pending'], [])
        self.assertEqual([p['version'] for p in out['pending_before']], [24, 19])
        self.assertEqual(version(self.home / '.openclaw/agents/main/agent/openclaw-agent.sqlite'), 27)

    def test_a_database_still_behind_is_3(self):
        code, out = self.run_it('exit 0')
        self.assertEqual(code, 3)
        self.assertEqual({Path(p['path']).name for p in out['pending']}, {'openclaw-agent.sqlite', 'openclaw.sqlite'})
        self.assertNotIn('agents/openclaw/', json.dumps(out['pending']))

    def test_the_gateway_is_held_stopped_for_the_run(self):
        marker = self.tmp / 'during'
        self.run_it(f'cat {self.calls} > {marker}; ' + MIGRATE)
        during = marker.read_text().splitlines()
        self.assertEqual(during, ['stop openclaw', 'mask --runtime openclaw'])
        self.assertEqual(self.systemctl_calls()[-1], 'unmask --runtime openclaw')

    def test_the_ceiling_stops_doctor_and_unmasks_the_gateway(self):
        code, out = self.run_it('sleep 30', CC_MIGRATE_LIMIT_S='2')
        self.assertEqual(code, 4)
        self.assertTrue(out['timed_out'])
        self.assertEqual(self.systemctl_calls()[-1], 'unmask --runtime openclaw')

    def test_doctor_is_not_run_with_a_network_mount_left_under_the_state_folder(self):
        point = self.home / '.openclaw/workspace/Drive/Team'
        point.mkdir(parents=True)
        self.mountinfo.write_text(f'22 1 0:21 / / rw - ext4 /dev/sda1 rw\n90 22 0:50 / {point} rw,nosuid - fuse.rclone Team: rw\n')
        ran = self.tmp / 'ran'
        code, out = self.run_it(f'touch {ran}')
        self.assertEqual(code, 5)
        self.assertEqual(out['network_mounts'], [str(point)])
        self.assertFalse(ran.exists())
        self.assertEqual(self.systemctl_calls(), [], 'nothing stopped or masked when doctor does not run')

    def test_a_network_mount_with_nothing_to_migrate_is_not_a_failure(self):
        for db, v in (('agents/main/agent/openclaw-agent.sqlite', 27), ('state/openclaw.sqlite', 22)):
            sqlite3.connect(self.home / '.openclaw' / db).execute(f'pragma user_version = {v}').connection.commit()
        point = self.home / '.openclaw/workspace/Drive/Team'
        point.mkdir(parents=True)
        self.mountinfo.write_text(f'90 22 0:50 / {point} rw - fuse.rclone Team: rw\n')
        code, out = self.run_it('exit 1', '--gateway')
        self.assertEqual(code, 0)
        self.assertEqual(out['pending'], [])
        self.assertEqual(self.systemctl_calls(), ['start openclaw'])

    def test_progress_reaches_a_running_update(self):
        self.state_file.write_text(json.dumps({'phase': 'running', 'detail': 'ansible-pull abc', 'ref': 'abc', 'at': '2026-01-01T00:00:00Z'}))
        self.run_it('sleep 3; ' + MIGRATE)
        state = json.loads(self.state_file.read_text())
        self.assertEqual(state['phase'], 'running')
        self.assertIn("Moving the agent's conversations", state['detail'])
        self.assertNotEqual(state['at'], '2026-01-01T00:00:00Z')
        self.assertEqual(state['ref'], 'abc')

    def test_a_finished_update_is_not_touched(self):
        done = {'phase': 'done', 'detail': 'updated', 'ref': 'abc', 'at': '2026-01-01T00:00:00Z'}
        self.state_file.write_text(json.dumps(done))
        self.run_it('sleep 3; ' + MIGRATE)
        self.assertEqual(json.loads(self.state_file.read_text()), done)

    def test_gateway_is_started_only_when_every_database_is_current(self):
        self.run_it('exit 0', '--gateway')
        calls = self.systemctl_calls()
        self.assertEqual(calls[:2], ['stop openclaw', 'mask --runtime openclaw'])
        self.assertNotIn('start openclaw', calls)
        self.calls.unlink()
        self.run_it(MIGRATE, '--gateway')
        self.assertEqual(self.systemctl_calls()[-2:], ['enable openclaw', 'start openclaw'])


if __name__ == '__main__':
    unittest.main()
