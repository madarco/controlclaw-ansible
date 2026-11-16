"""scripts/release.sh and the version reader in roles/controlclaw/tasks/release.yml."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]


def git(cwd, *args):
    return subprocess.run(['git', *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def version_reader():
    tasks = yaml.safe_load((ROOT / 'roles/controlclaw/tasks/release.yml').read_text())
    task = next(t for t in tasks[0]['block'] if t['name'] == 'Read the version this checkout is on')
    return task['ansible.builtin.command']['argv'][2]


class ReleaseTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        (self.dir / 'scripts').mkdir()
        shutil.copy(ROOT / 'scripts/release.sh', self.dir / 'scripts/release.sh')
        shutil.copy(ROOT / 'releases.json', self.dir / 'releases.json')
        (self.dir / 'playbooks').mkdir()
        (self.dir / 'playbooks/install.yml').write_text('---\n')
        git(self.dir, 'init', '-q')
        git(self.dir, '-c', 'user.name=t', '-c', 'user.email=t@t', 'add', '.')
        git(self.dir, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'base')

    def release(self, *args):
        env = {**os.environ, 'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@t', 'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@t'}
        return subprocess.run(['scripts/release.sh', *args], cwd=self.dir, env=env, capture_output=True, text=True)

    def releases(self):
        return json.loads((self.dir / 'releases.json').read_text())

    def test_adds_entry_commits_and_tags(self):
        r = self.release('1.1.0', 'Phone calls connect faster.', 'Fixed a typo.')
        self.assertEqual(r.returncode, 0, r.stderr)
        top = self.releases()[0]
        self.assertEqual(top['version'], '1.1.0')
        self.assertEqual(top['changes'], ['Phone calls connect faster.', 'Fixed a typo.'])
        self.assertNotIn('commit', top)
        self.assertEqual(self.releases()[1]['version'], '1.0.0')
        self.assertEqual(git(self.dir, 'rev-parse', 'v1.1.0^{commit}'), git(self.dir, 'rev-parse', 'HEAD'))
        self.assertEqual(git(self.dir, 'log', '-1', '--format=%s'), 'Release v1.1.0')

    def test_refuses_older_or_equal_versions(self):
        for v in ('1.0.0', '0.9.9'):
            r = self.release(v, 'x')
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('not newer', r.stderr)
        self.assertEqual(len(self.releases()), 1)

    def test_refuses_bad_input(self):
        self.assertNotEqual(self.release('1.1', 'x').returncode, 0)
        self.assertNotEqual(self.release('v1.1.0', 'x').returncode, 0)
        self.assertNotEqual(self.release('1.1.0', ' ').returncode, 0)
        (self.dir / 'releases.json').write_text('[]\n')
        self.assertIn('uncommitted', self.release('1.1.0', 'x').stderr)

    def with_openclaw(self, auto='false', record=None, pin='2026.11.3'):
        """The role's defaults and, when given, the upgrade test record, committed."""
        d = self.dir / 'roles/controlclaw/defaults'
        d.mkdir(parents=True, exist_ok=True)
        (d / 'main.yml').write_text(f'openclaw_version: "{pin}"\nopenclaw_auto_patch: {auto}\n')
        if record is not None:
            git(self.dir, 'add', 'roles')
            roles = git(self.dir, 'rev-parse', git(self.dir, 'write-tree') + ':roles')
            record = [{'roles_tree': roles, **r} for r in record]
            (self.dir / 'openclaw-upgrade-tests').mkdir(exist_ok=True)
            (self.dir / f'openclaw-upgrade-tests/{pin}.json').write_text(json.dumps(record))
        git(self.dir, '-c', 'user.name=t', '-c', 'user.email=t@t', 'add', '.')
        git(self.dir, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'openclaw')

    PASSED = [{'path': '2026.9.37@v1.46.0', 'pass': True, 'after': '2026.11.3'},
              {'path': '2026.11.3@v1.47.0', 'pass': True, 'after': '2026.11.3'}]

    def test_openclaw_tested_release(self):
        self.with_openclaw(record=self.PASSED)
        r = self.release('99.0.0', 'x')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('upgrade tested from 2026.9.37@v1.46.0, 2026.11.3@v1.47.0', r.stdout)

    def test_refuses_auto_patch(self):
        self.with_openclaw(auto='true', record=self.PASSED)
        r = self.release('99.0.0', 'x')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('openclaw_auto_patch is on', r.stderr)
        self.assertEqual(git(self.dir, 'tag'), '')

    def test_refuses_untested_openclaw(self):
        self.with_openclaw()
        r = self.release('99.0.0', 'x')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('no upgrade test for OpenClaw 2026.11.3', r.stderr)

    def test_refuses_failed_or_other_version_upgrade_test(self):
        for record in ([{**self.PASSED[0], 'pass': False}, self.PASSED[1]],
                       [{**self.PASSED[0], 'after': '2026.11.4'}],
                       []):
            with self.subTest(record=record):
                self.with_openclaw(record=record)
                r = self.release('99.0.0', 'x')
                self.assertNotEqual(r.returncode, 0)
                self.assertIn('did not pass to 2026.11.3', r.stderr)

    def test_refuses_a_test_of_other_roles(self):
        self.with_openclaw(record=[{**self.PASSED[0], 'roles_tree': 'f' * 40}])
        r = self.release('99.0.0', 'x')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('other roles than this commit', r.stderr)

    def test_refuses_a_rust_pin_without_controlclaw_agents(self):
        role = self.dir / 'roles/controlclaw'
        (role / 'files/cc-instructions-plugin').mkdir(parents=True)
        (role / 'files/cc-instructions-plugin/index.js').write_text('')
        (role / 'vars').mkdir(parents=True)
        for version, ok in (('1.8.0', False), ('1.9.0', True)):
            with self.subTest(version=version):
                (role / 'vars/rust_release.yml').write_text(f'cc_rust_release:\n  version: "{version}"\n')
                self.with_openclaw(record=self.PASSED)
                r = self.release('99.0.0', 'x')
                self.assertEqual(r.returncode == 0, ok, r.stderr)
                if not ok:
                    self.assertIn("do not write ControlClaw's instructions", r.stderr)

    def test_version_reader(self):
        def read():
            return subprocess.run(['python3', '-c', version_reader(), str(self.dir / 'playbooks')], capture_output=True, text=True, check=True).stdout.strip()

        self.assertEqual(read(), '1.0.0')
        (self.dir / 'releases.json').write_text('[{"version": "2.0"}]')
        self.assertEqual(read(), '')
        (self.dir / 'releases.json').write_text('not json')
        self.assertEqual(read(), '')
        (self.dir / 'releases.json').unlink()
        self.assertEqual(read(), '')


if __name__ == '__main__':
    unittest.main()
