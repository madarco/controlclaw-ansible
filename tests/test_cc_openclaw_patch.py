"""cc-openclaw-patch: only a patch the Meet step knows is installed (controlclaw docs/ops/t-openclaw-autopatch.md).

The archive tests need the npm archives of OpenClaw 2026.9.7, 2026.9.34 and 2026.9.35 in a folder
named by CC_OPENCLAW_ARCHIVES (openclaw-<version>.tgz each, 114 MB); without it they are skipped:

  mkdir -p /tmp/oc && for v in 2026.9.7 2026.9.34 2026.9.35; do
    curl -fsSLo /tmp/oc/openclaw-$v.tgz https://registry.npmjs.org/openclaw/-/openclaw-$v.tgz; done
  CC_OPENCLAW_ARCHIVES=/tmp/oc python3 -m unittest tests/test_cc_openclaw_patch.py
"""
import base64
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / 'roles/controlclaw/files'
loader = importlib.machinery.SourceFileLoader('cc_openclaw_patch', str(FILES / 'cc-openclaw-patch'))
spec = importlib.util.spec_from_loader('cc_openclaw_patch', loader)
resolver = importlib.util.module_from_spec(spec)
loader.exec_module(resolver)
CHECKER = str(FILES / 'meeting-runtime-patch.py')
ARCHIVES = os.environ.get('CC_OPENCLAW_ARCHIVES')
PIN = '2026.9.7'


def integrity(data):
    return 'sha512-' + base64.b64encode(hashlib.sha512(data).digest()).decode()


class Registry:
    """A registry of fake archives: version -> bytes; `known` is what the fake Meet check accepts."""

    def __init__(self, archives, known):
        self.archives, self.known, self.downloads = archives, set(known), []

    def versions(self):
        return {v: {'dist': {'integrity': integrity(data)}} for v, data in self.archives.items()}

    def get(self, version, digest, destination):
        data = self.archives[version]
        assert hashlib.sha512(data).hexdigest() == digest
        self.downloads.append(version)
        Path(destination).write_bytes(data)

    def knows(self, archive, checker):
        version = Path(archive).read_bytes().decode()
        return (version in self.known, '' if version in self.known else 'Unexpected Meet runtime code: x')


class ResolveTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.dest = os.path.join(self.dir, 'openclaw-pinned.tgz')
        versions = ['2026.9.7', '2026.9.8', '2026.9.34', '2026.9.35', '2026.9.36', '2026.10.1', '2026.9.37-beta.1']
        self.registry = Registry({v: v.encode() for v in versions}, known=['2026.9.7', '2026.9.8', '2026.9.34', '2026.9.35'])

    def tearDown(self):
        shutil.rmtree(self.dir)

    def resolve(self, installed, refused=(), auto=True, floor='', fetch=None, knows=None):
        return resolver.resolve(PIN, hashlib.sha512(b'2026.9.7').hexdigest(), installed, auto, self.dest, CHECKER, refused,
                                fetch=fetch or self.registry.versions, get=self.registry.get, knows=knows or self.registry.knows, floor=floor)

    def test_a_box_without_its_build_is_put_back_at_its_version_or_newer_never_the_pin(self):
        # Half installed (no dist/index.js: installed reads empty), it last ran 9.35, nothing newer known.
        self.assertEqual(self.resolve('', floor='2026.9.35')[0], '2026.9.35')
        self.assertEqual(Path(self.dest).read_bytes(), b'2026.9.35')
        # A newer known patch is fine too.
        self.registry.known.add('2026.9.36')
        self.assertEqual(self.resolve('', floor='2026.9.35')[0], '2026.9.36')

    def test_an_install_older_than_its_config_is_lifted_to_it(self):
        # 9.34 installed, the config stamped by 9.35: 9.34 would refuse to start.
        self.assertEqual(self.resolve('2026.9.34', floor='2026.9.35')[0], '2026.9.35')

    def test_auto_patch_off_puts_a_broken_box_back_at_its_own_version(self):
        self.assertEqual(self.resolve('', auto=False, floor='2026.9.35')[0], '2026.9.35')
        self.assertNotIn('2026.9.7', self.registry.downloads)

    def test_no_registry_and_no_build_never_installs_the_pin(self):
        def down():
            raise OSError('registry down')
        with self.assertRaises(OSError):
            self.resolve('', floor='2026.9.35', fetch=down)
        with self.assertRaises(OSError):
            self.resolve('', auto=False, floor='2026.9.35', fetch=down)
        self.assertEqual(self.registry.downloads, [])

    def test_an_odd_integrity_skips_that_patch_only(self):
        versions = self.registry.versions()
        versions['2026.9.36']['dist']['integrity'] = 'sha1-abc'
        version, skipped = self.resolve('2026.9.34', fetch=lambda: versions)
        self.assertEqual(version, '2026.9.35')
        self.assertEqual([(s['version'], s.get('transient')) for s in skipped], [('2026.9.36', True)])

    def test_a_check_that_crashes_on_one_patch_skips_it_unremembered_and_tries_older(self):
        def flaky(archive, checker):
            if Path(archive).read_bytes() == b'2026.9.36':
                raise RuntimeError('The Meet patch check failed: KeyError')
            return self.registry.knows(archive, checker)
        version, skipped = self.resolve('2026.9.34', knows=flaky)
        self.assertEqual(version, '2026.9.35')
        self.assertEqual([(s['version'], s.get('transient')) for s in skipped], [('2026.9.36', True)])
        self.assertFalse(os.path.exists(self.dest) and Path(self.dest).read_bytes() == b'2026.9.36')

    def test_the_newest_known_patch_is_installed_and_an_unknown_one_skipped(self):
        version, skipped = self.resolve('2026.9.34')
        self.assertEqual(version, '2026.9.35')
        self.assertEqual([s['version'] for s in skipped], ['2026.9.36'])
        self.assertEqual(Path(self.dest).read_bytes(), b'2026.9.35')
        # Another month and a prerelease are never candidates.
        self.assertNotIn('2026.10.1', self.registry.downloads)
        self.assertNotIn('2026.9.37-beta.1', self.registry.downloads)

    def test_nothing_newer_known_keeps_what_is_installed(self):
        version, skipped = self.resolve('2026.9.35')
        self.assertEqual(version, '2026.9.35')
        self.assertEqual([s['version'] for s in skipped], ['2026.9.36'])
        self.assertFalse(os.path.exists(self.dest))

    def test_a_box_already_on_an_unknown_patch_is_not_downgraded(self):
        version, skipped = self.resolve('2026.9.36')
        self.assertEqual((version, skipped), ('2026.9.36', []))
        self.assertEqual(self.registry.downloads, [])

    def test_a_new_box_gets_the_newest_known_patch(self):
        version, _ = self.resolve('')
        self.assertEqual(version, '2026.9.35')

    def test_a_box_below_the_pin_gets_a_known_patch_and_one_on_a_newer_month_keeps_it(self):
        self.assertEqual(self.resolve('2026.8.30')[0], '2026.9.35')
        # Never lower: the newer build stamped the config, and an older one refuses to start on it.
        self.assertEqual(self.resolve('2026.10.1'), ('2026.10.1', []))
        self.assertEqual(self.registry.downloads, ['2026.9.36', '2026.9.35'])

    def test_nothing_known_but_the_pin_installs_the_pin(self):
        self.registry.known = {'2026.9.7'}
        version, skipped = self.resolve('')
        self.assertEqual(version, '2026.9.7')
        self.assertEqual([s['version'] for s in skipped], ['2026.9.36', '2026.9.35', '2026.9.34', '2026.9.8'])

    def test_a_refusal_is_remembered_for_the_same_archive_and_meet_patch(self):
        _, skipped = self.resolve('2026.9.35')
        self.registry.downloads.clear()
        version, again = self.resolve('2026.9.35', refused=skipped)
        self.assertEqual(version, '2026.9.35')
        self.assertEqual(self.registry.downloads, [])
        self.assertEqual([s['version'] for s in again], ['2026.9.36'])
        # A new Meet patch is a new check.
        changed = [dict(s, checker='0' * 64) for s in skipped]
        self.resolve('2026.9.35', refused=changed)
        self.assertEqual(self.registry.downloads, ['2026.9.36'])

    def test_a_check_that_could_not_run_leaves_no_unchecked_archive(self):
        def broken(archive, checker):
            raise TimeoutError('the check took too long')
        version, skipped = resolver.resolve(PIN, hashlib.sha512(b'2026.9.7').hexdigest(), '2026.9.34', True, self.dest, CHECKER, (),
                                            fetch=self.registry.versions, get=self.registry.get, knows=broken)
        self.assertEqual(version, '2026.9.34')
        self.assertEqual([s['version'] for s in skipped], ['2026.9.36', '2026.9.35'])
        self.assertFalse(os.path.exists(self.dest))

    def test_auto_patch_off_installs_the_pin_but_never_downgrades(self):
        self.assertEqual(self.resolve('2026.9.34', auto=False)[0], '2026.9.34')
        self.assertEqual(self.resolve('', auto=False)[0], '2026.9.7')
        self.assertEqual(self.registry.downloads, ['2026.9.7'])


class CheckerTest(unittest.TestCase):
    def test_a_checker_that_crashes_is_not_a_refusal(self):
        d = tempfile.mkdtemp()
        try:
            archive = os.path.join(d, 'a.tgz')
            with tarfile.open(archive, 'w:gz') as tar:
                data = b'x'
                info = tarfile.TarInfo('package/dist/a.mjs')
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            crashing = os.path.join(d, 'checker.py')
            Path(crashing).write_text("import sys\nif sys.argv[1] == '--host-dirs': print('[\"dist\"]'); sys.exit(0)\nraise KeyError('bug')\n")
            with self.assertRaises(RuntimeError):
                resolver.meet_knows(archive, crashing)
            refusing = os.path.join(d, 'refusing.py')
            Path(refusing).write_text("import sys, json\nif sys.argv[1] == '--host-dirs': print('[\"dist\"]'); sys.exit(0)\nprint(json.dumps({'ok': False, 'reason': 'Unexpected Meet runtime code: ' + sys.argv[2] + '/dist/a.mjs'})); sys.exit(1)\n")
            ok, reason = resolver.meet_knows(archive, refusing)
            self.assertFalse(ok)
            self.assertEqual(reason, 'Unexpected Meet runtime code: package/dist/a.mjs')
        finally:
            shutil.rmtree(d)


@unittest.skipUnless(ARCHIVES, 'CC_OPENCLAW_ARCHIVES not set')
class ArchiveTest(unittest.TestCase):
    """The real Meet check on the real archives, and a fake 2026.9.36 with changed Meet code."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        cls.fake = os.path.join(cls.dir, 'openclaw-2026.9.36.tgz')
        with tarfile.open(os.path.join(ARCHIVES, 'openclaw-2026.9.35.tgz'), 'r:gz') as src, tarfile.open(cls.fake, 'w:gz') as out:
            for member in src.getmembers():
                data = src.extractfile(member).read() if member.isfile() else None
                if data is not None and re.search(r'package/dist/realtime-session-harness-[^/]+\.mjs$', member.name):
                    # One line of Meet code the patch was not reviewed against.
                    data = data.replace(b"createBridge(wrapCurrentPluginInstance(bridgeRequest))", b"createBridge(bridgeRequest)", 1)
                    assert b"createBridge(bridgeRequest)" in data
                    member.size = len(data)
                out.addfile(member, io.BytesIO(data) if data is not None else None)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir)

    def test_each_reviewed_archive_is_known(self):
        for version in ('2026.9.7', '2026.9.34', '2026.9.35'):
            with self.subTest(version=version):
                self.assertEqual(resolver.meet_knows(os.path.join(ARCHIVES, f'openclaw-{version}.tgz'), CHECKER), (True, ''))

    def test_changed_meet_code_is_refused(self):
        ok, reason = resolver.meet_knows(self.fake, CHECKER)
        self.assertFalse(ok)
        self.assertIn('Unexpected', reason)

    def test_a_build_without_what_the_install_check_imports_is_refused(self):
        fake = os.path.join(self.dir, 'openclaw-no-export.tgz')
        with tarfile.open(os.path.join(ARCHIVES, 'openclaw-2026.9.35.tgz'), 'r:gz') as src, tarfile.open(fake, 'w:gz') as out:
            for member in src.getmembers():
                data = src.extractfile(member).read() if member.isfile() else None
                if data is not None and re.search(r'package/dist/official-external-install-records-[^/]+\.mjs$', member.name):
                    data = data.replace(b'isTrustedOfficialPluginInstallRecord', b'isTrustedOfficialRecord')
                    member.size = len(data)
                out.addfile(member, io.BytesIO(data) if data is not None else None)
        ok, reason = resolver.meet_knows(fake, CHECKER)
        self.assertFalse(ok)
        self.assertIn('isTrustedOfficialPluginInstallRecord', reason)

    def test_the_fake_newer_patch_is_skipped_and_the_reviewed_one_installed(self):
        archives = {v: os.path.join(ARCHIVES, f'openclaw-{v}.tgz') for v in ('2026.9.7', '2026.9.34', '2026.9.35')}
        archives['2026.9.36'] = self.fake
        versions = {v: {'dist': {'integrity': integrity(Path(p).read_bytes())}} for v, p in archives.items()}
        dest = os.path.join(self.dir, 'openclaw-pinned.tgz')

        def get(version, digest, destination):
            shutil.copyfile(archives[version], destination)

        version, skipped = resolver.resolve(PIN, versions[PIN]['dist']['integrity'], '2026.9.34', True, dest, CHECKER,
                                            fetch=lambda: versions, get=get)
        self.assertEqual(version, '2026.9.35')
        self.assertEqual([s['version'] for s in skipped], ['2026.9.36'])
        self.assertTrue(os.path.exists(dest))


class MainTest(unittest.TestCase):
    def test_a_run_that_could_not_read_the_registry_keeps_what_the_last_one_found(self):
        d = tempfile.mkdtemp()
        try:
            state = os.path.join(d, 'openclaw-patch.json')
            refused = [{'version': '2026.9.36', 'reason': 'Unexpected Meet runtime code: x', 'digest': 'd', 'checker': resolver.file_sha256(CHECKER)},
                       # Refused by another Meet patch: not this one's to repeat.
                       {'version': '2026.9.37', 'reason': 'old', 'digest': 'd', 'checker': '0' * 64}]
            resolver.write_state(state, {'waiting': '2026.9.36', 'refused': refused})
            original, resolver.REGISTRY = resolver.REGISTRY, 'http://127.0.0.1:9'
            argv = sys.argv
            sys.argv = ['cc-openclaw-patch', PIN, '0' * 128, '2026.9.35', 'true', os.path.join(d, 'pinned.tgz'), CHECKER, state]
            out = io.StringIO()
            try:
                with contextlib.redirect_stdout(out):
                    resolver.main()
            finally:
                resolver.REGISTRY, sys.argv = original, argv
            self.assertEqual(json.loads(out.getvalue()), {'version': '2026.9.35', 'changed': False, 'fallback': True, 'skipped': [{'version': '2026.9.36', 'reason': 'Unexpected Meet runtime code: x'}]})
            kept = json.load(open(state))
            self.assertEqual((kept['waiting'], kept['refused']), ('2026.9.36', refused[:1]))
        finally:
            shutil.rmtree(d)

    def run_main(self, args):
        out, err = io.StringIO(), io.StringIO()
        argv = sys.argv
        sys.argv = ['cc-openclaw-patch', *args]
        original, resolver.REGISTRY = resolver.REGISTRY, 'http://127.0.0.1:9'
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    resolver.main()
                    code = 0
                except SystemExit as exit:
                    code = exit.code
        finally:
            resolver.REGISTRY, sys.argv = original, argv
        return code, out.getvalue(), err.getvalue()

    def test_registry_down_on_a_box_without_its_build_fails_instead_of_installing_the_pin(self):
        d = tempfile.mkdtemp()
        try:
            dest = os.path.join(d, 'pinned.tgz')
            for auto in ('true', 'false'):
                code, out, err = self.run_main([PIN, '0' * 128, '', auto, dest, CHECKER, os.path.join(d, 's.json'), '2026.9.35'])
                self.assertEqual(code, 1)
                self.assertIn('not installing an older one', err)
                self.assertFalse(os.path.exists(dest))
        finally:
            shutil.rmtree(d)

    def test_state_file_names_the_waiting_patch(self):
        d = tempfile.mkdtemp()
        try:
            state = os.path.join(d, 'state', 'openclaw-patch.json')
            resolver.write_state(state, {'waiting': '2026.9.36'})
            self.assertEqual(json.load(open(state))['waiting'], '2026.9.36')
            self.assertEqual(os.stat(state).st_mode & 0o777, 0o644)
        finally:
            shutil.rmtree(d)


if __name__ == '__main__':
    unittest.main()
