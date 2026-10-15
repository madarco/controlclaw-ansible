import re
"""Pinned runtime patches must be atomic, idempotent and refuse unknown upstream code."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('patch', ROOT / 'roles/controlclaw/files/meeting-runtime-patch.py')
patcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patcher)

class MeetingPins(unittest.TestCase):
    def test_unknown_build_refused_without_modification(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for p in patcher.PATCHES:
                file = root / p['kind'] / p['path']
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('unknown upstream build')
            with self.assertRaises(RuntimeError):
                patcher.patch(root / 'host', root / 'plugin')
            for p in patcher.PATCHES:
                self.assertEqual((root / p['kind'] / p['path']).read_text(), 'unknown upstream build')

    def test_pinned_archive(self):
        upstream = Path(os.environ.get('MEET_UPSTREAM', '/tmp/meet-upstream'))
        if not upstream.exists():
            self.skipTest('download the documented pinned npm archives for this integration test')
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for p in patcher.PATCHES:
                source = upstream / ('host/package' if p['kind'] == 'host' else 'package') / p['path']
                target = root / p['kind'] / p['path']
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            patcher.patch(root / 'host', root / 'plugin')
            patcher.patch(root / 'host', root / 'plugin')
            for p in patcher.PATCHES:
                self.assertEqual(patcher.hashlib.sha256((root / p['kind'] / p['path']).read_bytes()).hexdigest(), p['after'])

    def test_prior_patch_versions_upgrade_to_the_current_pin(self):
        upstream = Path(os.environ.get('MEET_UPSTREAM', '/tmp/meet-upstream'))
        if not upstream.exists():
            self.skipTest('download the documented pinned npm archives for this integration test')
        for target_spec in (p for p in patcher.PATCHES if p.get('upgrades')):
            source = (upstream / ('host/package' if target_spec['kind'] == 'host' else 'package') / target_spec['path']).read_text()
            versions = {patcher.hashlib.sha256(source.encode()).hexdigest(): source}
            for old, new, count in target_spec['replacements']:
                source = source.replace(old, new)
                versions[patcher.hashlib.sha256(source.encode()).hexdigest()] = source
            for digest in target_spec['upgrades']:
                with self.subTest(digest=digest), tempfile.TemporaryDirectory() as d:
                    self.assertIn(digest, versions)
                    root = Path(d)
                    for spec in patcher.PATCHES:
                        original = upstream / ('host/package' if spec['kind'] == 'host' else 'package') / spec['path']
                        target = root / spec['kind'] / spec['path']
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(original, target)
                    (root / target_spec['kind'] / target_spec['path']).write_text(versions[digest])
                    patcher.patch(root / 'host', root / 'plugin')
                    self.assertEqual(patcher.hashlib.sha256((root / target_spec['kind'] / target_spec['path']).read_bytes()).hexdigest(), target_spec['after'])

    def test_patched_host_of_another_month_build_upgrades(self):
        """An agent on a later 2026.9.x build (other bundle hashes, the same code) that carries the
        previous release's patch gets only the replacements added since (HOST_UPGRADES)."""
        upstream = Path(os.environ.get('MEET_UPSTREAM', '/tmp/meet-upstream'))
        later = os.environ.get('MEET_UPSTREAM_LATER')
        if not upstream.exists() or not later:
            self.skipTest('set MEET_UPSTREAM_LATER to an extracted later 2026.9.x OpenClaw package')
        for spec in (p for p in patcher.PATCHES if p['kind'] == 'host' and p['path'] in patcher.HOST_UPGRADES):
            with self.subTest(path=spec['path']), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                for other in patcher.PATCHES:
                    base = Path(later) if other['kind'] == 'host' else upstream / 'package'
                    source = base / other['path']
                    if other['kind'] == 'host' and not source.exists():
                        source = next(source.parent.glob(re.sub(r'-[A-Za-z0-9_-]{8}(?=\.mjs$)', '-????????', source.name)))
                    target = root / other['kind'] / other['path']
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, target)
                # The runtime modules the patch imports, as the installed package has them.
                for module in (Path(later) / 'dist').glob('*.mjs'):
                    link = root / 'host' / 'dist' / module.name
                    if not link.exists():
                        link.symlink_to(module)
                # The previous release's patch: the replacements before the ones it was upgraded with.
                target = root / 'host' / spec['path']
                text = target.read_text()
                previous = spec['replacements'][:len(spec['replacements']) - len(spec['upgrades'][spec['previousAfter']])]
                for old, new, count in previous:
                    text = text.replace(patcher.host_imports(old, root / 'host'), patcher.host_imports(new, root / 'host'))
                self.assertEqual(patcher.host_digest(text), patcher.HOST_UPGRADES[spec['path']])
                target.write_text(text)
                self.assertEqual(patcher.check(root / 'host', root / 'plugin')['files'][patcher.PATCHES.index(spec)]['status'], 'unpatched')
                patcher.patch(root / 'host', root / 'plugin')
                self.assertEqual(patcher.host_digest(target.read_text()), patcher.HOST_DIGESTS[spec['path']][1])
                patcher.patch(root / 'host', root / 'plugin')
                self.assertEqual(patcher.check(root / 'host', root / 'plugin')['files'][patcher.PATCHES.index(spec)]['status'], 'patched')

if __name__ == '__main__': unittest.main()
