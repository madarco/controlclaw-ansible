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

if __name__ == '__main__': unittest.main()
