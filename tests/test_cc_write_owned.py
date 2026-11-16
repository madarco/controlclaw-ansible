#!/usr/bin/env python3
"""roles/controlclaw/files/cc-write-owned: a file written in a folder, never through a link (T-oc114).

Run from the repo root: python3 -m unittest tests/test_cc_write_owned.py
(As a normal user: the root case, taking the folder owner's identity, is checked on a box.)
"""
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'roles/controlclaw/files/cc-write-owned'


def write(path, text):
    return subprocess.run([str(SCRIPT), str(path)], input=text.encode(), capture_output=True)


class WriteOwned(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / 'state').mkdir()
        (self.dir / 'elsewhere').mkdir()

    def test_writes_the_file_world_readable(self):
        self.assertEqual(write(self.dir / 'state/update.json', '{"phase":"done"}').returncode, 0)
        self.assertEqual((self.dir / 'state/update.json').read_text(), '{"phase":"done"}')
        self.assertEqual((self.dir / 'state/update.json').stat().st_mode & 0o777, 0o644)
        self.assertEqual(sorted(p.name for p in (self.dir / 'state').iterdir()), ['update.json'], 'no temporary file left')

    def test_a_link_at_the_files_name_is_replaced_not_written_through(self):
        victim = self.dir / 'elsewhere/victim'
        victim.write_text('keep')
        (self.dir / 'state/update.json').symlink_to(victim)
        self.assertEqual(write(self.dir / 'state/update.json', 'new').returncode, 0)
        self.assertEqual(victim.read_text(), 'keep')
        self.assertFalse((self.dir / 'state/update.json').is_symlink())

    def test_a_link_in_place_of_the_folder_is_refused(self):
        (self.dir / 'link').symlink_to(self.dir / 'elsewhere')
        r = write(self.dir / 'link/update.json', 'new')
        self.assertEqual(r.returncode, 1)
        self.assertEqual(list((self.dir / 'elsewhere').iterdir()), [])


if __name__ == '__main__':
    unittest.main()
