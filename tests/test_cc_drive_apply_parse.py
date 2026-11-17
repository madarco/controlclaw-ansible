#!/usr/bin/env python3
"""roles/controlclaw/files/cc-drive-apply: its parse of drive.json, which the box user can write (T-oc114).

Run from the repo root: python3 -m unittest tests/test_cc_drive_apply_parse.py
"""
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'roles/controlclaw/files/cc-drive-apply'
PARSE = re.search(r'''python3 -I - "\$DESIRED" [^\n]*<<'PY'\n(.*?)\nPY\n''', SCRIPT.read_text(), re.S).group(1)
GOOD = {'placeholder': 'CC-DRIVE-0123456789abcdef', 'connected': True,
        'mounts': [{'name': 'Team Docs', 'folderId': 'AAAAAAAAAAAA', 'mode': 'rw'}]}


class Parse(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def parse(self, desired):
        path = self.dir / 'drive.json'
        if isinstance(desired, (dict, list)):
            path.write_text(json.dumps(desired))
        return subprocess.run(['python3', '-I', '-c', PARSE, str(path)], capture_output=True, text=True, timeout=20)

    def test_a_good_set(self):
        r = self.parse(GOOD)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('SCOPE\thttps://www.googleapis.com/auth/drive\n', r.stdout)
        self.assertIn('MOUNT\tTeam Docs\tAAAAAAAAAAAA\trw\tTeam_Docs_', r.stdout)

    def test_a_newline_in_the_scope_cannot_add_a_mount(self):
        evil = {**GOOD, 'scope': 'https://www.googleapis.com/auth/drive\nMOUNT\tok\tAAAAAAAAAAAA\trw\t../../../../usr/local/bin'}
        r = self.parse(evil)
        self.assertEqual(r.returncode, 1)
        self.assertIn('scope', r.stderr)

    def test_more_than_eight_mounts(self):
        many = {**GOOD, 'mounts': [{'name': f'F{i}', 'folderId': 'A' * 12 + str(i), 'mode': 'ro'} for i in range(9)]}
        self.assertIn('more than 8', self.parse(many).stderr)
        self.assertEqual(self.parse({**GOOD, 'mounts': many['mounts'][:8]}).returncode, 0)

    def test_not_an_object_a_link_or_a_fifo(self):
        self.assertEqual(self.parse([]).returncode, 1)
        (self.dir / 'real.json').write_text(json.dumps(GOOD))
        (self.dir / 'drive.json').unlink()
        (self.dir / 'drive.json').symlink_to(self.dir / 'real.json')
        self.assertEqual(self.parse(None).returncode, 1, 'not through a link')
        (self.dir / 'drive.json').unlink()
        os.mkfifo(self.dir / 'drive.json')
        self.assertEqual(self.parse(None).returncode, 1, 'a FIFO does not block')

    def test_bad_fields(self):
        for mount in ({'name': '../x', 'folderId': 'AAAAAAAAAAAA'}, {'name': 'x', 'folderId': 'A\tB' * 6},
                      {'name': 'x', 'folderId': 'AAAAAAAAAAAA', 'mode': 'rwx'}):
            with self.subTest(mount=mount):
                self.assertEqual(self.parse({**GOOD, 'mounts': [mount]}).returncode, 1)


if __name__ == '__main__':
    unittest.main()
