#!/usr/bin/env python3
"""`cc-secure discard` (T-diskspace): discards pass through the encryption to the image file, on the
open mapping and on every later open, the `discard` mount option goes, and the first run trims.

Run from the repo root: sudo python3 -m unittest tests/test_cc_secure_discard.py

The live test runs the shipped script against a real LUKS2 container in a sparse file on a loop
device, mounted the way boxes built before this change mount it (`-o discard`, opened without
allow-discards, as the partner's clevis unlock does). It needs root, cryptsetup and mkfs.ext4, and
skips without them.
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'roles/controlclaw/files/cc-secure'
CC_SECURE = SCRIPT.read_text()
TASKS = (ROOT / 'roles/controlclaw/tasks/disk-encryption.yml').read_text()


def sh(*args, check=True, **kw):
    return subprocess.run(args, capture_output=True, text=True, check=check, **kw)


class Text(unittest.TestCase):
    def test_the_weekly_trim_names_the_container(self):
        # fstrim.service reads /etc/fstab only, and the container is not in it.
        self.assertIn('ExecStart=-/sbin/fstrim --verbose {{ luks_secure_mount }}', TASKS)

    def test_nothing_mounts_the_container_with_the_discard_option(self):
        self.assertNotRegex(CC_SECURE, r'mount -o discard')

    def test_a_new_container_writes_the_flag_into_its_header(self):
        self.assertRegex(CC_SECURE, r'luksOpen --key-file "\$tmp" --allow-discards --persistent')

    def test_the_play_runs_it_and_an_error_does_not_stop_the_update(self):
        block = TASKS[TASKS.index('/usr/local/bin/cc-secure discard\n'):]
        block = block[:block.index('\n\n')]
        self.assertIn("changed_when: luks_discard.stdout == 'changed'", block)
        self.assertIn('failed_when: false', block)


@unittest.skipUnless(os.geteuid() == 0 and shutil.which('cryptsetup') and shutil.which('mkfs.ext4'),
                     'needs root, cryptsetup and mkfs.ext4')
class Live(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.img = self.dir / 'secure.img'
        self.mnt = self.dir / 'secure'
        self.mapper = f'cc-secure-test-{os.getpid()}'
        self.env = {**os.environ, 'CC_SECURE_IMG': str(self.img), 'CC_SECURE_MOUNT': str(self.mnt),
                    'CC_SECURE_MAPPER': self.mapper, 'CC_SECURE_LOCK_DIR': str(self.dir / 'lock')}
        key = self.dir / 'k'
        key.write_text('a test passphrase that is long enough')
        sh('truncate', '-s', '1G', str(self.img))
        self.loop = sh('losetup', '--find', '--show', '--sector-size', '4096', str(self.img)).stdout.strip()
        sh('cryptsetup', 'luksFormat', '--type', 'luks2', '--batch-mode', '--pbkdf-memory', '65536',
           '--key-file', str(key), self.loop)
        # As clevis opens it: no --allow-discards.
        sh('cryptsetup', 'open', '--key-file', str(key), self.loop, self.mapper)
        sh('mkfs.ext4', '-q', '-E', 'nodiscard', f'/dev/mapper/{self.mapper}')
        self.mnt.mkdir()
        sh('mount', '-o', 'discard', f'/dev/mapper/{self.mapper}', str(self.mnt))
        (self.mnt / 'keys').mkdir()
        shutil.copy(key, self.mnt / 'keys/luks.key')
        for i in range(3):
            sh('dd', 'if=/dev/urandom', f'of={self.mnt}/big{i}', 'bs=1M', 'count=100', 'status=none')
        sh('sync')
        for i in range(3):
            (self.mnt / f'big{i}').unlink()
        sh('sync')

    def tearDown(self):
        sh('umount', str(self.mnt), check=False)
        sh('cryptsetup', 'close', self.mapper, check=False)
        sh('losetup', '-d', self.loop, check=False)
        shutil.rmtree(self.dir, ignore_errors=True)

    def allocated(self):
        return os.stat(self.img).st_blocks * 512

    def run_discard(self):
        return sh('bash', str(SCRIPT), 'discard', env=self.env)

    def test_space_comes_back_and_every_later_open_allows_discards(self):
        before = self.allocated()
        self.assertGreater(before, 250 * 2 ** 20)
        r = self.run_discard()
        self.assertEqual(r.stdout.strip(), 'changed', r.stderr)
        self.assertLess(self.allocated(), 120 * 2 ** 20, r.stderr)
        self.assertRegex(sh('cryptsetup', 'status', self.mapper).stdout, r'flags:\s+discards')
        self.assertRegex(sh('cryptsetup', 'luksDump', self.loop).stdout, r'Flags:\s+allow-discards')
        opts = sh('findmnt', '-no', 'OPTIONS', str(self.mnt)).stdout.strip().split(',')
        self.assertNotIn('discard', opts)
        self.assertTrue((self.mnt / 'state/discard-trimmed').exists())

        # A second run changes nothing.
        self.assertEqual(self.run_discard().stdout.strip(), 'unchanged')

        # Space freed later comes back with a plain fstrim, as the weekly one runs it.
        sh('dd', 'if=/dev/urandom', f'of={self.mnt}/later', 'bs=1M', 'count=200', 'status=none')
        sh('sync')
        grown = self.allocated()
        (self.mnt / 'later').unlink()
        sh('sync')
        sh('fstrim', str(self.mnt))
        self.assertLess(self.allocated(), grown - 150 * 2 ** 20)

        # Closed and opened again with no flag, as clevis does: the header's flag applies.
        sh('umount', str(self.mnt))
        sh('cryptsetup', 'close', self.mapper)
        key = self.dir / 'k'
        sh('cryptsetup', 'open', '--key-file', str(key), self.loop, self.mapper)
        self.assertRegex(sh('cryptsetup', 'status', self.mapper).stdout, r'flags:\s+discards')

    def test_a_container_that_is_not_mounted_is_refused(self):
        sh('umount', str(self.mnt))
        r = sh('bash', str(SCRIPT), 'discard', env=self.env, check=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn('not mounted', r.stderr)


if __name__ == '__main__':
    unittest.main()
