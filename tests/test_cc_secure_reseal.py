#!/usr/bin/env python3
"""Re-sealing a box's disk passphrase to a new recovery key: what `cc-secure reseal` takes, that the
old seal stays until the new one is in place, and the sudoers pattern.

Run from the repo root: python3 -m unittest tests/test_cc_secure_reseal.py

`cmd_reseal` is cut out of the shipped script and run with the container's own parts (mounted, the
lock, a leftover bind) replaced: those need root and a loop device. The sealing is the shipped
`cc-seal`, which needs `node`; the tests that seal skip without it.
"""
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'roles/controlclaw/files/cc-secure'
CC_SEAL = ROOT / 'roles/controlclaw/files/cc-seal'
CC_SECURE = SCRIPT.read_text()
TASKS = (ROOT / 'roles/controlclaw/tasks/disk-encryption.yml').read_text()
SEAL_JS = CC_SEAL.read_text()
# The vector both implementations of the seal are pinned to.
VECTOR_SECRET = re.search(r'recoverySecretKey: "([^"]+)"', SEAL_JS).group(1)
VECTOR_PUBLIC = re.search(r'recoveryPublicKey: "([^"]+)"', SEAL_JS).group(1)
VECTOR_TAG = re.search(r'recoveryKeyTag: "([^"]+)"', SEAL_JS).group(1)
OTHER_PUBLIC = base64.b64encode(bytes(range(1, 33))).decode()


def tag_of(key):
    return 'sha256:' + hashlib.sha256(base64.b64decode(key)).digest()[:8].hex()


def shell_function(name):
    return re.search(r'^' + name + r'\(\) \{(?: [^\n]*\}\n|\n.*?^\}\n)', CC_SECURE, re.S | re.M).group(0)


def run_script(*args):
    e = {**os.environ, 'CC_SECURE_IMG': '/nonexistent/secure.img', 'CC_SECURE_MOUNT': '/nonexistent/secure'}
    return subprocess.run(['bash', str(SCRIPT), *args], capture_output=True, text=True, env=e)


class Box:
    """A folder standing in for a box: the keyfile, the sealed blob and the recorded key."""

    def __init__(self, test, mounted=True, seal=None):
        self.dir = Path(tempfile.mkdtemp())
        test.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.keyfile = self.dir / 'luks.key'
        self.keyfile.write_text('the-passphrase')
        self.blob = self.dir / 'etc' / 'luks-recovery.sealed'
        self.pub = self.dir / 'etc' / 'luks-recovery-pub.b64'
        self.blob.parent.mkdir()
        self.mounted = mounted
        self.seal = seal or str(CC_SEAL)

    def reseal(self, *args):
        script = '\n'.join([
            'set -u',
            'die() { echo "cc-secure: $*" >&2; exit 1; }',
            'log() { echo "cc-secure: $*" >&2; }',
            f'is_mounted() {{ {"true" if self.mounted else "false"}; }}',
            'take_lock() { echo locked >> "$TRACE"; }',
            'stop_leftover_bind() { :; }',
            'loopdev() { echo /dev/loop9; }',
            shell_function('recovery_key_tag'), shell_function('sealed_tag'), shell_function('cmd_reseal'),
            'cmd_reseal "$@"',
        ])
        env = {**os.environ, 'KEYFILE': str(self.keyfile), 'RECOVERY_JWE': str(self.blob), 'RECOVERY_PUB': str(self.pub),
               'CC_SEAL': self.seal, 'TRACE': str(self.dir / 'trace')}
        return subprocess.run(['bash', '-c', script, 'cc-secure', *args], capture_output=True, text=True, env=env)

    def sealed_before(self, key):
        """Seal to `key` the way a box did when it was made."""
        self.pub.write_text(key)
        subprocess.run(['node', str(CC_SEAL), str(self.pub), str(self.keyfile), str(self.blob)], check=True)
        return self.blob.read_text()


class Arguments(unittest.TestCase):
    def test_anything_but_one_key_is_refused_before_anything_is_read(self):
        k = VECTOR_PUBLIC
        for args in ([], [k, 'x'], [k[:-1]], [k + '='], [k[:-2] + '=='], ['-' + k[1:]], [k[:10] + ';' + k[11:]], [' ' + k], [k + '\n'], ['$(id)'], ['']):
            r = run_script('reseal', *args)
            self.assertEqual(r.returncode, 1, args)
            self.assertIn('usage: cc-secure reseal <recovery public key>', r.stderr, args)

    def test_a_good_key_gets_as_far_as_the_container(self):
        r = run_script('reseal', VECTOR_PUBLIC)
        self.assertEqual(r.returncode, 1)
        self.assertIn('the disk is not open', r.stderr)
        self.assertIn('nothing was changed', r.stderr)

    def test_the_key_is_never_read_from_the_file_the_play_wrote(self):
        body = shell_function('cmd_reseal')
        self.assertNotIn('seal_to_recovery', body)
        self.assertIn('"$CC_SEAL" "$pub" "$KEYFILE" "$new" >&2', body)


@unittest.skipUnless(shutil.which('node'), 'needs node')
class Reseal(unittest.TestCase):
    def test_a_locked_box_is_refused_and_keeps_its_seal(self):
        box = Box(self, mounted=False)
        before = box.sealed_before(OTHER_PUBLIC)
        r = box.reseal(VECTOR_PUBLIC)
        self.assertEqual(r.returncode, 1)
        self.assertIn('the disk is not open', r.stderr)
        self.assertEqual(box.blob.read_text(), before)
        self.assertEqual(box.pub.read_text(), OTHER_PUBLIC)
        self.assertFalse((box.dir / 'trace').exists(), 'took the lock for nothing')

    def test_it_seals_to_the_key_it_was_given_and_records_it(self):
        box = Box(self)
        box.sealed_before(OTHER_PUBLIC)
        r = box.reseal(VECTOR_PUBLIC)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), {'to': VECTOR_TAG, 'changed': True})
        blob = json.loads(box.blob.read_text())
        self.assertEqual(blob['to'], VECTOR_TAG)
        self.assertEqual(box.pub.read_text().strip(), VECTOR_PUBLIC)
        self.assertEqual(stat.S_IMODE(box.blob.stat().st_mode), 0o644)
        self.assertFalse(Path(str(box.blob) + '.new').exists())
        # And the owner's half opens it: the vector's secret key gives the passphrase back.
        opener = SEAL_JS.split('function selftest()')[0] + (
            'const b = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));'
            'process.stdout.write(open_(b, Buffer.from(process.argv[3], "base64")));')
        with tempfile.NamedTemporaryFile('w', suffix='.cjs') as f:
            f.write(opener.replace('#!/usr/bin/env node', ''))
            f.flush()
            out = subprocess.run(['node', f.name, str(box.blob), VECTOR_SECRET], capture_output=True, text=True)
        self.assertEqual(out.stdout, 'the-passphrase', out.stderr)

    def test_a_box_already_on_the_key_is_left_alone(self):
        box = Box(self)
        before = box.sealed_before(VECTOR_PUBLIC)
        r = box.reseal(VECTOR_PUBLIC)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), {'to': VECTOR_TAG, 'changed': False})
        self.assertEqual(box.blob.read_text(), before)

    def test_a_current_seal_with_the_wrong_recorded_key_gets_the_record_put_right(self):
        box = Box(self)
        before = box.sealed_before(VECTOR_PUBLIC)
        box.pub.write_text(OTHER_PUBLIC)
        r = box.reseal(VECTOR_PUBLIC)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(box.blob.read_text(), before)
        self.assertEqual(box.pub.read_text().strip(), VECTOR_PUBLIC)

    def test_a_seal_with_no_name_is_sealed_again(self):
        box = Box(self)
        box.sealed_before(VECTOR_PUBLIC)
        old = json.loads(box.blob.read_text())
        del old['to']
        box.blob.write_text(json.dumps(old))
        r = box.reseal(VECTOR_PUBLIC)
        self.assertEqual(json.loads(r.stdout), {'to': VECTOR_TAG, 'changed': True})

    def test_a_failed_seal_leaves_the_old_one(self):
        box = Box(self, seal='/bin/false')
        before = box.sealed_before(OTHER_PUBLIC)
        r = box.reseal(VECTOR_PUBLIC)
        self.assertEqual(r.returncode, 1)
        self.assertIn('the old one still opens this disk', r.stderr)
        self.assertEqual(box.blob.read_text(), before)
        self.assertEqual(box.pub.read_text(), OTHER_PUBLIC)
        self.assertEqual(r.stdout, '')

    def test_a_seal_that_names_another_key_is_thrown_away(self):
        box = Box(self)
        before = box.sealed_before(OTHER_PUBLIC)
        # A sealer that ignores the key it is handed and seals to the box's old one.
        liar = box.dir / 'liar'
        liar.write_text(f'#!/bin/sh\ncp "{box.blob}" "$3"\n')
        liar.chmod(0o755)
        box.seal = str(liar)
        r = box.reseal(VECTOR_PUBLIC)
        self.assertEqual(r.returncode, 1)
        self.assertIn('does not name the key it was given', r.stderr)
        self.assertEqual(box.blob.read_text(), before)
        self.assertFalse(Path(str(box.blob) + '.new').exists())

    @unittest.skipIf(os.geteuid() == 0, 'root writes into a read-only folder')
    def test_a_folder_that_cannot_be_written_leaves_the_old_seal(self):
        box = Box(self)
        before = box.sealed_before(OTHER_PUBLIC)
        box.blob.parent.chmod(0o555)
        self.addCleanup(box.blob.parent.chmod, 0o755)
        r = box.reseal(VECTOR_PUBLIC)
        self.assertEqual(r.returncode, 1)
        self.assertIn('the old one still opens this disk', r.stderr)
        self.assertEqual(box.blob.read_text(), before)

    def test_the_passphrase_never_leaves_the_keyfile(self):
        box = Box(self)
        box.sealed_before(OTHER_PUBLIC)
        r = box.reseal(VECTOR_PUBLIC)
        self.assertNotIn('the-passphrase', r.stdout + r.stderr)
        self.assertEqual(sorted(p.name for p in box.blob.parent.iterdir()), ['luks-recovery-pub.b64', 'luks-recovery.sealed'])


class Play(unittest.TestCase):
    def lines(self):
        return [l.strip() for l in TASKS.split('\n') if '/usr/local/bin/cc-secure' in l and 'NOPASSWD' in l]

    def test_reseal_takes_one_key_and_nothing_else(self):
        line = [l for l in self.lines() if 'reseal' in l]
        self.assertEqual(len(line), 1)
        pattern = line[0].split('/usr/local/bin/cc-secure ', 1)[1]
        self.assertEqual(pattern, r'^reseal [A-Za-z0-9+/]{43}\=$')
        rx = re.compile(pattern)
        k = VECTOR_PUBLIC
        self.assertRegex(f'reseal {k}', rx)
        for bad in ('reseal', 'reseal ', f'reseal {k} x', f'reseal {k[:-1]}', f'reseal {k}=', f'reseal  {k}', f' reseal {k}', f'reseal {k[:5]};{k[6:]}', 'rekey', f'reseal {k}\nrekey'):
            self.assertIsNone(rx.fullmatch(bad), bad)

    def test_an_update_does_not_write_the_first_key_back(self):
        task = TASKS[TASKS.index("- name: Disk encryption | the org's recovery public key"):]
        task = task[:task.index('\n\n')]
        self.assertIn('dest: /etc/controlclaw/luks-recovery-pub.b64', task)
        self.assertIn('force: false', task)

    @unittest.skipUnless(shutil.which('visudo'), 'needs visudo')
    def test_visudo_accepts_the_lines(self):
        text = '\n'.join(l.replace('{{ controlclaw_user }}', 'controlclaw') for l in self.lines()) + '\n'
        with tempfile.NamedTemporaryFile('w', suffix='.sudoers') as f:
            f.write(text)
            f.flush()
            r = subprocess.run(['visudo', '-cf', f.name], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == '__main__':
    unittest.main()
