#!/usr/bin/env python3
"""Growing an agent's container: what `cc-secure grow` refuses, the lock, how long a bind may hold
it, what a bind that is stopped half-way leaves in the LUKS header, a mount with one entry that
fails, and the sudoers pattern.

Run from the repo root: python3 -m unittest tests/test_cc_secure_grow.py

The grow itself (truncate, losetup -c, cryptsetup resize, resize2fs on a mounted LUKS2 container)
was proven on real pairs and is not repeated here: it needs root, a loop device and a partner. These
tests cover the parts that decide whether those four commands run at all. Functions are cut out of
the shipped script, so the tests exercise the shipped text.

The test that another user cannot hold the lock needs root and `setpriv`; it skips without them.
The tests of a stopped bind run the real `clevis luks bind` (clevis 20 on Ubuntu 24.04) against a
real LUKS2 header in a file and a real tangd behind a listener that answers late; they need
`cryptsetup`, `clevis`, `jose` and tang, and skip without them.
"""
import fcntl
import os
import re
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'roles/controlclaw/files/cc-secure'
CC_SECURE = SCRIPT.read_text()
TASKS = (ROOT / 'roles/controlclaw/tasks/disk-encryption.yml').read_text()
GIB = 2 ** 30


def shell_function(name):
    return re.search(r'^' + name + r'\(\) \{(?: [^\n]*\}\n|\n.*?^\}\n)', CC_SECURE, re.S | re.M).group(0)


def run_script(*args, env=None):
    """The shipped script, pointed at paths that do not exist."""
    e = {**os.environ, 'CC_SECURE_IMG': '/nonexistent/secure.img', 'CC_SECURE_MOUNT': '/nonexistent/secure', **(env or {})}
    return subprocess.run(['bash', str(SCRIPT), *args], capture_output=True, text=True, env=e)


class Arguments(unittest.TestCase):
    def test_anything_but_one_whole_number_is_refused_before_anything_is_read(self):
        for args in (['30', 'x'], ['-5'], ['0'], ['030'], ['12345'], ['3.5'], ['30G'], [''], [' 30'], ['30;id'], ['$(id)'], []):
            r = run_script('grow', *args)
            self.assertEqual(r.returncode, 1, args)
            self.assertRegex(r.stderr, r'usage: cc-secure grow <gb>|whole number of GiB', args)
            self.assertNotIn('no container', r.stderr, args)

    def test_a_good_number_gets_as_far_as_the_container(self):
        r = run_script('grow', '30')
        self.assertEqual(r.returncode, 1)
        self.assertIn('no container at /nonexistent/secure.img', r.stderr)

    def test_size_on_a_box_with_no_container_says_so_and_changes_nothing(self):
        r = run_script('size')
        self.assertEqual((r.returncode, r.stdout.strip()), (0, '{"present":false}'))


class Refusals(unittest.TestCase):
    """`cmd_grow` as shipped, with the container and the four commands stood in for."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='cc-grow-'))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.img = self.dir / 'secure.img'
        self.key = self.dir / 'luks.key'
        self.key.write_text('k')
        self.calls = self.dir / 'calls'

    def grow(self, gb, *, size_gb=20, max_gb=53, pending=False, size_fails=False):
        with open(self.img, 'wb') as f:
            f.truncate(size_gb * GIB)  # sparse
        info = '{"present":true,"mounted":true,"sizeGb":%d,"maxGb":%d,"pending":%s}' % (size_gb, max_gb, 'true' if pending else 'false')
        script = f'''
set -euo pipefail
IMG={self.img}; KEYFILE={self.key}; MAPPER=cc-test; GIB={GIB}; SECURE=/nonexistent
die() {{ echo "cc-secure: $*" >&2; exit 1; }}
log() {{ echo "cc-secure: $*" >&2; }}
is_mounted() {{ return 0; }}
take_lock() {{ echo take_lock >> {self.calls}; }}
stop_leftover_bind() {{ :; }}
cmd_size() {{ {'return 3' if size_fails else "echo '" + info + "'"}; }}
fs_device_bytes() {{ echo 0; }}
truncate() {{ echo "truncate $*" >> {self.calls}; command truncate "$@"; }}
losetup() {{ echo "losetup $*" >> {self.calls}; [ "$1" = -j ] && echo /dev/loop9; return 0; }}
cryptsetup() {{ echo "cryptsetup $*" >> {self.calls}; }}
resize2fs() {{ echo "resize2fs $*" >> {self.calls}; }}
blockdev() {{ echo 0; }}
{shell_function('cmd_grow')}
cmd_grow {gb}
'''
        r = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
        calls = self.calls.read_text().split('\n') if self.calls.exists() else []
        # `losetup -j` only asks which loop device the image is on; it changes nothing.
        return r, [c for c in calls if c and c != 'take_lock' and not c.startswith('losetup -j')], self.img.stat().st_size // GIB

    def test_smaller_is_refused_and_nothing_runs(self):
        r, calls, size = self.grow(10)
        self.assertEqual(r.returncode, 1)
        self.assertIn('the storage is 20 GiB and cannot be made smaller', r.stderr)
        self.assertEqual((calls, size), ([], 20))

    def test_the_same_size_is_refused_unless_a_grow_was_interrupted(self):
        r, calls, size = self.grow(20)
        self.assertIn('the storage is already 20 GiB', r.stderr)
        self.assertEqual((r.returncode, calls, size), (1, [], 20))
        r, calls, size = self.grow(20, pending=True)
        self.assertIn('finishing an interrupted grow to 20G', r.stderr)
        # The file is not touched; the three later steps run again.
        self.assertEqual([c.split()[0] for c in calls], ['losetup', 'cryptsetup', 'resize2fs'])
        self.assertEqual(size, 20)

    def test_above_the_limit_is_refused_and_the_file_keeps_its_size(self):
        r, calls, size = self.grow(54)
        self.assertIn("no room: this server's disk allows at most 53 GiB", r.stderr)
        self.assertEqual((r.returncode, calls, size), (1, [], 20))

    def test_the_limit_itself_is_accepted_and_the_steps_run_in_order(self):
        r, calls, size = self.grow(53)
        self.assertEqual([c.split()[0] for c in calls], ['truncate', 'losetup', 'cryptsetup', 'resize2fs'])
        self.assertIn(f'cryptsetup resize --key-file {self.key} cc-test', calls)
        self.assertEqual(size, 53)
        # The stand-ins report no device size, so the final check must fail rather than say "done".
        self.assertEqual(r.returncode, 1)
        self.assertIn('after the grow', r.stderr)

    def test_sizes_that_cannot_be_read_are_an_error_with_a_message(self):
        r, calls, size = self.grow(30, size_fails=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("could not read the container's sizes; nothing was changed", r.stderr)
        self.assertEqual((calls, size), ([], 20))

    def test_the_lock_is_taken_before_anything_is_read_or_changed(self):
        grow = shell_function('cmd_grow')
        self.assertLess(grow.index('take_lock'), grow.index('cmd_size'))
        self.assertLess(grow.index('take_lock'), grow.index('truncate -s'))

    def test_grow_never_shrinks_and_never_writes_the_header(self):
        grow = shell_function('cmd_grow')
        for word in ('luksFormat', 'luksAddKey', 'luksChangeKey', 'luksKillSlot', 'clevis', 'mkfs', '--persistent'):
            self.assertNotIn(word, grow)
        # The one truncate is in the branch that already checked the target is larger than the file.
        self.assertEqual(grow.count('truncate -s'), 1)


class Lock(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='cc-lock-'))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.lock_dir = self.dir / 'cc-secure'

    def take(self, wait=1, then='true'):
        script = f'''
set -euo pipefail
die() {{ echo "cc-secure: $*" >&2; exit 1; }}
LOCK_DIR={self.lock_dir}; LOCK="$LOCK_DIR/lock"; LOCK_WAIT_S={wait}
{shell_function('take_lock')}
take_lock
{then}
'''
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True)

    def test_every_change_takes_the_lock_and_the_reads_do_not(self):
        for name in ('cmd_grow', 'cmd_bind', 'cmd_unbind', 'cmd_rekey', 'cmd_reseal', 'cmd_mount'):
            self.assertIn('  take_lock\n', shell_function(name), name)
        for name in ('cmd_size', 'cmd_status', 'cmd_list'):
            self.assertNotIn('take_lock', shell_function(name), name)

    def test_the_lock_is_in_a_directory_only_its_owner_can_enter(self):
        self.assertEqual(self.take().returncode, 0)
        self.assertEqual(stat.S_IMODE(self.lock_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.lock_dir / 'lock').stat().st_mode), 0o600)
        self.assertIn('LOCK_DIR=${CC_SECURE_LOCK_DIR:-/run/cc-secure}', CC_SECURE)

    def test_a_directory_and_file_left_open_to_others_are_closed_again(self):
        self.lock_dir.mkdir(mode=0o755)
        (self.lock_dir / 'lock').touch(mode=0o644)
        os.chmod(self.lock_dir, 0o755)
        os.chmod(self.lock_dir / 'lock', 0o644)
        self.assertEqual(self.take().returncode, 0)
        self.assertEqual(stat.S_IMODE(self.lock_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.lock_dir / 'lock').stat().st_mode), 0o600)

    def test_a_link_in_place_of_the_directory_is_refused(self):
        elsewhere = self.dir / 'elsewhere'
        elsewhere.mkdir()
        self.lock_dir.symlink_to(elsewhere)
        r = self.take()
        self.assertEqual(r.returncode, 1)
        self.assertIn('is not a directory', r.stderr)
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_the_older_lock_file_in_run_is_removed(self):
        self.assertIn('rm -f /run/cc-secure.lock', shell_function('take_lock'))

    def test_a_second_change_waits_and_then_says_why_it_did_nothing(self):
        self.assertEqual(self.take().returncode, 0)
        with open(self.lock_dir / 'lock') as holder:
            fcntl.flock(holder, fcntl.LOCK_EX)
            r = self.take(wait=1)
            self.assertEqual(r.returncode, 1)
            self.assertIn('another change to the container is still running; nothing was changed', r.stderr)
            fcntl.flock(holder, fcntl.LOCK_UN)
        self.assertEqual(self.take(wait=1).returncode, 0)

    def test_the_lock_is_released_when_the_command_ends(self):
        self.assertEqual(self.take(then='exit 0').returncode, 0)
        self.assertEqual(self.take(then='exit 7').returncode, 7)
        self.assertEqual(self.take(wait=1).returncode, 0)

    @unittest.skipUnless(os.geteuid() == 0 and shutil.which('setpriv') and shutil.which('flock'), 'needs root, setpriv and flock')
    def test_another_user_cannot_open_the_lock_so_cannot_hold_it(self):
        os.chmod(self.dir, 0o755)
        self.assertEqual(self.take().returncode, 0)
        r = subprocess.run(['setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', 'flock', '-n', str(self.lock_dir / 'lock'), 'true'], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('ermission denied', r.stderr)
        # And root is not kept waiting by the attempt.
        self.assertEqual(self.take(wait=1).returncode, 0)


class SilentListener:
    """A TCP listener that accepts every connection and never answers: a dead partner's tang."""

    def __enter__(self):
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.conns = []
        self.stop = False
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()
        return self

    def accept(self):
        self.sock.settimeout(0.2)
        while not self.stop:
            try:
                self.conns.append(self.sock.accept()[0])
            except OSError:
                pass

    def __exit__(self, *a):
        self.stop = True
        self.thread.join()
        for c in self.conns:
            c.close()
        self.sock.close()


@unittest.skipUnless(shutil.which('curl') and shutil.which('timeout') and shutil.which('flock'), 'needs curl, timeout and flock')
class BindTimeout(unittest.TestCase):
    """`cmd_bind` as shipped, with a clevis that fetches the advertisement the way clevis does: curl, no timeout."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='cc-bind-'))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        (self.dir / 'bin').mkdir()
        clevis = self.dir / 'bin/clevis'
        # `luks list` prints no slots; `luks bind` asks the URL for its advertisement and waits.
        clevis.write_text('#!/bin/bash\nif [ "$2" = list ]; then exit 0; fi\n'
                          'url=$(printf "%s" "${@: -1}" | sed -n \'s/.*"url":"\\([^"]*\\)".*/\\1/p\')\n'
                          f'echo started > {self.dir}/clevis-started\n'
                          'curl -sf "$url/adv/x" > /dev/null || exit 1\n')
        clevis.chmod(0o755)
        (self.dir / 'luks.key').write_text('k')

    def bind(self, url, timeout_s=2):
        script = f'''
set -euo pipefail
export PATH={self.dir}/bin:$PATH
SECURE={self.dir}/secure; KEYFILE={self.dir}/luks.key; MAPPER=cc-test
LOCK_DIR={self.dir}/lockdir; LOCK="$LOCK_DIR/lock"; LOCK_WAIT_S=1; BIND_TIMEOUT_S={timeout_s}; BIND_RECORD="$LOCK_DIR/bind.sid"
BINDINGS="$SECURE/state/tang-bindings.json"
die() {{ echo "cc-secure: $*" >&2; exit 1; }}
log() {{ echo "cc-secure: $*" >&2; }}
is_mounted() {{ return 0; }}
loopdev() {{ echo /dev/loop9; }}
{shell_function('take_lock')}
{shell_function('bindings_read')}
{shell_function('bindings_write')}
{shell_function('clevis_slots')}
luks_keyslots() {{ echo 0; }}
luks_token_keyslots() {{ :; }}
{shell_function('drop_tokenless_keyslots')}
{shell_function('session_pids')}
{shell_function('session_gone')}
{shell_function('marked_session_pids')}
{shell_function('unrecorded_bind_pids')}
{shell_function('stop_leftover_bind')}
{shell_function('stop_bind')}
{shell_function('finished_unrecorded_slot')}
{shell_function('bind_interrupted')}
{shell_function('run_bind')}
{shell_function('record_binding')}
{shell_function('cmd_bind')}
cmd_bind {url} thumbprint
'''
        started = time.monotonic()
        r = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=60)
        return r, time.monotonic() - started

    def lock_is_free(self):
        return subprocess.run(['flock', '-n', str(self.dir / 'lockdir/lock'), 'true']).returncode == 0

    def test_a_partner_that_accepts_and_never_answers_does_not_hold_the_lock(self):
        with SilentListener() as partner:
            r, took = self.bind(f'http://127.0.0.1:{partner.port}', timeout_s=2)
            self.assertTrue((self.dir / 'clevis-started').exists())
            self.assertEqual(r.returncode, 1)
            self.assertIn(f'bind to http://127.0.0.1:{partner.port} did not answer in 2 s; nothing was changed', r.stderr)
            self.assertGreaterEqual(took, 1.9)
            self.assertLess(took, 12)
            # The listener still has the connection open; the lock is free all the same.
            self.assertTrue(self.lock_is_free())
            # And nothing of the fetch is left running.
            left = subprocess.run(['pgrep', '-f', f'127.0.0.1:{partner.port}/adv'], capture_output=True, text=True).stdout.split()
            self.assertEqual(left, [])

    def test_the_bind_has_a_session_of_its_own_and_does_not_inherit_the_lock(self):
        self.assertRegex(shell_function('run_bind'), r'setsid clevis luks bind [^\n]* 9>&- &')
        # The header is read only after run_bind has returned, and run_bind returns only when the
        # session is empty.
        bind = shell_function('cmd_bind')
        self.assertLess(bind.index('run_bind "$loop"'), bind.index('removed=$(drop_tokenless_keyslots "$loop")'))
        self.assertIn('session_gone "$sid"', shell_function('stop_bind'))
        # The kills come before the wait: a leader that ignores TERM must not be waited on for ever.
        run = shell_function('run_bind')
        self.assertLess(run.index('stop_bind "$sid" "$url"'), run.index('wait "$pid"'))

    def test_a_bind_whose_leader_ignores_term_is_killed_and_does_not_hold_the_lock(self):
        clevis = self.dir / 'bin/clevis'
        clevis.write_text('#!/bin/bash\nif [ "$2" = list ]; then exit 0; fi\ntrap "" TERM\nwhile true; do sleep 1; done\n')
        with SilentListener() as partner:
            r, took = self.bind(f'http://127.0.0.1:{partner.port}', timeout_s=1)
        self.assertEqual(r.returncode, 1)
        self.assertIn('did not answer in 1 s; nothing was changed', r.stderr)
        # One second, three for TERM to be ignored, then KILL.
        self.assertLess(took, 12)
        self.assertTrue(self.lock_is_free())

    def test_a_partner_that_refuses_at_once_is_still_the_old_message(self):
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        r, took = self.bind(f'http://127.0.0.1:{port}', timeout_s=5)
        self.assertEqual(r.returncode, 1)
        self.assertIn('refused (wrong thumbprint, or the partner is unreachable); nothing was changed', r.stderr)
        self.assertLess(took, 4)
        self.assertTrue(self.lock_is_free())

    def test_the_bind_wait_is_shorter_than_the_lock_wait(self):
        bind = int(re.search(r'BIND_TIMEOUT_S=\$\{CC_SECURE_BIND_TIMEOUT_S:-(\d+)\}', CC_SECURE).group(1))
        lock = int(re.search(r'LOCK_WAIT_S=\$\{CC_SECURE_LOCK_WAIT_S:-(\d+)\}', CC_SECURE).group(1))
        self.assertEqual(bind, 60)
        self.assertLess(bind + 5, lock)

    def test_bind_is_the_only_step_under_the_lock_that_talks_to_another_machine(self):
        for name in ('cmd_unbind', 'cmd_rekey', 'cmd_reseal', 'cmd_grow'):
            body = shell_function(name)
            self.assertNotIn('curl', body, name)
            self.assertNotIn('clevis luks bind', body, name)
        # mount asks this box's own tangd, on loopback, and gives it three seconds.
        self.assertIn('curl -sf --max-time 3 "http://127.0.0.1:${TANGD_PORT}/adv"', shell_function('cmd_mount'))


TANGD = '/usr/libexec/tangd'
HAVE_CLEVIS = all(shutil.which(t) for t in ('cryptsetup', 'clevis', 'jose', 'timeout')) and os.path.exists(TANGD) and os.path.exists('/usr/libexec/tangd-keygen')


class LateTang:
    """A real tangd, behind a listener that waits `delay` seconds before it lets each request through."""

    def __init__(self, db, delay):
        self.db, self.delay = db, delay

    def __enter__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.stop = False
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
        return self

    def serve(self):
        self.sock.settimeout(0.2)
        while not self.stop:
            try:
                conn = self.sock.accept()[0]
            except OSError:
                continue
            threading.Thread(target=self.answer, args=(conn,), daemon=True).start()

    def answer(self, conn):
        try:
            conn.settimeout(5)
            request = b''
            while b'\r\n\r\n' not in request:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                request += chunk
            head, _, body = request.partition(b'\r\n\r\n')
            m = re.search(rb'content-length: *(\d+)', head, re.I)
            while m and len(body) < int(m.group(1)):
                body += conn.recv(4096)
            time.sleep(self.delay)
            out = subprocess.run([TANGD, str(self.db)], input=head + b'\r\n\r\n' + body, capture_output=True).stdout
            conn.sendall(out)
        except OSError:
            pass
        finally:
            conn.close()

    def __exit__(self, *a):
        self.stop = True
        self.thread.join()
        self.sock.close()


@unittest.skipUnless(HAVE_CLEVIS, 'needs cryptsetup, clevis, jose and tang')
class StoppedBind(unittest.TestCase):
    """`cmd_bind` as shipped and the real clevis, stopped at each place it can be stopped."""

    @classmethod
    def setUpClass(cls):
        cls.base = Path(tempfile.mkdtemp(prefix='cc-stopped-'))
        cls.db = cls.base / 'tang'
        cls.db.mkdir()
        subprocess.run(['/usr/libexec/tangd-keygen', str(cls.db)], check=True, capture_output=True)
        cls.thp = ''
        for jwk in cls.db.glob('*.jwk'):
            if subprocess.run(['jose', 'jwk', 'use', '-i', str(jwk), '-r', '-u', 'verify'], capture_output=True).returncode == 0:
                cls.thp = subprocess.run(['jose', 'jwk', 'thp', '-i', str(jwk)], capture_output=True, text=True, check=True).stdout.strip()
        assert cls.thp

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base, ignore_errors=True)

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='cc-bindleft-', dir=self.base))
        self.img = self.dir / 'luks.img'
        self.key = self.dir / 'luks.key'
        self.key.write_text('the passphrase of slot 0')
        with open(self.img, 'wb') as f:
            f.truncate(32 * 1024 * 1024)
        # A cheap key derivation, so the tests are about the order of the steps and not about waiting.
        subprocess.run(['cryptsetup', 'luksFormat', '--type', 'luks2', '--batch-mode', '--pbkdf', 'pbkdf2', '--pbkdf-force-iterations', '1000',
                        '--key-file', str(self.key), str(self.img)], check=True, capture_output=True)
        (self.dir / 'bin').mkdir()

    def hang_cryptsetup(self, when):
        """Put a `cryptsetup` in front of the real one that stops clevis at one place: `before-add`,
        `before-token` (the keyslot is added, its token is not) or `after-token` (both are)."""
        real = shutil.which('cryptsetup')
        wrapper = self.dir / 'bin/cryptsetup'
        wrapper.write_text(f'''#!/bin/bash
case " $* " in
  *" luksAddKey "*) [ {when} = before-add ] && exec sleep 599 ;;
  *" token import "*)
    [ {when} = before-token ] && exec sleep 599
    if [ {when} = after-token ]; then {real} "$@"; exec sleep 599; fi ;;
esac
exec {real} "$@"
''')
        wrapper.chmod(0o755)

    def header(self):
        import json
        meta = json.loads(subprocess.run(['cryptsetup', 'luksDump', '--dump-json-metadata', str(self.img)], capture_output=True, text=True, check=True).stdout)
        tokens = sorted(k for t in meta.get('tokens', {}).values() for k in t.get('keyslots', []))
        return sorted(meta['keyslots'], key=int), tokens

    def slot0_opens(self):
        return subprocess.run(['cryptsetup', 'open', '--test-passphrase', '--key-slot', '0', '--key-file', str(self.key), str(self.img)], capture_output=True).returncode == 0

    def bind(self, port, timeout_s):
        script = f'''
set -euo pipefail
export PATH={self.dir}/bin:$PATH
SECURE={self.dir}/secure; KEYFILE={self.key}; MAPPER=cc-test
LOCK_DIR={self.dir}/lockdir; LOCK="$LOCK_DIR/lock"; LOCK_WAIT_S=1; BIND_TIMEOUT_S={timeout_s}; BIND_RECORD="$LOCK_DIR/bind.sid"
BINDINGS="$SECURE/state/tang-bindings.json"
die() {{ echo "cc-secure: $*" >&2; exit 1; }}
log() {{ echo "cc-secure: $*" >&2; }}
is_mounted() {{ return 0; }}
loopdev() {{ echo {self.img}; }}
{shell_function('take_lock')}
{shell_function('bindings_read')}
{shell_function('bindings_write')}
{shell_function('clevis_slots')}
{shell_function('luks_keyslots')}
{shell_function('luks_token_keyslots')}
{shell_function('drop_tokenless_keyslots')}
{shell_function('session_pids')}
{shell_function('session_gone')}
{shell_function('marked_session_pids')}
{shell_function('unrecorded_bind_pids')}
{shell_function('stop_leftover_bind')}
{shell_function('stop_bind')}
{shell_function('finished_unrecorded_slot')}
{shell_function('bind_interrupted')}
{shell_function('run_bind')}
{shell_function('record_binding')}
{shell_function('cmd_bind')}
cmd_bind http://127.0.0.1:{port} {self.thp}
'''
        # Its own process group, so the stand-in that hangs can be stopped with it and with nothing else.
        p = subprocess.Popen(['bash', '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, process_group=0)
        try:
            out, err = p.communicate(timeout=120)
        finally:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        return subprocess.CompletedProcess(p.args, p.returncode, out, err)

    def test_a_bind_that_finishes_adds_one_slot_with_its_token(self):
        with LateTang(self.db, 0) as tang:
            r = self.bind(tang.port, 30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('bound slot 1 to', r.stderr)
        self.assertEqual(self.header(), (['0', '1'], ['1']))

    def test_stopped_before_the_keyslot_is_added_nothing_is_changed(self):
        self.hang_cryptsetup('before-add')
        with LateTang(self.db, 0) as tang:
            r = self.bind(tang.port, 4)
        self.assertEqual(r.returncode, 1)
        self.assertIn('did not answer in 4 s; nothing was changed', r.stderr)
        self.assertEqual(self.header(), (['0'], []))

    def test_stopped_between_the_keyslot_and_its_token_the_keyslot_is_removed_and_said_so(self):
        self.hang_cryptsetup('before-token')
        with LateTang(self.db, 0) as tang:
            r = self.bind(tang.port, 4)
        self.assertEqual(r.returncode, 1)
        self.assertIn('removed keyslot 1, which had no token', r.stderr)
        self.assertIn('did not answer in 4 s after it had added keyslot(s) 1 with no token; removed them, so nothing is changed', r.stderr)
        self.assertEqual(self.header(), (['0'], []))
        self.assertTrue(self.slot0_opens())
        # And they do not add up: the same again leaves the same header.
        with LateTang(self.db, 0) as tang:
            self.bind(tang.port, 4)
            self.bind(tang.port, 4)
        self.assertEqual(self.header(), (['0'], []))
        # A bind that is let through afterwards works, in the slot the others would have taken.
        (self.dir / 'bin/cryptsetup').unlink()
        with LateTang(self.db, 0) as tang:
            r = self.bind(tang.port, 30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.header(), (['0', '1'], ['1']))

    def test_stopped_after_the_token_the_finished_binding_is_kept_and_recorded(self):
        self.hang_cryptsetup('after-token')
        with LateTang(self.db, 0) as tang:
            r = self.bind(tang.port, 4)
            port = tang.port
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('slot 1 was already written with its token; keeping it', r.stderr)
        self.assertEqual(self.header(), (['0', '1'], ['1']))
        self.assertIn(f'"url": "http://127.0.0.1:{port}"', (self.dir / 'secure/state/tang-bindings.json').read_text())

    def test_a_tokenless_keyslot_found_at_the_start_of_a_bind_is_removed_before_anything_else(self):
        # What a bind leaves when its cc-secure is killed outright and can clean up nothing: a
        # keyslot with no token. No later unbind can find it; the next bind removes it first.
        left = self.dir / 'left.key'
        left.write_text('what the killed bind had derived')
        for _ in range(2):
            subprocess.run(['cryptsetup', 'luksAddKey', '--batch-mode', '--pbkdf', 'pbkdf2', '--pbkdf-force-iterations', '1000', '--key-file', str(self.key), str(self.img), str(left)], check=True, capture_output=True)
        self.assertEqual(self.header(), (['0', '1', '2'], []))
        with LateTang(self.db, 0) as tang:
            r = self.bind(tang.port, 30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('removed keyslot 1, which had no token', r.stderr)
        self.assertIn('removed keyslot 2, which had no token', r.stderr)
        # The new binding took the first free slot, and it is the only one besides slot 0.
        self.assertEqual(self.header(), (['0', '1'], ['1']))
        self.assertTrue(self.slot0_opens())

    def test_the_sweep_at_the_start_leaves_slots_that_have_a_token(self):
        with LateTang(self.db, 0) as tang:
            self.assertEqual(self.bind(tang.port, 30).returncode, 0)
        with LateTang(self.db, 0) as other:
            r = self.bind(other.port, 30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn('removed keyslot', r.stderr)
        self.assertEqual(self.header(), (['0', '1', '2'], ['1', '2']))

    def script_file(self, port, timeout_s):
        f = self.dir / 'cc-secure-under-test'
        f.write_text(f'''
set -euo pipefail
export PATH={self.dir}/bin:$PATH
SECURE={self.dir}/secure; KEYFILE={self.key}; MAPPER=cc-test
LOCK_DIR={self.dir}/lockdir; LOCK="$LOCK_DIR/lock"; LOCK_WAIT_S=1; BIND_TIMEOUT_S={timeout_s}; BIND_RECORD="$LOCK_DIR/bind.sid"
BINDINGS="$SECURE/state/tang-bindings.json"
die() {{ echo "cc-secure: $*" >&2; exit 1; }}
log() {{ echo "cc-secure: $*" >&2; }}
is_mounted() {{ return 0; }}
finish_interrupted_rekey() {{ :; }}
loopdev() {{ echo {self.img}; }}
''' + '\n'.join(shell_function(n) for n in (
            'take_lock', 'bindings_read', 'bindings_write', 'clevis_slots', 'luks_keyslots', 'luks_token_keyslots', 'drop_tokenless_keyslots',
            'session_pids', 'session_gone', 'marked_session_pids', 'unrecorded_bind_pids', 'stop_leftover_bind', 'stop_bind',
            'finished_unrecorded_slot', 'bind_interrupted', 'run_bind', 'record_binding', 'cmd_bind')) + f'''
cmd_bind http://127.0.0.1:{port} {self.thp}
''')
        return f

    def test_killed_while_clevis_waits_for_a_partner_that_never_answers_the_next_bind_stops_it(self):
        # The case found in review. clevis runs as `/bin/bash -e /usr/bin/clevis-luks-bind …` and is
        # in its curl; cc-secure is killed outright, so nothing stops it and nothing cleans up. It
        # would add its keyslot whenever that partner answered, with no lock held.
        with SilentListener() as silent, LateTang(self.db, 0) as tang:
            # Its output goes to a file: the leftover inherits it, and a pipe would never close.
            with open(self.dir / 'first.log', 'w') as out:
                p = subprocess.Popen(['bash', str(self.script_file(silent.port, 60))], stdout=out, stderr=out)
            for _ in range(100):
                if subprocess.run(['pgrep', '-f', f'127.0.0.1:{silent.port}/adv'], capture_output=True).stdout.split():
                    break
                time.sleep(0.1)
            p.kill()
            p.wait()
            orphan = subprocess.run(['pgrep', '-f', f'127.0.0.1:{silent.port}/adv'], capture_output=True, text=True).stdout.split()
            self.assertTrue(orphan, 'the test did not leave clevis in its curl')
            record = self.dir / 'lockdir/bind.sid'
            self.assertTrue(record.exists())
            # A second bind, to a partner that does answer.
            r = self.bind(tang.port, 30)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('stopping a bind that an earlier cc-secure left running', r.stderr)
            # Nothing of the first bind is left, in curl or anywhere else.
            self.assertEqual(subprocess.run(['pgrep', '-f', f'127.0.0.1:{silent.port}/adv'], capture_output=True, text=True).stdout.split(), [])
            self.assertEqual(subprocess.run(['pgrep', '-f', 'clevis-luks-bind'], capture_output=True, text=True).stdout.split(), [])
            self.assertFalse(record.exists())
            self.assertEqual(self.header(), (['0', '1'], ['1']))
            listed = subprocess.run(['clevis', 'luks', 'list', '-d', str(self.img)], capture_output=True, text=True).stdout
            self.assertEqual(listed.count('"url"'), 1, listed)
            self.assertIn(f'127.0.0.1:{tang.port}', listed)

    @unittest.skipUnless(os.geteuid() == 0, 'the fallback only looks at root\'s processes')
    def test_a_leftover_from_before_the_record_is_found_by_its_command_line_wherever_the_name_stands(self):
        # No record file, as after an update from a version that did not write one: the leftover
        # is found by name. `/bin/bash -e /usr/bin/clevis-luks-bind -y -d DEV …` is how clevis runs.
        fake = self.dir / 'usr-bin'
        fake.mkdir()
        (fake / 'clevis-luks-bind').write_text('sleep 300\n')
        p = subprocess.Popen(['setsid', '/bin/bash', '-e', str(fake / 'clevis-luks-bind'), '-y', '-d', str(self.img), '-k', 'x'])
        try:
            time.sleep(0.3)
            out = subprocess.run(['bash', '-c', f'{shell_function("unrecorded_bind_pids")}\nunrecorded_bind_pids {self.img}'], capture_output=True, text=True).stdout.split()
            self.assertIn(str(p.pid), out)
            # Another device's bind is somebody else's.
            other = subprocess.run(['bash', '-c', f'{shell_function("unrecorded_bind_pids")}\nunrecorded_bind_pids /dev/loop77'], capture_output=True, text=True).stdout.split()
            self.assertNotIn(str(p.pid), other)
            with LateTang(self.db, 0) as tang:
                r = self.bind(tang.port, 30)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('stopping a bind from before this version', r.stderr)
            self.assertIsNotNone(p.wait(timeout=10))
        finally:
            subprocess.run(['pkill', '-KILL', '-f', str(fake / 'clevis-luks-bind')], capture_output=True)

    @unittest.skipUnless(os.geteuid() == 0 and shutil.which('setpriv'), 'needs root and setpriv')
    def test_words_in_a_command_line_do_not_get_a_root_service_killed(self):
        # Found in review: a process run as nobody with `cryptsetup luksAddKey <device>` in its
        # arguments, inside a root service's session, got that whole service SIGKILLed.
        os.chmod(self.base, 0o755)
        os.chmod(self.dir, 0o755)
        fake = self.dir / 'spoof'
        fake.mkdir(mode=0o755)
        (fake / 'cryptsetup').write_text('#!/bin/sh\nsleep 300\n')
        (fake / 'cryptsetup').chmod(0o755)
        (fake / 'service').write_text(f'''#!/bin/sh
setpriv --reuid=65534 --regid=65534 --clear-groups {fake}/cryptsetup luksAddKey {self.img} &
echo $! > {fake}/nobody.pid
{fake}/cryptsetup luksAddKey {self.img} &
echo $! > {fake}/root.pid
sleep 300
''')
        (fake / 'service').chmod(0o755)
        service = subprocess.Popen(['setsid', str(fake / 'service')])
        try:
            for _ in range(50):
                if (fake / 'root.pid').exists() and (fake / 'root.pid').read_text().strip():
                    break
                time.sleep(0.1)
            time.sleep(0.3)
            as_nobody = int((fake / 'nobody.pid').read_text())
            as_root = int((fake / 'root.pid').read_text())
            alive = lambda pid: subprocess.run(['kill', '-0', str(pid)], capture_output=True).returncode == 0
            with LateTang(self.db, 0) as tang:
                r = self.bind(tang.port, 30)
            self.assertEqual(r.returncode, 0, r.stderr)
            # The service, a root process whose session this is, is untouched.
            self.assertIsNone(service.poll(), 'the root service was killed')
            # nobody's process is not root's, so its words are not believed.
            self.assertTrue(alive(as_nobody), "nobody's process was killed")
            # Root's own match inside that session loses only itself: the session is not the bind's.
            self.assertFalse(alive(as_root), "root's luksAddKey on this device was left running")
        finally:
            subprocess.run(['pkill', '-KILL', '-s', str(service.pid)], capture_output=True)
            service.kill()
            service.wait()

    def test_stopped_at_the_instant_a_rebind_finished_the_slot_it_replaces_is_removed(self):
        # A partner whose tang key changed is bound again: same URL, new slot, old slot dropped.
        # Stopped by a signal just as clevis finished, the new slot was recorded and the old one
        # left: two slots for one URL.
        with LateTang(self.db, 0) as tang:
            self.assertEqual(self.bind(tang.port, 30).returncode, 0)
            self.assertEqual(self.header(), (['0', '1'], ['1']))
            # What a changed key looks like here: the thumbprint on record is no longer the partner's.
            record = self.dir / 'secure/state/tang-bindings.json'
            record.write_text(record.read_text().replace(self.thp, 'the-thumbprint-it-had-before'))
            self.hang_cryptsetup('after-token')
            p = subprocess.Popen(['bash', str(self.script_file(tang.port, 60))], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for _ in range(200):
                if self.header() == (['0', '1', '2'], ['1', '2']):
                    break
                time.sleep(0.1)
            p.send_signal(signal.SIGTERM)
            _, err = p.communicate(timeout=60)
            port = tang.port
        self.assertIn('which had just finished: slot 2 is kept and recorded', err)
        self.assertIn('removed the stale slot 1', err)
        self.assertEqual(self.header(), (['0', '2'], ['2']))
        listed = subprocess.run(['clevis', 'luks', 'list', '-d', str(self.img)], capture_output=True, text=True).stdout
        self.assertEqual(listed.count(f'127.0.0.1:{port}'), 1, listed)
        import json
        self.assertEqual(json.loads(record.read_text()), {'2': {'thp': self.thp, 'url': f'http://127.0.0.1:{port}'}})

    def test_already_bound_still_stops_a_leftover_first(self):
        bind = shell_function('cmd_bind')
        self.assertLess(bind.index('stop_leftover_bind "$loop"'), bind.index('already bound to $url with that key'))
        self.assertEqual(bind.count('stop_leftover_bind'), 1)

    def test_the_record_is_written_by_rename_and_a_vanished_pid_is_not_an_error(self):
        self.assertIn('> "$BIND_RECORD.tmp" && mv -f "$BIND_RECORD.tmp" "$BIND_RECORD"', shell_function('run_bind'))
        r = subprocess.run(['bash', '-c', f'session_pids() {{ echo 999999991; }}\n{shell_function("marked_session_pids")}\nmarked_session_pids 1'], capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, '', ''))

    def test_a_recorded_session_that_is_no_longer_a_bind_is_left_alone(self):
        # The kernel can hand a session id to something else. Without the mark a bind is started
        # with, the recorded session is not touched.
        bystander = subprocess.Popen(['sleep', '300'], start_new_session=True)
        try:
            (self.dir / 'lockdir').mkdir(mode=0o700, exist_ok=True)
            (self.dir / 'lockdir/bind.sid').write_text(f'{bystander.pid}\n')
            with LateTang(self.db, 0) as tang:
                r = self.bind(tang.port, 30)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn('stopping a bind', r.stderr)
            self.assertIsNone(bystander.poll())
        finally:
            bystander.kill()
            bystander.wait()

    def test_stopped_by_a_signal_at_the_instant_clevis_finished_the_binding_is_recorded(self):
        # Keyslot and token both written, and then cc-secure is told to stop: a working binding
        # that must not be left unlisted.
        self.hang_cryptsetup('after-token')
        with LateTang(self.db, 0) as tang:
            p = subprocess.Popen(['bash', str(self.script_file(tang.port, 60))], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for _ in range(200):
                if self.header() == (['0', '1'], ['1']):
                    break
                time.sleep(0.1)
            p.send_signal(signal.SIGTERM)
            _, err = p.communicate(timeout=60)
            port = tang.port
        self.assertIn('which had just finished: slot 1 is kept and recorded', err)
        self.assertEqual(self.header(), (['0', '1'], ['1']))
        self.assertIn(f'"url": "http://127.0.0.1:{port}"', (self.dir / 'secure/state/tang-bindings.json').read_text())
        self.assertEqual(subprocess.run(['pgrep', '-f', str(self.img)], capture_output=True, text=True).stdout.split(), [])

    def test_a_keyslot_that_cannot_be_removed_is_said_as_that(self):
        left = self.dir / 'left.key'
        left.write_text('left by a bind')
        subprocess.run(['cryptsetup', 'luksAddKey', '--batch-mode', '--pbkdf', 'pbkdf2', '--pbkdf-force-iterations', '1000', '--key-file', str(self.key), str(self.img), str(left)], check=True, capture_output=True)
        good = self.key.read_text()
        self.key.write_text('not the passphrase of slot 0')
        try:
            with LateTang(self.db, 0) as tang:
                r = self.bind(tang.port, 30)
        finally:
            self.key.write_text(good)
        self.assertEqual(r.returncode, 1)
        self.assertIn('keyslot 1 has no token and could not be removed', r.stderr)
        self.assertNotIn('cannot read the LUKS header', r.stderr)
        self.assertEqual(self.header(), (['0', '1'], []))

    def test_grow_unbind_rekey_and_reseal_stop_a_leftover_bind_first(self):
        for name in ('cmd_grow', 'cmd_unbind', 'cmd_rekey', 'cmd_reseal', 'cmd_bind'):
            body = shell_function(name)
            self.assertIn('stop_leftover_bind', body, name)
            self.assertLess(body.index('take_lock'), body.index('stop_leftover_bind'), name)

    def test_the_session_is_written_down_when_the_bind_starts_and_removed_when_it_ends(self):
        run = shell_function('run_bind')
        self.assertLess(run.index('CC_SECURE_BIND=1 setsid clevis luks bind'), run.index('"$BIND_RECORD.tmp" "$BIND_RECORD"'))
        self.assertLess(run.index('wait "$pid"'), run.index('rm -f "$BIND_RECORD"'))
        self.assertIn('BIND_RECORD="$LOCK_DIR/bind.sid"', CC_SECURE)
        with LateTang(self.db, 0) as tang:
            self.assertEqual(self.bind(tang.port, 30).returncode, 0)
        self.assertFalse((self.dir / 'lockdir/bind.sid').exists())

    def test_the_sweep_is_the_first_thing_a_bind_does_to_the_header(self):
        bind = shell_function('cmd_bind')
        self.assertLess(bind.index('take_lock'), bind.index('stop_leftover_bind "$loop"'))
        self.assertLess(bind.index('stop_leftover_bind "$loop"'), bind.index('drop_tokenless_keyslots "$loop" >/dev/null'))
        self.assertLess(bind.index('drop_tokenless_keyslots "$loop" >/dev/null'), bind.index('run_bind "$loop"'))

    def test_killed_at_any_moment_after_a_late_answer_no_keyslot_is_left_without_a_token(self):
        # The measured case: tang answers after a while and the bind is stopped some time after that.
        # Whatever the moment, the header ends with slot 0 and only slots that have their token.
        with LateTang(self.db, 1.0) as tang:
            for timeout_s in (1.2, 1.5, 1.8, 2.2, 2.6, 3.0):
                r = self.bind(tang.port, timeout_s)
                slots, tokens = self.header()
                self.assertEqual([s for s in slots if s != '0' and s not in tokens], [], f'{timeout_s}: {r.stderr}')
                self.assertTrue(self.slot0_opens(), timeout_s)

    def test_slot_zero_and_slots_with_a_token_are_never_candidates(self):
        body = shell_function('drop_tokenless_keyslots')
        self.assertIn('[ "$slot" != 0 ] || continue', body)
        self.assertLess(body.index('[ "$slot" != 0 ] || continue'), body.index('luksKillSlot'))
        self.assertLess(body.index('grep -qx "$slot" && continue'), body.index('luksKillSlot'))


@unittest.skipUnless(HAVE_CLEVIS, 'needs cryptsetup, clevis, jose and tang')
class StoppedBindWithTheRealKeyDerivation(unittest.TestCase):
    """The case found in review, with nothing stood in: a container whose slot 0 is argon2id (what
    `cc-secure init` makes), the real clevis, and a tang that answers after 3 s. `cryptsetup
    luksAddKey` then spends seconds deriving a key and does not die on SIGTERM, so a bind stopped
    in that window used to write its keyslot after the header had been read and the lock released.

    Slow on purpose (about three minutes): every timeout from 5.0 to 7.4 s in steps of 0.2."""

    @classmethod
    def setUpClass(cls):
        cls.base = Path(tempfile.mkdtemp(prefix='cc-argon-'))
        cls.db = cls.base / 'tang'
        cls.db.mkdir()
        subprocess.run(['/usr/libexec/tangd-keygen', str(cls.db)], check=True, capture_output=True)
        cls.thp = ''
        for jwk in cls.db.glob('*.jwk'):
            if subprocess.run(['jose', 'jwk', 'use', '-i', str(jwk), '-r', '-u', 'verify'], capture_output=True).returncode == 0:
                cls.thp = subprocess.run(['jose', 'jwk', 'thp', '-i', str(jwk)], capture_output=True, text=True, check=True).stdout.strip()
        cls.key = cls.base / 'luks.key'
        cls.key.write_text('the passphrase of slot 0')
        cls.pristine = cls.base / 'pristine.img'
        with open(cls.pristine, 'wb') as f:
            f.truncate(32 * 1024 * 1024)
        # The defaults, as cmd_init: an argon2id keyslot.
        subprocess.run(['cryptsetup', 'luksFormat', '--type', 'luks2', '--batch-mode', '--key-file', str(cls.key), str(cls.pristine)], check=True, capture_output=True)
        # Slot 1: a partner that is already bound, which no later bind may touch.
        with LateTang(cls.db, 0) as tang:
            subprocess.run(['clevis', 'luks', 'bind', '-y', '-d', str(cls.pristine), '-k', str(cls.key), 'tang',
                            '{"url":"http://127.0.0.1:%d","thp":"%s"}' % (tang.port, cls.thp)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base, ignore_errors=True)

    def header(self, img):
        import json
        return json.loads(subprocess.run(['cryptsetup', 'luksDump', '--dump-json-metadata', str(img)], capture_output=True, text=True, check=True).stdout)

    def script(self, img, port, timeout_s):
        d = img.parent
        script = f'''
set -euo pipefail
SECURE={d}/secure; KEYFILE={self.key}; MAPPER=cc-test
LOCK_DIR={d}/lockdir; LOCK="$LOCK_DIR/lock"; LOCK_WAIT_S=1; BIND_TIMEOUT_S={timeout_s}; BIND_RECORD="$LOCK_DIR/bind.sid"
BINDINGS="$SECURE/state/tang-bindings.json"
die() {{ echo "cc-secure: $*" >&2; exit 1; }}
log() {{ echo "cc-secure: $*" >&2; }}
is_mounted() {{ return 0; }}
loopdev() {{ echo {img}; }}
{shell_function('take_lock')}
{shell_function('bindings_read')}
{shell_function('bindings_write')}
{shell_function('clevis_slots')}
{shell_function('luks_keyslots')}
{shell_function('luks_token_keyslots')}
{shell_function('drop_tokenless_keyslots')}
{shell_function('session_pids')}
{shell_function('session_gone')}
{shell_function('marked_session_pids')}
{shell_function('unrecorded_bind_pids')}
{shell_function('stop_leftover_bind')}
{shell_function('stop_bind')}
{shell_function('finished_unrecorded_slot')}
{shell_function('bind_interrupted')}
{shell_function('run_bind')}
{shell_function('record_binding')}
{shell_function('cmd_bind')}
cmd_bind http://127.0.0.1:{port} {self.thp}
'''
        return script

    def bind(self, img, port, timeout_s):
        return subprocess.run(['bash', '-c', self.script(img, port, timeout_s)], capture_output=True, text=True, timeout=180)

    def start_bind(self, img, port, timeout_s):
        # `exec` in a file, as the real script is run: the signal goes to cc-secure itself.
        f = img.parent / 'cc-secure-under-test'
        f.write_text(self.script(img, port, timeout_s))
        return subprocess.Popen(['bash', str(f)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_cc_secure_itself_told_to_stop_at_any_moment_leaves_no_keyslot_without_a_token(self):
        # What the daemon's own timeout did: TERM to cc-secure while its bind was under way. Found
        # in review at a 5.5 s bind timeout with TERM at 6.6 s: cryptsetup survived and wrote a
        # tokenless slot. Here: TERM to the script at seven moments around the partner's answer.
        before = self.header(self.pristine)
        said = []
        with LateTang(self.db, 3.0) as tang:
            # 7.0 to 8.2: after the bind's own timeout, while what it left is being removed.
            for at in (2.0, 3.6, 4.4, 5.0, 5.6, 6.6, 7.0, 7.4, 7.8, 8.2):
                d = Path(tempfile.mkdtemp(prefix=f'term-{at}-', dir=self.base))
                img = d / 'luks.img'
                shutil.copyfile(self.pristine, img)
                p = self.start_bind(img, tang.port, 5.5)
                time.sleep(at)
                p.send_signal(signal.SIGTERM)
                try:
                    _, err = p.communicate(timeout=60)
                except subprocess.TimeoutExpired:
                    p.kill()
                    self.fail(f'TERM at {at} s: cc-secure did not end')
                left = subprocess.run(['pgrep', '-f', str(img)], capture_output=True, text=True).stdout.split()
                self.assertEqual(left, [], f'TERM at {at} s: still running after cc-secure ended')
                time.sleep(4)
                now = self.header(img)
                token_slots = {str(k) for t in now.get('tokens', {}).values() for k in t.get('keyslots', [])}
                orphans = [k for k in now['keyslots'] if k not in token_slots and k != '0']
                self.assertEqual(orphans, [], f'TERM at {at} s: keyslot(s) {orphans} have no token. {err}')
                for slot in ('0', '1'):
                    self.assertEqual(now['keyslots'][slot], before['keyslots'][slot], f'TERM at {at} s: keyslot {slot} changed')
                said.append('interrupted' if 'interrupted during the bind' in err else 'other')
                # It never goes without a word: either the trap's sentence or the bind's own.
                self.assertIn('cc-secure: ', err, f'TERM at {at} s: cc-secure ended silently')
                shutil.rmtree(d, ignore_errors=True)
        self.assertIn('interrupted', said, said)

    def test_cc_secure_killed_outright_leaves_a_slot_that_the_next_bind_removes(self):
        # kill -9 cannot be caught: clevis and its cryptsetup carry on in their own session and
        # write a keyslot with no token, with the lock gone. The next bind stops what is still
        # running and removes the slot before it does anything else.
        d = Path(tempfile.mkdtemp(prefix='kill9-', dir=self.base))
        img = d / 'luks.img'
        shutil.copyfile(self.pristine, img)
        with LateTang(self.db, 1.0) as tang:
            p = self.start_bind(img, tang.port, 30)
            time.sleep(2.2)
            p.kill()
            p.communicate()
            r = self.bind(img, tang.port, 60)
        self.assertEqual(r.returncode, 0, r.stderr)
        time.sleep(4)
        now = self.header(img)
        token_slots = {str(k) for t in now.get('tokens', {}).values() for k in t.get('keyslots', [])}
        self.assertEqual([k for k in now['keyslots'] if k not in token_slots and k != '0'], [], r.stderr)
        self.assertEqual(subprocess.run(['pgrep', '-f', str(img)], capture_output=True, text=True).stdout.split(), [])

    def test_the_slot_zero_under_test_is_argon2id(self):
        self.assertEqual(self.header(self.pristine)['keyslots']['0']['kdf']['type'], 'argon2id')

    def test_no_timeout_from_5_to_7_4_seconds_leaves_a_keyslot_without_a_token(self):
        before = self.header(self.pristine)
        outcomes = []
        with LateTang(self.db, 3.0) as tang:
            for tenths in range(50, 76, 2):
                timeout_s = tenths / 10
                d = Path(tempfile.mkdtemp(prefix=f'run-{tenths}-', dir=self.base))
                img = d / 'luks.img'
                shutil.copyfile(self.pristine, img)
                r = self.bind(img, tang.port, timeout_s)
                # When cmd_bind returns the lock is free, and nothing of the bind may still be running.
                left = subprocess.run(['pgrep', '-f', str(img)], capture_output=True, text=True).stdout.split()
                self.assertEqual(left, [], f'{timeout_s}: still running after the bind returned')
                self.assertEqual(subprocess.run(['flock', '-n', str(d / 'lockdir/lock'), 'true']).returncode, 0, timeout_s)
                # Long enough for a key derivation that was left running to finish and write its slot.
                time.sleep(4)
                now = self.header(img)
                token_slots = {str(k) for t in now.get('tokens', {}).values() for k in t.get('keyslots', [])}
                orphans = [k for k in now['keyslots'] if k not in token_slots and k != '0']
                self.assertEqual(orphans, [], f'{timeout_s} s: keyslot(s) {orphans} have no token. {r.stderr}')
                for slot in ('0', '1'):
                    self.assertEqual(now['keyslots'][slot], before['keyslots'][slot], f'{timeout_s}: keyslot {slot} changed')
                self.assertEqual({k: v for k, v in now['tokens'].items() if '1' in [str(x) for x in v['keyslots']]},
                                 {k: v for k, v in before['tokens'].items()}, f'{timeout_s}: the token of slot 1 changed')
                outcomes.append('bound' if r.returncode == 0 else 'removed' if 'removed them' in r.stderr else 'nothing')
                shutil.rmtree(d, ignore_errors=True)
        # The sweep has to have stopped at least one bind, or it proved nothing.
        self.assertTrue(any(o != 'bound' for o in outcomes), outcomes)
        print('\n      outcomes by timeout 5.0..7.4 s:', ' '.join(outcomes), file=__import__('sys').stderr)


class MountWithOneEntryThatFails(unittest.TestCase):
    """`cmd_mount` as shipped, with the system stood in for."""

    def mount(self, binds, failing_owner='ghost'):
        d = Path(tempfile.mkdtemp(prefix='cc-mount-'))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        calls = d / 'calls'
        script = f'''
set -euo pipefail
SECURE={d}/secure; TANG_DB="$SECURE/tang"; MAPPER=cc-test; TANGD_PORT=3921; KEYFILE=/nonexistent; MOUNT_OPTIONAL_FAILED=3
export CC_SECURE_BINDS="{binds}"
die() {{ echo "cc-secure: $*" >&2; exit 1; }}
log() {{ echo "cc-secure: $*" >&2; }}
is_open() {{ return 0; }}
is_mounted() {{ return 0; }}
take_lock() {{ :; }}
mountpoint() {{ return 1; }}
mount() {{ echo "mount $*" >> {calls}; }}
chown() {{ case "$*" in *{failing_owner}*) echo "chown: invalid user" >&2; return 1 ;; esac; return 0; }}
systemctl() {{ echo "systemctl $*" >> {calls}; }}
curl() {{ return 0; }}
{shell_function('bind_entry')}
{shell_function('cmd_mount')}
cmd_mount
'''
        r = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
        return r, calls.read_text() if calls.exists() else '', d

    def test_the_other_entries_are_mounted_tang_starts_and_the_exit_says_one_failed(self):
        d0 = tempfile.mkdtemp(prefix='cc-mount-dst-')
        self.addCleanup(shutil.rmtree, d0, ignore_errors=True)
        r, calls, d = self.mount(f'keys:{d0}/keys:root:0750 notes:{d0}/notes:ghost:0750 state:{d0}/state:root:0750')
        self.assertEqual(r.returncode, 1)
        self.assertIn(f'ERROR: could not mount {d}/secure/notes at {d0}/notes; carrying on with the rest', r.stderr)
        self.assertIn(f'mounted at {d}/secure, but these could not be mounted: {d0}/notes', r.stderr)
        self.assertIn(f'mount --bind {d}/secure/keys {d0}/keys', calls)
        self.assertIn(f'mount --bind {d}/secure/state {d0}/state', calls)
        self.assertNotIn(f'{d0}/notes', calls)
        self.assertIn('systemctl start tangd.socket', calls)
        self.assertIn('tang is serving', r.stderr)

    def test_with_nothing_failing_it_ends_as_before(self):
        d0 = tempfile.mkdtemp(prefix='cc-mount-dst-')
        self.addCleanup(shutil.rmtree, d0, ignore_errors=True)
        r, calls, d = self.mount(f'keys:{d0}/keys:root:0750 state:{d0}/state:root:0750')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stderr.rstrip().endswith(f'cc-secure: mounted at {d}/secure'))
        self.assertEqual(calls.count('mount --bind'), 2)

    def test_an_optional_entry_that_fails_exits_3_with_everything_else_done(self):
        d0 = tempfile.mkdtemp(prefix='cc-mount-dst-')
        self.addCleanup(shutil.rmtree, d0, ignore_errors=True)
        r, calls, d = self.mount(f'keys:{d0}/keys:root:0750 notes:{d0}/notes:ghost:0750:optional state:{d0}/state:root:0750')
        self.assertEqual(r.returncode, 3)
        self.assertIn(f'mounted at {d}/secure, but these optional directories could not be mounted: {d0}/notes', r.stderr)
        self.assertEqual(calls.count('mount --bind'), 2)
        self.assertIn('systemctl start tangd.socket', calls)

    def test_a_required_entry_that_fails_is_still_exit_1_even_next_to_an_optional_one(self):
        d0 = tempfile.mkdtemp(prefix='cc-mount-dst-')
        self.addCleanup(shutil.rmtree, d0, ignore_errors=True)
        r, _, _ = self.mount(f'keys:{d0}/keys:ghost:0750 notes:{d0}/notes:ghost:0750:optional')
        self.assertEqual(r.returncode, 1)
        self.assertIn(f'could not be mounted: {d0}/keys {d0}/notes', r.stderr)

    def test_keys_state_and_the_home_cannot_be_made_optional(self):
        d0 = tempfile.mkdtemp(prefix='cc-mount-dst-')
        self.addCleanup(shutil.rmtree, d0, ignore_errors=True)
        for sub in ('keys', 'state', 'openclaw', 'gbrain', 'mitm-ca', 'connector', 'clickclack', 'postgresql'):
            r, _, _ = self.mount(f'{sub}:{d0}/{sub}:ghost:0750:optional other:{d0}/other:root:0750')
            self.assertEqual(r.returncode, 1, sub)
            self.assertIn(f'ignoring :optional on {sub}: it is always required', r.stderr)
            self.assertIn(f'could not be mounted: {d0}/{sub}', r.stderr)

    def test_shared_notes_is_the_one_optional_entry_the_role_ships(self):
        defaults = (ROOT / 'roles/controlclaw/defaults/main.yml').read_text()
        binds = defaults[defaults.index('luks_binds:'):defaults.index('luks_dependent_units:')]
        specs = re.findall(r"'([a-z-]+):((?:/|' ~)[^\]]*?)'(?=[,\]])", binds)
        self.assertEqual({name for name, _ in specs}, {'keys', 'state', 'openclaw', 'mitm-ca', 'connector', 'clickclack', 'gbrain', 'postgresql', 'notes'})
        self.assertEqual({name for name, rest in specs if rest.endswith(':optional')}, {'notes'})
        self.assertIn("'notes:/var/lib/controlclaw-notes:root:0755:optional'", binds)
        # cc-secure would not take the marker on any of the others: each is a name it always requires.
        always = set(re.search(r'case "\$sub" in\n\s+([a-z|-]+)\)', shell_function('cmd_mount')).group(1).split('|'))
        self.assertEqual({name for name, _ in specs} - always, {'notes'})

    def test_the_notes_folder_is_the_one_cc_notes_and_the_marker_name(self):
        notes = (ROOT / 'roles/controlclaw/files/cc-notes').read_text()
        self.assertIn('BASE=/var/lib/controlclaw-notes', notes)
        self.assertIn('mountpoint -q "$BASE"', notes)
        tasks = (ROOT / 'roles/controlclaw/tasks/shared-notes.yml').read_text()
        self.assertIn('mountpoint -q /var/lib/controlclaw-notes', tasks)

    def test_the_daemon_is_ready_after_exit_3_and_after_nothing_else(self):
        daemon = (ROOT / 'roles/controlclaw/files/cc-secure-daemon').read_text()
        finish = re.search(r'const finish = \(\) => \{.*?\n  \};\n', daemon, re.S).group(0)
        self.assertIn('const MOUNT_OPTIONAL_FAILED = 3;', daemon)
        self.assertIn('if (mounted.status !== 0 && mounted.status !== MOUNT_OPTIONAL_FAILED) {', finish)
        self.assertLess(finish.index('throw new Error'), finish.index('notify("READY=1")'))
        self.assertIn('not everything in it could be mounted:', finish)
        # The play accepts the same code, so an Update does not fail on it.
        self.assertIn('failed_when: cc_secure_mount.rc not in [0, 3]', TASKS)

    def test_the_daemon_sends_on_what_mount_says_whatever_it_exits_with(self):
        daemon = (ROOT / 'roles/controlclaw/files/cc-secure-daemon').read_text()
        mount_now = re.search(r'^function mountNow\(\) \{.*?^\}\n', daemon, re.S | re.M).group(0)
        # Written to the journal before the exit code is looked at.
        self.assertIn('if (said) process.stderr.write(said);', mount_now)
        self.assertLess(mount_now.index('process.stderr.write(said)'), mount_now.index('return {'))
        self.assertIn('spawnSync', daemon.split('require("node:child_process")')[0].split('\n')[-1])

    def test_the_tang_repair_and_cc_fw_repair_do_not_call_exit_3_a_failure(self):
        daemon = (ROOT / 'roles/controlclaw/files/cc-secure-daemon').read_text()
        self.assertIn('if (e.code !== MOUNT_OPTIONAL_FAILED) log(`could not restart tang', daemon)
        repair = (ROOT / 'roles/controlclaw/files/cc-fw-repair').read_text()
        self.assertRegex(repair, r'if code == 3:\n\s+print\("mounted, without the optional directories named above"')

    def test_the_daemon_waits_longer_than_a_bind_can_take(self):
        daemon = (ROOT / 'roles/controlclaw/files/cc-secure-daemon').read_text()
        wait_ms = int(re.search(r'const SH_TIMEOUT_MS = ([\d_]+);', daemon).group(1).replace('_', ''))
        lock = int(re.search(r'LOCK_WAIT_S=\$\{CC_SECURE_LOCK_WAIT_S:-(\d+)\}', CC_SECURE).group(1))
        bind = int(re.search(r'BIND_TIMEOUT_S=\$\{CC_SECURE_BIND_TIMEOUT_S:-(\d+)\}', CC_SECURE).group(1))
        # Lock wait, the bind, stopping it (3 s, then 10 s), and a minute for two key derivations.
        self.assertGreater(wait_ms / 1000, lock + bind + 13 + 60)

    def test_every_entry_failing_still_starts_tang(self):
        d0 = tempfile.mkdtemp(prefix='cc-mount-dst-')
        self.addCleanup(shutil.rmtree, d0, ignore_errors=True)
        r, calls, _ = self.mount(f'a:{d0}/a:ghost:0750 b:{d0}/b:ghost:0750')
        self.assertEqual(r.returncode, 1)
        self.assertIn(f'could not be mounted: {d0}/a {d0}/b', r.stderr)
        self.assertIn('systemctl start tangd.socket', calls)


class Sudoers(unittest.TestCase):
    def lines(self):
        return [l.strip() for l in TASKS.split('\n') if '/usr/local/bin/cc-secure' in l and 'NOPASSWD' in l]

    def test_size_takes_no_argument_and_grow_takes_one_to_four_digits(self):
        lines = self.lines()
        self.assertIn('{{ controlclaw_user }} ALL=(ALL) NOPASSWD: /usr/local/bin/cc-secure size', lines)
        grow = [l for l in lines if ' ^grow ' in l]
        self.assertEqual(len(grow), 1)
        pattern = grow[0].split('/usr/local/bin/cc-secure ', 1)[1]
        self.assertEqual(pattern, '^grow [0-9]{1,4}$')
        # sudo matches the pattern against the arguments joined by one space.
        rx = re.compile(pattern)
        for ok in ('grow 1', 'grow 30', 'grow 9999'):
            self.assertRegex(ok, rx)
        for bad in ('grow', 'grow ', 'grow 12345', 'grow 30 x', 'grow -5', 'grow 3.5', 'grow 30;id', 'grow 30\nrekey', 'size', 'grow x', 'init', ' grow 30', 'grow  30'):
            self.assertIsNone(rx.fullmatch(bad), bad)
            self.assertIsNone(rx.match(bad) if '\n' not in bad else None, bad)

    def test_the_two_lines_are_for_agent_boxes_only(self):
        block = TASKS[TASKS.index("{% if box_role == 'openclaw' %}", TASKS.index('controlclaw-secure')):]
        block = block[:block.index('{% endif %}')]
        self.assertIn('cc-secure size', block)
        self.assertIn('cc-secure ^grow', block)

    def test_nothing_else_about_the_container_was_opened_to_the_box_user(self):
        allowed = sorted(l.split('/usr/local/bin/cc-secure ', 1)[1] for l in self.lines())
        self.assertEqual(allowed, sorted(['status', 'list', 'thumbprint', 'bind *', 'unbind *', 'rekey', r'^reseal [A-Za-z0-9+/]{43}\=$', 'size', '^grow [0-9]{1,4}$']))

    def test_the_file_says_which_sudo_the_pattern_needs(self):
        self.assertIn('sudo 1.9.10', TASKS)

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
