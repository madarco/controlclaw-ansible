#!/usr/bin/env python3
"""The daemon keeps its disk-state port for its whole life on an agent (pairing follow-up).

Run from the repo root: python3 -m unittest tests/test_disk_state_port.py

Caddy sends /__cc/disk/* to 127.0.0.1:3101 whether the disk is locked or open. The daemon used to
close that port once the disk opened, so any process on the box could bind it and answer "locked"
for an open disk, and the console asks that port about an agent it has no report from. The
listener is cut out of the shipped daemon and run with node, so the test exercises the shipped text.
"""
import json
import re
import shutil
import socket
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DAEMON = (ROOT / 'roles/controlclaw/files/cc-secure-daemon').read_text()
SERVE = re.search(r'^function serveDisk\(\) \{.*?^\}\n', DAEMON, re.S | re.M).group(0)

HARNESS = textwrap.dedent("""
    const http = require("http");
    const net = require("net");
    const LOCKED_PORT = Number(process.env.PORT);
    const ROLE = process.env.ROLE;
    const log = () => {};
    %s
    const get = (path, method = "GET") => new Promise((resolve) => {
      const req = http.request({ host: "127.0.0.1", port: LOCKED_PORT, path, method }, (res) => {
        let raw = ""; res.on("data", (c) => raw += c); res.on("end", () => resolve([res.statusCode, JSON.parse(raw)]));
      });
      req.on("error", (e) => resolve(["error", e.code])); req.end();
    });
    const taken = () => new Promise((resolve) => {
      const probe = net.createServer();
      probe.once("error", () => resolve(true));
      probe.listen(LOCKED_PORT, "127.0.0.1", () => probe.close(() => resolve(false)));
    });
    (async () => {
      const disk = serveDisk();
      await new Promise((r) => setTimeout(r, 200));
      const out = {};
      out.starting = await get("/disk/status");
      disk.lock((req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ locked: true })); });
      out.locked = [disk.isLocked(), await get("/disk/status")];
      disk.open();
      await new Promise((r) => setTimeout(r, 200));
      out.open = [disk.isLocked(), await get("/disk/status"), await get("/disk/unlock", "POST"), await get("/other")];
      out.taken = await taken();
      console.log(JSON.stringify(out));
      process.exit(0);
    })();
""") % SERVE


@unittest.skipUnless(shutil.which('node'), 'needs node')
class DiskStatePort(unittest.TestCase):
    def run_as(self, role):
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False) as f:
            f.write(HARNESS)
        done = subprocess.run(['node', f.name], env={'PORT': str(port), 'ROLE': role, 'PATH': '/usr/bin:/bin:/usr/local/bin'},
                              capture_output=True, text=True, timeout=30)
        Path(f.name).unlink()
        self.assertEqual(done.returncode, 0, done.stderr)
        return json.loads(done.stdout)

    def test_an_agent_keeps_the_port_and_answers_open(self):
        for role in ['openclaw', 'gbrain']:
            out = self.run_as(role)
            # Before the first open attempt it is bound too, and does not claim to be locked.
            self.assertEqual(out['starting'], [200, {'locked': False, 'role': role}])
            self.assertEqual(out['locked'], [True, [200, {'locked': True}]])
            # Open: the same port answers that it is open, takes no passphrase, and nobody else can bind it.
            self.assertEqual(out['open'][0], False)
            self.assertEqual(out['open'][1], [200, {'locked': False, 'role': role}])
            self.assertEqual(out['open'][2][0], 409)
            self.assertEqual(out['open'][3][0], 404)
            self.assertTrue(out['taken'])

    def test_a_firewall_lets_go_of_it_for_the_ai_judge(self):
        out = self.run_as('mitm')
        self.assertEqual(out['locked'], [True, [200, {'locked': True}]])
        self.assertEqual(out['open'][1][0], 'error')
        self.assertFalse(out['taken'])

    def test_the_firewall_judge_and_the_daemon_share_the_port_by_default(self):
        # The reason for the exception: if either default moves, the exception may be dropped.
        addon = (ROOT / 'roles/controlclaw/files/mitm-proxy/addon.py').read_text()
        self.assertIn('http://127.0.0.1:3101/judge', addon)
        self.assertIn('process.env.CC_LOCKED_PORT || 3101', DAEMON)

    def test_main_never_closes_the_listener_itself(self):
        main = re.search(r'^async function main\(\) \{.*?^\}\n', DAEMON, re.S | re.M).group(0)
        self.assertIn('const disk = serveDisk();', main)
        self.assertIn('disk.open();', main)
        self.assertNotIn('.close()', main)


if __name__ == '__main__':
    unittest.main()
