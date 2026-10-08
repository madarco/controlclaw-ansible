#!/usr/bin/env python3
"""What cc-reprovision tells the console about a failed run (T-updfail).

Run from the repo root: python3 -m unittest tests/test_cc_reprovision_failure.py

The function is cut out of the script and run with bash, so the test exercises the shipped text.
"""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = (Path(__file__).resolve().parents[1] / 'roles/controlclaw/files/cc-reprovision').read_text()
FUNC = re.search(r'^failure_detail\(\) \{\n.*?^\}\n', SCRIPT, re.S | re.M).group(0)

# The tail of a first provisioning, as every box's log begins.
PROVISIONING = """TASK [Create cloud-init completion marker] *************************************
changed: [localhost]

TASK [Provisioning complete] ***************************************************
ok: [localhost] => {
    "msg": "ControlClaw VM provisioning complete!"
}

PLAY RECAP *********************************************************************
localhost                  : ok=420  changed=180  unreachable=0    failed=0    skipped=60
"""

# ansible-pull's checkout failing, as it reached the log on a dev agent (2026-10-08).
FETCH_FAILED = """Starting Ansible Pull at 2026-10-08 10:05:22
/usr/bin/ansible-pull --full -U https://github.com/madarco/controlclaw-ansible-test.git -C main playbook.yml -e {"vm_id": "j9926"}
Nothing to do. All requested collections are already installed.
[WARNING]: Could not match supplied host pattern, ignoring: oc-j9926t5z
localhost | FAILED! => {
    "changed": false,
    "cmd": [
        "/usr/bin/git",
        "fetch",
        "--tags",
        "origin"
    ],
    "msg": "Failed to download remote objects and refs:  fatal: unable to access 'https://github.com/madarco/controlclaw-ansible-test.git/': The requested URL returned error: 403\\n"
}
"""

TASK_FAILED = """Starting Ansible Pull at 2026-10-08 09:45:44
PLAY [Provision ControlClaw VM] ************************************************

TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [controlclaw : Install OpenClaw globally from npm] ************************
fatal: [localhost]: FAILED! => {"changed": true, "msg": "non-zero return code", "rc": 254}
"""


def detail(before: str, run: str, rc: int = 2) -> str:
    with tempfile.NamedTemporaryFile('w', suffix='.log') as log:
        log.write(before)
        log.flush()
        start = len(before.encode())
        log.write(run)
        log.flush()
        return subprocess.run(['bash', '-c', FUNC + f'failure_detail "$1" "$2" "$3"', '_', log.name, str(start), str(rc)],
                              check=True, capture_output=True, text=True).stdout


class FailureDetail(unittest.TestCase):
    def test_a_failed_fetch_is_not_reported_as_the_last_provisioning_task(self):
        out = detail(PROVISIONING, FETCH_FAILED)
        self.assertNotIn('Provisioning complete', out)
        self.assertTrue(out.startswith('could not fetch the update (ansible-pull exited 2 before the playbook started): '), out)
        self.assertIn('The requested URL returned error: 403', out)
        self.assertNotIn('\n', out)

    def test_a_failed_task_names_the_task_of_this_run(self):
        self.assertEqual(detail(PROVISIONING, TASK_FAILED, 2), 'ansible-pull exited 2 at: controlclaw : Install OpenClaw globally from npm')

    def test_an_earlier_failed_run_is_not_reported_again(self):
        self.assertEqual(detail(PROVISIONING + TASK_FAILED, FETCH_FAILED)[:26], 'could not fetch the update')

    def test_a_run_with_no_output_still_says_something(self):
        self.assertEqual(detail(PROVISIONING, '', 1), 'could not fetch the update (ansible-pull exited 1 before the playbook started)')

    def test_a_missing_log_reads_as_empty(self):
        out = subprocess.run(['bash', '-c', FUNC + 'failure_detail /nonexistent/log 0 2'], check=True, capture_output=True, text=True).stdout
        self.assertEqual(out, 'could not fetch the update (ansible-pull exited 2 before the playbook started)')


if __name__ == '__main__':
    unittest.main()
