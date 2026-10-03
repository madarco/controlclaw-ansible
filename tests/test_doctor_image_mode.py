#!/usr/bin/env python3
"""Exercise the actual Doctor trust task's guards with ansible-core, without changing the host."""
import copy
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROLE = Path(__file__).resolve().parents[1] / 'roles/controlclaw/tasks/doctor-agent.yml'
TASK = next(task for task in yaml.safe_load(ROLE.read_text())
            if task.get('ansible.builtin.command') == '/usr/local/bin/cc-doctor-trust')


class DoctorModeTests(unittest.TestCase):
    def run_task(self, variables, skipped, helper='/bin/true', success=True):
        task = copy.deepcopy(TASK)
        # Only replace the helper body. Ansible evaluates the shipped task's actual guards.
        task['ansible.builtin.command'] = helper
        play = [{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
                 'vars': {'ci_test': False, 'vm_id': 'image-build', **variables},
                 'tasks': [task, {'ansible.builtin.assert': {'that': [
                     'doctor_root_trust is skipped' if skipped else 'doctor_root_trust is not skipped'
                 ]}}]}]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'test.yml'
            path.write_text(yaml.safe_dump(play))
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(path)],
                                    cwd=tmp, env={**os.environ, 'ANSIBLE_NOCOLOR': '1'},
                                    text=True, capture_output=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)

    def test_image_agent_pass_bakes_without_a_firewall_identity(self):
        self.run_task({}, skipped=True, helper='/bin/false')

    def test_live_first_boot_installs_trust(self):
        self.run_task({'vm_id': 'agent', 'config_api_url': 'https://control.example/config'}, skipped=False)

    def test_matching_image_still_installs_per_box_trust(self):
        self.run_task({'vm_id': 'agent', 'config_api_url': 'https://control.example/config',
                       'cc_fast_path': True, 'cc_skip': {'doctor': True}}, skipped=False)

    def test_live_update_with_empty_callback_still_fails_closed(self):
        self.run_task({'vm_id': 'agent', 'config_api_url': ''}, skipped=False,
                      helper='/bin/false', success=False)

    def test_live_trust_failure_is_fatal(self):
        self.run_task({'vm_id': 'agent', 'config_api_url': 'https://control.example/config'},
                      skipped=False, helper='/bin/false', success=False)

    def test_ci_install_only_skips_trust(self):
        self.run_task({'ci_test': True, 'config_api_url': 'https://control.example/config'},
                      skipped=True, helper='/bin/false')

    def test_unclaimed_pool_defers_trust_to_claim(self):
        self.run_task({'pool_unclaimed': True, 'config_api_url': 'https://control.example/config'},
                      skipped=True, helper='/bin/false')


if __name__ == '__main__':
    unittest.main()
