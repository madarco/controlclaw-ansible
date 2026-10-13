#!/usr/bin/env python3
"""An automatic update does not reboot a box whose encrypted disk has no partner yet.

Run from the repo root: python3 -m unittest tests/test_cc_reprovision_pairing.py

The function is cut out of the script and run with bash, so the test exercises the shipped text.
"""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = (Path(__file__).resolve().parents[1] / 'roles/controlclaw/files/cc-reprovision').read_text()
FUNC = re.search(r'^disk_has_partner\(\) \{\n.*?^\}\n', SCRIPT, re.S | re.M).group(0)


def has_partner(image: bool, listing: str, fails: bool = False, role: str = 'openclaw', given: str | None = None) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        img = Path(tmp) / 'secure.img'
        if image:
            img.write_text('x')
        fake = Path(tmp) / 'cc-secure'
        fake.write_text('#!/bin/bash\n[ "$1" = list ] || exit 2\n' + ('exit 1\n' if fails else f"printf '%s' {listing!r}\n"))
        fake.chmod(0o755)
        state = Path(tmp) / 'secure' / 'state'
        state.mkdir(parents=True)
        if given is not None:
            (state / 'tang-partners.json').write_text(given)
        run = subprocess.run(['bash', '-c', FUNC + 'disk_has_partner'], env={'CC_SECURE_IMG': str(img), 'CC_SECURE': str(fake), 'CC_SECURE_MOUNT': str(Path(tmp) / 'secure'), 'ROLE': role, 'PATH': '/usr/bin:/bin'})
        return run.returncode == 0


class DiskHasPartner(unittest.TestCase):
    def test_a_box_with_no_encrypted_disk_is_rebooted_as_before(self):
        self.assertTrue(has_partner(image=False, listing=''))

    def test_a_new_box_with_no_partner_bound_is_not_rebooted(self):
        self.assertFalse(has_partner(image=True, listing=''))

    def test_a_paired_box_is_rebooted(self):
        self.assertTrue(has_partner(image=True, listing='{"slot": 1, "url": "http://10.0.0.2:3920", "thp": "abc", "known": true}\n'))

    def test_a_box_whose_slots_cannot_be_read_is_not_rebooted(self):
        # Locked, or cc-secure failing: nothing says a partner could open it, so no reboot is started.
        self.assertFalse(has_partner(image=True, listing='', fails=True))

    def test_a_firewall_with_no_agent_has_no_partner_by_design_and_is_rebooted(self):
        self.assertTrue(has_partner(image=True, listing='', role='mitm', given='[]'))
        self.assertTrue(has_partner(image=True, listing='', role='mitm', given='[ ]\n'))

    def test_a_firewall_that_was_given_partners_and_bound_none_is_not_rebooted(self):
        self.assertFalse(has_partner(image=True, listing='', role='mitm', given='[{"ip": "10.0.0.3", "name": "a1"}]'))
        # Never told its list (a new firewall), or a list that cannot be read: not known, so not rebooted.
        self.assertFalse(has_partner(image=True, listing='', role='mitm'))
        self.assertFalse(has_partner(image=True, listing='', role='mitm', given='not json'))

    def test_an_agent_is_never_excused_by_an_empty_list(self):
        self.assertFalse(has_partner(image=True, listing='', role='openclaw', given='[]'))
        self.assertFalse(has_partner(image=True, listing='', role='gbrain', given='[]'))

    def test_the_script_asks_before_it_reboots(self):
        asks = SCRIPT.index('! disk_has_partner')
        self.assertLess(asks, SCRIPT.index('systemctl reboot'))
        self.assertIn('not rebooting yet', SCRIPT[asks:SCRIPT.index('systemctl reboot')])


if __name__ == '__main__':
    unittest.main()
