#!/usr/bin/env python3
"""Root trust migration regressions. Run with sudo python3 -m unittest tests/test_doctor_trust.py."""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

FILE = Path(__file__).resolve().parents[1] / 'roles/controlclaw/files/cc-doctor-trust'
loader = importlib.machinery.SourceFileLoader('trust', str(FILE))
spec = importlib.util.spec_from_loader(loader.name, loader)
trust = importlib.util.module_from_spec(spec)
loader.exec_module(trust)


class TrustTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.patches = [patch.object(trust, name, root / name) for name in ['ROOT_VARS', 'PIN', 'SOURCE', 'PRIVATE']]
        for item in self.patches:
            item.start()
        self.addCleanup(lambda: [item.stop() for item in self.patches])
        self.addCleanup(self.tmp.cleanup)
        private = subprocess.check_output(['openssl', 'genpkey', '-algorithm', 'ed25519'], stderr=subprocess.DEVNULL)
        self.pub = subprocess.check_output(['openssl', 'pkey', '-pubout'], input=private, stderr=subprocess.DEVNULL).decode()
        self.original = {'vm_id': 'original-agent', 'mitm_vm_public_key': self.pub,
                         'mitm_box_private_ip': '10.23.0.2', 'config_api_url': 'https://trusted.example/api/vm-agent/config',
                         'vm_bootstrap_token': 'root-bootstrap'}
        self.write_original()

    def write_original(self):
        trust.ROOT_VARS.write_text(json.dumps(self.original))
        trust.ROOT_VARS.chmod(0o600)

    def install(self):
        with contextlib.redirect_stdout(io.StringIO()):
            trust.install()

    def test_mutable_environment_cannot_select_firewall(self):
        with patch.dict(os.environ, {'MITM_IP': '127.0.0.1', 'MITM_PUB': 'evil', 'CONFIG_URL': 'https://evil.example'}):
            self.install()
        self.assertEqual(trust.PIN.read_text(), self.pub)
        self.assertEqual(trust.SOURCE.read_text().strip(), '10.23.0.2')

    def test_existing_identity_survives_changed_update_vars(self):
        self.install()
        self.original.update(mitm_box_private_ip='127.0.0.1', mitm_vm_public_key='evil')
        self.write_original()
        self.install()
        self.assertEqual(trust.SOURCE.read_text().strip(), '10.23.0.2')
        self.assertEqual(trust.PIN.read_text(), self.pub)

    def test_service_writable_root_record_refused(self):
        trust.ROOT_VARS.chmod(0o666)
        with self.assertRaises(ValueError):
            self.install()
        self.assertFalse(trust.PIN.exists())

    def test_root_record_symlink_refused(self):
        target = trust.ROOT_VARS.with_suffix('.real')
        trust.ROOT_VARS.rename(target)
        trust.ROOT_VARS.symlink_to(target)
        with self.assertRaises(OSError):
            self.install()

    def test_legacy_first_agent_fetches_original_vm_scoped_ca(self):
        self.original['mitm_vm_public_key'] = ''
        self.write_original()
        trust.PRIVATE.touch()
        with patch.object(trust, 'token', return_value='signed-original') as sign, patch.object(trust, 'request', return_value={'pubKey': self.pub, 'privateIp': '10.23.0.3'}) as request:
            self.install()
        sign.assert_called_once_with('original-agent')
        request.assert_called_once_with('https://trusted.example/api/vm-agent/ca', 'signed-original')
        self.assertEqual(trust.SOURCE.read_text().strip(), '10.23.0.3')

    def test_firstboot_fetches_using_original_bootstrap(self):
        self.original['mitm_vm_public_key'] = ''
        self.write_original()
        with patch.object(trust, 'request', return_value={'publicKey': self.pub}) as request:
            self.install()
        request.assert_called_once_with('https://trusted.example/api/vm-agent/doctor-pin', 'root-bootstrap', {'vmId': 'original-agent'})

    def test_missing_original_does_not_fall_back_to_mutable_keys(self):
        trust.ROOT_VARS.unlink()
        with self.assertRaises(FileNotFoundError):
            self.install()

    def test_partial_existing_pin_refuses_identity_substitution(self):
        trust.PIN.write_text(self.pub)
        self.original['mitm_vm_public_key'] = subprocess.check_output(['openssl', 'pkey', '-pubout'], input=subprocess.check_output(['openssl', 'genpkey', '-algorithm', 'ed25519'], stderr=subprocess.DEVNULL), stderr=subprocess.DEVNULL).decode()
        self.write_original()
        with self.assertRaises(ValueError):
            self.install()
        self.assertFalse(trust.SOURCE.exists())


if __name__ == '__main__':
    unittest.main()
