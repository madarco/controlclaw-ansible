"""Unit tests for roles/controlclaw/files/cc-proxy-routes.py (controlclaw T-105).

Run from the repo root: python3 -m unittest tests/test_cc_proxy_routes.py
"""
import importlib.machinery
import importlib.util
import pathlib
import sys
import unittest

# No __pycache__ next to the role's files: the role copies that directory's contents by name.
sys.dont_write_bytecode = True

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "roles/controlclaw/files/cc-proxy-routes.py"
loader = importlib.machinery.SourceFileLoader("cc_proxy_routes", str(SCRIPT))
spec = importlib.util.spec_from_loader("cc_proxy_routes", loader)
routes = importlib.util.module_from_spec(spec)
loader.exec_module(routes)

LEGACY = ".vm.controlclaw.com"


def box(host, ip, domain=None, created="2026-09-30T10:00:00+00:00", role="agent", name=None):
    labels = {"cc-role": role, "cc-host": host}
    if domain is not None:
        labels["cc-domain"] = domain
    return {"name": name or host, "labels": labels, "created": created, "public_net": {"ipv4": {"ip": ip}}}


def lines(content):
    return content.splitlines()


class BuildMap(unittest.TestCase):
    def setUp(self):
        self.allowed = routes.allowed_domains(routes.normalize_domain(LEGACY), "vm.controlclaw.com,ccl.bot")

    def test_a_box_without_cc_domain_keeps_the_legacy_name(self):
        out = routes.build_map([box("marcobot", "192.0.2.1")], LEGACY, self.allowed)
        self.assertEqual(lines(out), ["marcobot.vm.controlclaw.com 192.0.2.1"])

    def test_old_call_shape_still_works(self):
        # No allow-list passed: exactly what the script did before T-105.
        self.assertEqual(routes.build_map([box("a", "192.0.2.1")], LEGACY), "a.vm.controlclaw.com 192.0.2.1\n")

    def test_a_box_names_its_own_domain(self):
        out = routes.build_map(
            [box("newbot", "192.0.2.2", "ccl.bot"), box("mitm-ab12cd34", "192.0.2.3", "ccl.bot", role="mitm"), box("oldbot", "192.0.2.4")],
            LEGACY,
            self.allowed,
        )
        self.assertEqual(
            lines(out),
            ["mitm-ab12cd34.ccl.bot 192.0.2.3", "newbot.ccl.bot 192.0.2.2", "oldbot.vm.controlclaw.com 192.0.2.4"],
        )

    def test_the_legacy_suffix_named_explicitly_is_the_same_route(self):
        out = routes.build_map([box("rebuilt", "192.0.2.5", "vm.controlclaw.com")], LEGACY, self.allowed)
        self.assertEqual(lines(out), ["rebuilt.vm.controlclaw.com 192.0.2.5"])

    def test_a_domain_not_on_the_list_is_dropped(self):
        out = routes.build_map([box("evil", "192.0.2.6", "example.com"), box("ok", "192.0.2.7", "ccl.bot")], LEGACY, self.allowed)
        self.assertEqual(lines(out), ["ok.ccl.bot 192.0.2.7"])

    def test_the_default_suffix_is_always_allowed(self):
        allowed = routes.allowed_domains("vm.controlclaw.com", "")
        self.assertEqual(allowed, {"vm.controlclaw.com"})
        out = routes.build_map([box("new", "192.0.2.8", "ccl.bot"), box("old", "192.0.2.9")], LEGACY, allowed)
        self.assertEqual(lines(out), ["old.vm.controlclaw.com 192.0.2.9"])

    def test_cc_host_cannot_carry_a_domain(self):
        out = routes.build_map([box("evil.example.com", "192.0.2.10"), box("-x", "192.0.2.11"), box("fine", "192.0.2.12")], LEGACY, self.allowed)
        self.assertEqual(lines(out), ["fine.vm.controlclaw.com 192.0.2.12"])

    def test_labels_are_case_and_dot_insensitive(self):
        out = routes.build_map([box("MixedCase", "192.0.2.13", ".CCL.bot.")], LEGACY, self.allowed)
        self.assertEqual(lines(out), ["mixedcase.ccl.bot 192.0.2.13"])

    def test_the_same_handle_on_two_domains_is_two_routes(self):
        # Handles are unique across domains in the control plane; if two boxes ever did share one,
        # each name still goes to its own box rather than one overwriting the other.
        out = routes.build_map([box("same", "192.0.2.14"), box("same", "192.0.2.15", "ccl.bot")], LEGACY, self.allowed)
        self.assertEqual(lines(out), ["same.ccl.bot 192.0.2.15", "same.vm.controlclaw.com 192.0.2.14"])

    def test_duplicates_keep_the_newest(self):
        out = routes.build_map(
            [
                box("dup", "192.0.2.16", "ccl.bot", created="2026-09-30T10:00:00+00:00"),
                box("dup", "192.0.2.17", "ccl.bot", created="2026-09-30T11:00:00+00:00"),
            ],
            LEGACY,
            self.allowed,
        )
        self.assertEqual(lines(out), ["dup.ccl.bot 192.0.2.17"])

    def test_invalid_allowed_entries_are_ignored(self):
        allowed = routes.allowed_domains("vm.controlclaw.com", " ccl.bot , ,bot,*.x.com,.cclbot.dev")
        self.assertEqual(allowed, {"vm.controlclaw.com", "ccl.bot", "cclbot.dev"})

    def test_boxes_without_host_or_ip_are_skipped(self):
        servers = [box("", "192.0.2.18"), {"labels": {"cc-host": "noip"}, "public_net": {"ipv4": None}}]
        self.assertEqual(routes.build_map(servers, LEGACY, self.allowed), "")


if __name__ == "__main__":
    unittest.main()
