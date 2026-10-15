"""The OpenClaw widget sandbox host, sandbox.<vm_hostname> (controlclaw docs/security-design.md,
"The widget sandbox"): what Caddy serves there, how a claim adds the handle, and the origin OpenClaw
is told.

Run from the repo root: python3 -m unittest tests/test_widget_sandbox.py
"""
import json
import pathlib
import re
import subprocess
import tempfile
import unittest
import urllib.parse

import jinja2

ROLE = pathlib.Path(__file__).resolve().parent.parent / "roles/controlclaw"
HOST = "pool-ab12.ccl.bot"


VARS = dict(caddy_acme_email="ops@example.com", config_api_url="https://controlclaw.com/api/vm-agent/config",
            browser_novnc_port=6080, openclaw_gateway_port=18789, openclaw_sandbox_port=18790, luks_locked_port=3101)


def render(alias="", enabled=True, template=None):
    # As Ansible renders templates: trim_blocks on.
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROLE / "templates")), keep_trailing_newline=True, trim_blocks=True)
    env.filters["urlsplit"] = lambda v, part: getattr(urllib.parse.urlsplit(v), part)
    # Ansible's `bool` filter.
    env.filters["bool"] = lambda v: v if isinstance(v, bool) else str(v).strip().lower() in ("yes", "on", "1", "true", "y")
    t = env.from_string(template) if template else env.get_template("Caddyfile.j2")
    return t.render(vm_hostname=HOST, cc_handle_alias=alias, widget_sandbox_enabled=enabled, **VARS)


def claim(caddyfile, handle="mjhtest.ccl.bot"):
    """cc-pool-local.cjs's own claimCaddyfile, run by node on a rendered Caddyfile in a temp dir."""
    with tempfile.TemporaryDirectory() as d:
        path = pathlib.Path(d) / "Caddyfile"
        path.write_text(caddyfile)
        script = (f"const fs=require('fs');const {{claimCaddyfile}}=require({json.dumps(str(ROLE / 'files/cc-pool-local.cjs'))});"
                  f"fs.writeFileSync({json.dumps(str(path))},claimCaddyfile(fs.readFileSync({json.dumps(str(path))},'utf8'),{json.dumps(HOST)},{json.dumps(handle)}))")
        run = subprocess.run(["node", "-e", script], capture_output=True, text=True)
        if run.returncode:
            raise RuntimeError(run.stderr.strip() or "node failed")
        return path.read_text()


def site(caddyfile, name):
    """The body of one site block, by its first line."""
    start = caddyfile.index(f"\n{name} {{")
    depth, i = 0, caddyfile.index("{", start)
    for j in range(i, len(caddyfile)):
        depth += {"{": 1, "}": -1}.get(caddyfile[j], 0)
        if depth == 0:
            return caddyfile[i + 1:j]
    raise AssertionError("unclosed site block")


class SandboxSite(unittest.TestCase):
    def setUp(self):
        self.sandbox = site(render(), f"sandbox.{HOST}")

    def handle(self, matcher):
        return site("\n" + self.sandbox, f"    handle {matcher}" if matcher else "    handle")

    def test_the_shell_only_after_the_vm_agent_check(self):
        shell = self.handle("@shell")
        self.assertIn("forward_auth 127.0.0.1:3100", shell)
        self.assertIn("uri /__cc/sandbox/verify", shell)
        self.assertLess(shell.index("forward_auth"), shell.index("reverse_proxy 127.0.0.1:18790"))
        self.assertIn("path /mcp-app-sandbox\n", self.sandbox)

    def test_no_cookie_goes_to_openclaw_or_comes_back(self):
        for matcher in ("@shell", "@renderer"):
            body = self.handle(matcher)
            for line in ("header_up -Cookie", "header_up -Authorization", "header_down -Set-Cookie"):
                self.assertIn(line, body, matcher)

    def test_framed_only_by_the_dashboard(self):
        self.assertIn(f'header_down +Content-Security-Policy "frame-ancestors https://{HOST}"', self.handle("@shell"))
        claimed = site(render("mjhtest.ccl.bot"), f"sandbox.{HOST}")
        self.assertIn(f'"frame-ancestors https://{HOST} https://mjhtest.ccl.bot"', claimed)

    def test_the_shipped_site_gets_a_public_certificate(self):
        # ACME (Let's Encrypt, then ZeroSSL) like the agent's own name; never the local CA used in a test.
        self.assertNotIn("tls internal", render())
        self.assertNotIn("tls ", self.sandbox)

    def test_public_only_the_two_renderer_bundles_everything_else_404(self):
        self.assertIn("path /__openclaw__/a2ui/a2ui.bundle.js /__openclaw__/a2ui/a2ui-v0.9.bundle.js\n", self.sandbox)
        self.assertNotIn("forward_auth", self.handle("@renderer"))
        self.assertIn("reverse_proxy 127.0.0.1:3100", self.handle("/__cc/sandbox/exchange"))
        self.assertEqual(self.handle("").strip(), "respond 404")
        # Nothing on this host reaches the gateway or the vm-agent's other routes.
        self.assertNotIn("18789", self.sandbox)
        self.assertEqual(len(re.findall(r"reverse_proxy 127\.0\.0\.1:3100", self.sandbox)), 1)


class Claim(unittest.TestCase):
    def test_the_claim_adds_the_handle_to_the_site_and_the_sandbox_ancestors(self):
        claimed = claim(render())
        self.assertIn(f"\n{HOST}, mjhtest.ccl.bot {{", claimed)
        self.assertIn(f"header_up Origin https://{HOST}", claimed)
        self.assertIn(f'"frame-ancestors https://{HOST} https://mjhtest.ccl.bot"', site(claimed, f"sandbox.{HOST}"))
        # The same as rendering with the handle from the start (a later reprovision).
        self.assertEqual(site(claimed, f"sandbox.{HOST}"), site(render("mjhtest.ccl.bot"), f"sandbox.{HOST}"))

    def test_with_the_switch_off_the_claim_is_what_it_was(self):
        claimed = claim(render(enabled=False))
        self.assertIn(f"\n{HOST}, mjhtest.ccl.bot {{", claimed)
        self.assertNotIn("sandbox.", claimed)

    def test_a_sandbox_site_it_cannot_edit_is_refused(self):
        broken = render().replace(f'"frame-ancestors https://{HOST}"', '"frame-ancestors https://elsewhere.example"')
        with self.assertRaisesRegex(RuntimeError, "Caddy sandbox frame-ancestors missing"):
            claim(broken)


class Switch(unittest.TestCase):
    def test_off_by_default(self):
        self.assertIn("\nwidget_sandbox_enabled: false\n", (ROLE / "defaults/main.yml").read_text())

    def test_off_the_caddyfile_is_the_one_before_this_change(self):
        before = subprocess.run(["git", "show", "4059775974f822631d6e63e1935af16740f40dab:roles/controlclaw/templates/Caddyfile.j2"],
                                cwd=ROLE.parent.parent, capture_output=True, text=True)
        if before.returncode:
            self.skipTest("the 1.19.1 commit is not in this clone")
        for alias in ("", "mjhtest.ccl.bot"):
            self.assertEqual(render(alias, enabled=False), render(alias, template=before.stdout), alias)

    def test_off_no_sandbox_origin_and_one_set_earlier_is_cleared(self):
        tasks = (ROLE / "tasks/openclaw.yml").read_text()
        self.assertIn("if (vm_hostname is defined and widget_sandbox_enabled | default(false) | bool)", tasks)
        self.assertIn("""else (',"mcp":{"apps":{"sandboxOrigin":null}}' if openclaw_sandbox_set | bool else '') }}""", tasks)
        self.assertIn("(('https://sandbox.' ~ vm_hostname) if widget_sandbox_enabled | default(false) | bool else '')", tasks)


class OpenClawConfig(unittest.TestCase):
    def test_the_sandbox_origin_is_written_and_checked(self):
        tasks = (ROLE / "tasks/openclaw.yml").read_text()
        self.assertIn("""',"mcp":{"apps":{"sandboxOrigin":"https://sandbox.' ~ vm_hostname ~ '"}}'""", tasks)
        self.assertIn("{{ openclaw_sandbox_json }}}'", tasks)


if __name__ == "__main__":
    unittest.main()
