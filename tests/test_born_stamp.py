"""The born stamp (roles/controlclaw/tasks/main.yml, cc-pool-local.cjs): who writes it, and when.

The role's own condition is read out of main.yml and evaluated here for every kind of run, so the
test fails if the condition changes, not only if this file does. Run: python3 -m unittest tests/test_born_stamp.py
"""
import pathlib
import unittest

import jinja2
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
TASKS = yaml.safe_load((ROOT / "roles/controlclaw/tasks/main.yml").read_text())
POOL = (ROOT / "roles/controlclaw/files/cc-pool-local.cjs").read_text()


def task(name):
    return next(t for t in TASKS if t.get("name") == name)


def truthy(value):
    return str(value).strip().lower() in ("true", "yes", "1") if not isinstance(value, bool) else value


ENV = jinja2.Environment(undefined=jinja2.StrictUndefined)
ENV.filters["bool"] = truthy
FACT = task("Born stamp | is this the first provisioning of a box for its organization")["ansible.builtin.set_fact"]["cc_born_now"]


def writes(box_role="openclaw", vm_id="vm-abc", pool_unclaimed=None, release=False, identity=False):
    """Whether a run of the role with these facts writes the stamp."""
    facts = {
        "box_role": box_role,
        "vm_id": vm_id,
        "cc_born_release": {"stat": {"exists": release}},
        "cc_born_identity": {"stat": {"exists": identity}},
    }
    if pool_unclaimed is not None:
        facts["pool_unclaimed"] = pool_unclaimed
    return truthy(ENV.from_string(FACT).render(**facts))


class BornStamp(unittest.TestCase):
    def test_a_real_first_provisioning_writes_it(self):
        # From the base image: release.json and the keys were scrubbed, the update pin was not.
        self.assertTrue(writes())
        self.assertTrue(writes(box_role="mitm"))
        self.assertTrue(writes(box_role="gbrain"))

    def test_the_image_build_never_writes_it(self):
        # The three passes of the build (base-image.ts), on a disk with nothing on it yet.
        for role in ("mitm", "gbrain", "openclaw"):
            self.assertFalse(writes(box_role=role, vm_id="image-build"), role)

    def test_an_update_never_writes_it(self):
        self.assertFalse(writes(release=True, identity=True))
        # An agent from before release.json existed, on its first Update: it has its keys.
        self.assertFalse(writes(release=False, identity=True))
        # A release record with no keys (a restore in progress) is not a first provisioning either.
        self.assertFalse(writes(release=True, identity=False))

    def test_a_pool_box_gets_none_when_it_is_warmed(self):
        self.assertFalse(writes(pool_unclaimed=True))
        self.assertFalse(writes(pool_unclaimed="true"))
        # After the claim it is a box like any other: its Updates write nothing.
        self.assertFalse(writes(pool_unclaimed=False, release=True, identity=True))

    def test_other_roles_get_none(self):
        self.assertFalse(writes(box_role="proxy"))
        self.assertFalse(writes(box_role="exit-relay"))

    def test_the_condition_does_not_go_by_the_update_pin(self):
        # update.conf is written during the image build and stays in the image.
        stats = [t["ansible.builtin.stat"]["path"] for t in TASKS if t.get("name", "").startswith("Born stamp |") and "ansible.builtin.stat" in t]
        self.assertEqual(sorted(stats), ["/etc/controlclaw/release.json", "/opt/controlclaw/keys/vm_id"])

    def test_the_write_keeps_a_stamp_that_is_there_and_is_roots(self):
        write = task("Born stamp | record when this box was born (first provisioning only)")
        copy = write["ansible.builtin.copy"]
        self.assertEqual([copy["dest"], copy["owner"], copy["group"], copy["mode"], copy["force"]], ["/etc/controlclaw/born", "root", "root", "0644", False])
        self.assertEqual(write["when"], "cc_born_now | bool")

    def test_it_is_in_a_folder_only_root_can_write(self):
        folder = task("Born stamp | make sure its folder exists and is root's")["ansible.builtin.file"]
        self.assertEqual([folder["path"], folder["owner"], folder["group"], folder["mode"]], ["/etc/controlclaw", "root", "root", "0755"])
        # No task of the role makes that folder anybody else's, or writable by group or others.
        for path in sorted((ROOT / "roles/controlclaw/tasks").glob("*.yml")):
            for t in yaml.safe_load(path.read_text()) or []:
                for block in [t] + (t.get("block") or []):
                    spec = block.get("ansible.builtin.file") if isinstance(block, dict) else None
                    if isinstance(spec, dict) and spec.get("path") == "/etc/controlclaw":
                        self.assertEqual(spec.get("owner", "root"), "root", path.name)
                        self.assertEqual(int(str(spec.get("mode", "0755")), 8) & 0o022, 0, path.name)

    def test_it_is_decided_before_this_play_writes_the_keys_or_the_release(self):
        names = [t.get("name", "") for t in TASKS]
        decided = names.index("Born stamp | record when this box was born (first provisioning only)")
        # Before every include that provisions the box: only the node environment facts come first.
        first_include = next(i for i, t in enumerate(TASKS) if "ansible.builtin.include_tasks" in t)
        self.assertLess(decided, first_include)
        self.assertEqual(names[-1], "Record the installed release")

    def test_the_pool_claim_writes_it_before_the_agent_is_restarted(self):
        activate = POOL[POOL.index("function activate(vars)"):]
        stamp = activate.index("write('/etc/controlclaw/born'")
        # Whatever is there: a stamp on an unclaimed box could only be an image's or a warm's.
        self.assertNotIn("existsSync('/etc/controlclaw/born')", activate)
        # And only for a box that is still unclaimed, which is true once.
        self.assertLess(activate.index("!fs.existsSync('/etc/controlclaw/pool-unclaimed')) throw"), stamp)
        self.assertLess(stamp, activate.index("fs.unlinkSync('/etc/controlclaw/pool-unclaimed')"))
        self.assertLess(stamp, activate.index("'systemctl', 'restart'"))
        # Nothing else in the role's files writes it.
        others = [p.name for p in (ROOT / "roles/controlclaw/files").glob("cc-*") if p.is_file() and p.name != "cc-pool-local.cjs" and "/etc/controlclaw/born" in p.read_text(errors="ignore")]
        self.assertEqual(others, [])


if __name__ == "__main__":
    unittest.main()
