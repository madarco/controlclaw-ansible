"""cc-disk-cleanup (T-diskcleanup): what it may touch, and that it stands down during an Update."""
import os
import re
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "roles/controlclaw/files/cc-disk-cleanup"
TASKS = ROOT / "roles/controlclaw/tasks/disk-space.yml"
BROWSER = ROOT / "roles/controlclaw/files/browser-stream.sh"


def body() -> str:
    # The code, without the comments that name what is never touched.
    return "\n".join(l for l in SCRIPT.read_text().splitlines() if not l.lstrip().startswith("#"))


def test_never_touches_the_container_or_openclaw_state():
    code = body()
    for forbidden in (".openclaw", "/opt/controlclaw/secure", "workspace", "Cookies", "Local Storage",
                      "IndexedDB", "Login Data"):
        assert forbidden not in code, forbidden


def test_leaves_chrome_apt_lists_and_the_rollback_copy():
    code = body()
    assert ".chrome" not in code and "Service Worker" not in code
    assert "/var/lib/apt/lists" not in code
    assert ".cc-openclaw-previous" not in code


def test_an_update_stops_a_running_cleanup():
    reprov = (ROOT / "roles/controlclaw/files/cc-reprovision").read_text()
    assert "systemctl stop cc-disk-cleanup.service" in reprov


def test_connector_image_only_on_a_recorded_agent():
    code = body()
    assert '[ "$BOX_ROLE" = openclaw ]' in code
    assert "/etc/controlclaw/pool-unclaimed" in code
    tasks = TASKS.read_text()
    assert "(vm_id | default('')) != 'image-build'" in tasks
    assert "BOX_ROLE={{ box_role }}" in tasks


def test_low_priority_unit_and_chrome_cache_cap():
    tasks = TASKS.read_text()
    assert "Nice=19" in tasks and "IOSchedulingPriority=7" in tasks
    assert "--disk-cache-size=268435456" in BROWSER.read_text()


def _stub(dir: Path, name: str, script: str):
    p = dir / name
    p.write_text("#!/bin/bash\n" + script + "\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


def test_stands_down_while_an_update_runs(tmp_path):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    # systemctl says cc-reprovision is active; anything that would delete must not be reached.
    _stub(bin_, "systemctl", '[ "$*" = "is-active -q cc-reprovision.service" ] && exit 0; exit 1')
    for tool in ("rm", "docker", "apt-get", "snap", "find", "npm"):
        _stub(bin_, tool, f'echo CALLED-{tool} >&2; exit 99')
    env = dict(os.environ, PATH=f"{bin_}:{os.environ['PATH']}", CC_DISK_CLEANUP_CONF=str(tmp_path / "none"))
    out = subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True)
    assert out.returncode == 0
    assert "skipped: something is installing" in out.stdout
    assert "CALLED-" not in out.stderr
