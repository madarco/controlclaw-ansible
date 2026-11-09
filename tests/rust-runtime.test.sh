#!/bin/bash
# Tests roles/controlclaw/tasks/rust-runtime.yml: the pinned binaries are installed, anything that is
# not the pinned release fails the run (there is no Node build to go back to), the Node fallback's
# markers and helper are removed, and the units run the release with no OnFailure.
#
#   bash tests/rust-runtime.test.sh          runs itself in a throwaway container (needs docker)
#   bash tests/rust-runtime.test.sh --here   runs on this machine, as root. ONLY in that container:
#                                            it writes /etc/controlclaw and /opt/controlclaw.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

if [ "${1:-}" != "--here" ]; then
  docker build -q -t cc-rust-runtime-test "$HERE/rust-runtime" >/dev/null || exit 1
  exec docker run --rm -v "$REPO:/repo:ro" cc-rust-runtime-test bash /repo/tests/rust-runtime.test.sh --here
fi
[ -f /.dockerenv ] || { echo "run without --here: this writes /etc/controlclaw and /opt/controlclaw"; exit 2; }

fails=0
pass() { echo "ok    $1"; }
fail() { echo "FAIL  $1"; fails=$((fails + 1)); }

# A copy of the repo the test can stage binaries into, and stand-in binaries with their pins.
rm -rf /work && cp -r /repo /work
STAGE=/work/roles/controlclaw/files/rust
mkdir -p "$STAGE"
printf '#!/bin/sh\necho rust vm-agent\n' > "$STAGE/vm-agent-x86_64-linux-musl"
migrate_ok() { printf '#!/bin/sh\necho "{\\"checked\\":0,\\"unreadable\\":0}"\nexit 0\n' > "$STAGE/cc-migrate-x86_64-linux-musl"; }
migrate_ok
sha() { sha256sum "$1" | cut -d' ' -f1; }
pins() {
  cat > /work/roles/controlclaw/vars/rust_release.yml <<YML
cc_rust_release:
  version: "$1"
  commit: "test"
  base_url: "http://127.0.0.1:1/none"
  binaries:
    vm-agent: { asset: "vm-agent-x86_64-linux-musl", sha256: "${2:-$(sha "$STAGE/vm-agent-x86_64-linux-musl")}" }
    cc-migrate: { asset: "cc-migrate-x86_64-linux-musl", sha256: "$(sha "$STAGE/cc-migrate-x86_64-linux-musl")" }
YML
}
fresh() { rm -rf /etc/controlclaw/runtime /opt/controlclaw/agent /opt/controlclaw/mitm /opt/controlclaw/rust /tmp/cc_rust_dir /usr/local/bin/cc-runtime-fallback /etc/systemd/system/cc-runtime-fallback@.service; }
play() { (cd /work && ansible-playbook -i localhost, tests/rust-runtime/play.yml -e cc_rust_source=files "$@" > /tmp/play.log 2>&1); }
# The Node fallback's leftovers, as a box from before this role has them.
leftovers() {
  mkdir -p /etc/controlclaw/runtime /etc/systemd/system
  echo '{"unit":"controlclaw-agent","release":"1.0.0","reason":"crash-loop"}' > /etc/controlclaw/runtime/controlclaw-agent.fallback
  echo '/usr/bin/node /opt/controlclaw/agent/dist/gbrain.js' > /etc/controlclaw/runtime/controlclaw-agent.node-exec
  echo '1.0.0' > /etc/controlclaw/runtime/controlclaw-agent.release
  echo '#!/bin/sh' > /usr/local/bin/cc-runtime-fallback
  echo '[Unit]' > /etc/systemd/system/cc-runtime-fallback@.service
  mkdir -p /opt/controlclaw/agent/dist /opt/controlclaw/mitm/agent/dist /opt/controlclaw/mitm/venv/bin /opt/controlclaw/mitm/proxy
  touch /opt/controlclaw/agent/dist/index.js /opt/controlclaw/agent/dist/gbrain.js /opt/controlclaw/agent/dist/cc-runbook.js /opt/controlclaw/mitm/agent/dist/index.js /opt/controlclaw/mitm/proxy/addon.py
}

fresh; pins 1.0.0
if play && [ "$(cat /tmp/cc_rust_dir)" = /opt/controlclaw/rust/1.0.0 ] \
   && [ -x /opt/controlclaw/rust/1.0.0/vm-agent ] && [ "$(stat -c %U /opt/controlclaw/rust/1.0.0/vm-agent)" = root ] \
   && [ -x /opt/controlclaw/rust/1.0.0/cc-migrate ]; then
  pass "the pinned binaries, root-owned"
else fail "the pinned binaries, root-owned"; tail -20 /tmp/play.log; fi

fresh; leftovers; play
[ $? = 0 ] && [ ! -e /etc/controlclaw/runtime ] && [ ! -e /usr/local/bin/cc-runtime-fallback ] \
  && [ ! -e /etc/systemd/system/cc-runtime-fallback@.service ] \
  && [ ! -e /opt/controlclaw/agent/dist/index.js ] && [ ! -e /opt/controlclaw/agent/dist/gbrain.js ] && [ -e /opt/controlclaw/agent/dist/cc-runbook.js ] \
  && [ ! -e /opt/controlclaw/mitm/agent ] && [ ! -e /opt/controlclaw/mitm/venv ] && [ ! -e /opt/controlclaw/mitm/proxy ] \
  && pass "a box from before: the markers, the helper, its unit and the Node builds go; cc-runbook stays" \
  || { fail "a box from before: the markers, the helper, its unit and the Node builds go; cc-runbook stays"; tail -20 /tmp/play.log; }

fresh; pins 1.0.0 "0000000000000000000000000000000000000000000000000000000000000000"
play
[ $? != 0 ] && [ ! -e /opt/controlclaw/rust/1.0.0/vm-agent ] \
  && pass "a binary that is not the pinned one is removed, and the run fails" \
  || { fail "a binary that is not the pinned one is removed, and the run fails"; tail -20 /tmp/play.log; }
pins 1.0.0

fresh; (cd /work && ansible-playbook -i localhost, tests/rust-runtime/play.yml -e cc_rust_source=release > /tmp/play.log 2>&1)
[ $? != 0 ] && pass "a download that fails fails the run" || fail "a download that fails fails the run"

fresh; play -e ansible_architecture=aarch64
[ $? != 0 ] && [ ! -e /opt/controlclaw/rust ] && pass "another architecture fails the run" || fail "another architecture fails the run"

fresh; mkdir -p /opt/controlclaw/rust/0.9.0 && touch /opt/controlclaw/rust/0.9.0/vm-agent
play
[ ! -e /opt/controlclaw/rust/0.9.0 ] && [ -x /opt/controlclaw/rust/1.0.0/vm-agent ] && pass "older release folders are pruned" || fail "older release folders are pruned"

fresh; leftovers
printf '#!/bin/sh\necho "{\\"checked\\":1,\\"unreadable\\":1}"\nexit 1\n' > "$STAGE/cc-migrate-x86_64-linux-musl"; pins 1.0.0
mkdir -p /opt/controlclaw/rust/0.9.0 && touch /opt/controlclaw/rust/0.9.0/vm-agent
play
[ $? != 0 ] && [ -e /etc/controlclaw/runtime/controlclaw-agent.fallback ] && [ -e /opt/controlclaw/rust/0.9.0/vm-agent ] \
  && pass "stores the Rust build cannot read fail the run, before anything of the old one is removed" \
  || { fail "stores the Rust build cannot read fail the run, before anything of the old one is removed"; tail -20 /tmp/play.log; }
migrate_ok; pins 1.0.0

# The unit vm-agent.yml writes: the release's binary, nothing of the fallback.
python3 - > /tmp/agent-unit.j2 <<'PY'
import yaml
for t in yaml.safe_load(open("/work/roles/controlclaw/tasks/vm-agent.yml")):
    c = t.get("ansible.builtin.copy", {})
    if c.get("dest") == "/etc/systemd/system/controlclaw-agent.service":
        print(c["content"], end="")
PY
(cd /work && ansible localhost -c local -m ansible.builtin.copy \
  -a "dest=/tmp/agent-unit content={{ lookup('template', '/tmp/agent-unit.j2') }}" \
  -e '{"cc_rust_dir": "/opt/controlclaw/rust/1.0.0", "box_role": "openclaw", "controlclaw_user": "controlclaw", "controlclaw_home": "/home/controlclaw", "openclaw_gateway_port": 18789}' > /tmp/render.log 2>&1)
grep -qx 'ExecStart=/opt/controlclaw/rust/1.0.0/vm-agent' /tmp/agent-unit && ! grep -q 'OnFailure\|StartLimit\|RestartMode\|node' /tmp/agent-unit \
  && grep -qx 'Restart=always' /tmp/agent-unit \
  && pass "the unit: the release's binary, no OnFailure, no start limit" \
  || { fail "the unit: the release's binary, no OnFailure, no start limit"; tail -5 /tmp/render.log; cat /tmp/agent-unit; }

# The firewall agent: its page assets go in dist-ui/ next to it, pinned like the binary.
printf '#!/bin/sh\necho rust mitm-agent\n' > "$STAGE/mitm-agent-x86_64-linux-musl"
printf 'body{--background:#fff}\n' > "$STAGE/mitm-agent-ui-app.css"
printf 'console.log(1)\n' > "$STAGE/mitm-agent-ui-app.js"
pins_fw() {
  cat > /work/roles/controlclaw/vars/rust_release.yml <<YML
cc_rust_release:
  version: "1.0.0"
  commit: "test"
  base_url: "http://127.0.0.1:1/none"
  binaries:
    mitm-agent: { asset: "mitm-agent-x86_64-linux-musl", sha256: "$(sha "$STAGE/mitm-agent-x86_64-linux-musl")" }
    cc-migrate: { asset: "cc-migrate-x86_64-linux-musl", sha256: "$(sha "$STAGE/cc-migrate-x86_64-linux-musl")" }
YML
  [ "${1:-}" = none ] && return
  cat >> /work/roles/controlclaw/vars/rust_release.yml <<YML
  ui:
    app.css: { asset: "mitm-agent-ui-app.css", sha256: "${1:-$(sha "$STAGE/mitm-agent-ui-app.css")}" }
    app.js: { asset: "mitm-agent-ui-app.js", sha256: "$(sha "$STAGE/mitm-agent-ui-app.js")" }
YML
}
play_fw() { (cd /work && ansible-playbook -i localhost, tests/rust-runtime/play-mitm.yml -e cc_rust_source=files "$@" > /tmp/play.log 2>&1); }
ui=/opt/controlclaw/rust/1.0.0/dist-ui

fresh; pins_fw; play_fw
[ $? = 0 ] && [ -x /opt/controlclaw/rust/1.0.0/mitm-agent ] && cmp -s "$ui/app.css" "$STAGE/mitm-agent-ui-app.css" && [ -f "$ui/app.js" ] \
  && [ "$(stat -c '%U %a' "$ui/app.css")" = "root 644" ] \
  && pass "firewall agent: its page assets in dist-ui/ next to it" \
  || { fail "firewall agent: its page assets in dist-ui/ next to it"; tail -20 /tmp/play.log; }

fresh; pins_fw "0000000000000000000000000000000000000000000000000000000000000000"; play_fw
[ $? != 0 ] && [ ! -e "$ui/app.css" ] \
  && pass "a page asset that is not the pinned one is removed, and the run fails" \
  || { fail "a page asset that is not the pinned one is removed, and the run fails"; tail -20 /tmp/play.log; }

fresh; pins_fw none; play_fw
[ $? != 0 ] && pass "a release without page assets fails the firewall's run" \
  || { fail "a release without page assets fails the firewall's run"; tail -20 /tmp/play.log; }

echo
[ "$fails" = 0 ] && echo "all rust-runtime checks passed" || { echo "$fails check(s) failed"; exit 1; }
