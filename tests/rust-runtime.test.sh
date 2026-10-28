#!/bin/bash
# Tests roles/controlclaw/tasks/rust-runtime.yml and files/cc-runtime-fallback: which build a
# component runs (default, setting, canary, fallback marker, store check), that a binary is only
# installed when it is the pinned one, and what the fallback helper leaves behind.
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
printf '#!/bin/sh\necho "{\\"checked\\":0,\\"unreadable\\":0}"\nexit 0\n' > "$STAGE/cc-migrate-x86_64-linux-musl"
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
fresh() { rm -rf /etc/controlclaw/runtime /opt/controlclaw/rust /tmp/cc_rt.json; }
play() { (cd /work && ansible-playbook -i localhost, tests/rust-runtime/play.yml -e cc_rust_source=files "$@" > /tmp/play.log 2>&1); }
runtime() { python3 -c 'import json;print(json.load(open("/tmp/cc_rt.json"))["vm_agent"]["runtime"])' 2>/dev/null; }
field() { python3 -c "import json;print(json.load(open('/tmp/cc_rt.json'))['vm_agent']['$1'])" 2>/dev/null; }

fresh; pins 1.0.0
play && [ "$(runtime)" = node ] && [ ! -e /opt/controlclaw/rust ] && pass "default: node, nothing installed" || fail "default: node, nothing installed"

fresh; play -e cc_vm_agent_runtime=rust
if [ "$(runtime)" = rust ] && [ "$(field exec)" = /opt/controlclaw/rust/1.0.0/vm-agent ] \
   && [ -x /opt/controlclaw/rust/1.0.0/vm-agent ] && [ "$(stat -c %U /opt/controlclaw/rust/1.0.0/vm-agent)" = root ] \
   && [ "$(cat /etc/controlclaw/runtime/controlclaw-agent.node-exec)" = "/usr/bin/node /opt/controlclaw/agent/dist/index.js" ]; then
  pass "rust: the pinned binary, root-owned, with the fallback wired"
else fail "rust: the pinned binary, root-owned, with the fallback wired"; tail -20 /tmp/play.log; fi

fresh; play -e '{"cc_rust_canary": {"vm_agent": ["vm_test"], "mitm_agent": [], "proxy": []}}'
[ "$(runtime)" = rust ] && pass "canary by vm_id" || fail "canary by vm_id"

fresh; play -e '{"cc_rust_canary": {"vm_agent": ["vm_other"], "mitm_agent": [], "proxy": []}}'
[ "$(runtime)" = node ] && pass "another box's canary changes nothing" || fail "another box's canary changes nothing"

fresh; pins 1.0.0 "0000000000000000000000000000000000000000000000000000000000000000"
play -e cc_vm_agent_runtime=rust
[ "$(runtime)" = node ] && [ ! -e /opt/controlclaw/rust/1.0.0/vm-agent ] \
  && grep -q '"reason": "pin-mismatch"' /etc/controlclaw/runtime/controlclaw-agent.fallback \
  && pass "a binary that is not the pinned one is removed, node stays, with a marker" \
  || { fail "a binary that is not the pinned one is removed, node stays, with a marker"; tail -20 /tmp/play.log; }
pins 1.0.0

fresh; (cd /work && ansible-playbook -i localhost, tests/rust-runtime/play.yml -e cc_rust_source=release -e cc_vm_agent_runtime=rust > /tmp/play.log 2>&1)
[ $? = 0 ] && [ "$(runtime)" = node ] && [ ! -e /etc/controlclaw/runtime/controlclaw-agent.fallback ] \
  && pass "a download that fails keeps node, no marker, the run goes on" || { fail "a download that fails keeps node, no marker, the run goes on"; tail -20 /tmp/play.log; }

fresh; play -e '{"cc_rust_canary": {"vm_agent": ["vm_test"]}}'
[ "$(runtime)" = rust ] && pass "a canary with one list only" || { fail "a canary with one list only"; tail -20 /tmp/play.log; }

fresh; play -e cc_vm_agent_runtime=rust -e ansible_architecture=aarch64
[ "$(runtime)" = node ] && grep -q '"reason": "unsupported-arch"' /etc/controlclaw/runtime/controlclaw-agent.fallback \
  && pass "another architecture keeps node, with a marker" || { fail "another architecture keeps node, with a marker"; tail -20 /tmp/play.log; }

fresh; mkdir -p /opt/controlclaw/rust/0.9.0 && touch /opt/controlclaw/rust/0.9.0/vm-agent
play -e cc_vm_agent_runtime=rust
[ ! -e /opt/controlclaw/rust/0.9.0 ] && [ -x /opt/controlclaw/rust/1.0.0/vm-agent ] && pass "older release folders are pruned" || fail "older release folders are pruned"

fresh; mkdir -p /etc/controlclaw/runtime
echo '{"unit":"controlclaw-agent","release":"1.0.0","reason":"crash-loop"}' > /etc/controlclaw/runtime/controlclaw-agent.fallback
play -e cc_vm_agent_runtime=rust
[ "$(runtime)" = node ] && [ -e /etc/controlclaw/runtime/controlclaw-agent.fallback ] \
  && pass "a fallback for the pinned release keeps node, and the marker" || fail "a fallback for the pinned release keeps node, and the marker"

pins 1.1.0; play -e cc_vm_agent_runtime=rust
[ "$(runtime)" = rust ] && [ ! -e /etc/controlclaw/runtime/controlclaw-agent.fallback ] \
  && pass "a new release gets its try, the old marker goes" || fail "a new release gets its try, the old marker goes"

fresh; pins 1.0.0
printf '#!/bin/sh\necho "{\\"checked\\":1,\\"unreadable\\":1}"\nexit 1\n' > "$STAGE/cc-migrate-x86_64-linux-musl"; pins 1.0.0
play -e cc_vm_agent_runtime=rust
[ "$(runtime)" = node ] && grep -q '"reason": "store-check"' /etc/controlclaw/runtime/controlclaw-agent.fallback \
  && pass "stores the Rust build cannot read keep node, with a marker" || { fail "stores the Rust build cannot read keep node, with a marker"; tail -20 /tmp/play.log; }

fresh; mkdir -p /etc/controlclaw/runtime
echo '{"unit":"controlclaw-agent","release":"0.9.0","reason":"crash-loop"}' > /etc/controlclaw/runtime/controlclaw-agent.fallback
play -e cc_vm_agent_runtime=rust
[ "$(runtime)" = node ] && grep -q '"release": "1.0.0", "reason": "store-check"' /etc/controlclaw/runtime/controlclaw-agent.fallback \
  && pass "an old release's marker goes, and this run's store-check marker stays" || { fail "an old release's marker goes, and this run's store-check marker stays"; cat /etc/controlclaw/runtime/controlclaw-agent.fallback; }

fresh; mkdir -p /etc/controlclaw/runtime
echo '{"unit":"controlclaw-agent","release":"1.0.0","reason":"crash-loop"}' > /etc/controlclaw/runtime/controlclaw-agent.fallback
play
[ "$(runtime)" = node ] && [ ! -e /etc/controlclaw/runtime/controlclaw-agent.fallback ] \
  && pass "set back to node on purpose: the marker goes" || fail "set back to node on purpose: the marker goes"

# The unit vm-agent.yml writes, rendered for each build: with Rust the start limit and OnFailure are
# lines of their own (a literal "\\n" in one line would leave systemd without OnFailure).
python3 - > /tmp/agent-unit.j2 <<'PY'
import yaml
for t in yaml.safe_load(open("/work/roles/controlclaw/tasks/vm-agent.yml")):
    c = t.get("ansible.builtin.copy", {})
    if c.get("dest") == "/etc/systemd/system/controlclaw-agent.service":
        print(c["content"], end="")
PY
render() {
  (cd /work && ansible localhost -c local -m ansible.builtin.copy \
    -a "dest=/tmp/agent-unit-$1 content={{ lookup('template', '/tmp/agent-unit.j2') }}" \
    -e "{\"cc_rt\": {\"vm_agent\": {\"runtime\": \"$1\", \"exec\": \"$2\"}}, \"box_role\": \"openclaw\", \"controlclaw_user\": \"controlclaw\", \"controlclaw_home\": \"/home/controlclaw\", \"openclaw_gateway_port\": 18789, \"cc_rust_start_limit_interval_s\": 120, \"cc_rust_start_limit_burst\": 5}" > /tmp/render.log 2>&1)
}
render rust /opt/controlclaw/rust/1.0.0/vm-agent && render node "/usr/bin/node /opt/controlclaw/agent/dist/index.js"
grep -qx 'OnFailure=cc-runtime-fallback@%N.service' /tmp/agent-unit-rust && grep -qx 'RestartMode=direct' /tmp/agent-unit-rust && grep -qx 'StartLimitBurst=5' /tmp/agent-unit-rust \
  && grep -qx 'ExecStart=/opt/controlclaw/rust/1.0.0/vm-agent' /tmp/agent-unit-rust \
  && ! grep -q 'OnFailure\|StartLimit\|\\n' /tmp/agent-unit-node && grep -qx 'ExecStart=/usr/bin/node /opt/controlclaw/agent/dist/index.js' /tmp/agent-unit-node \
  && pass "the unit: Rust gets its start limit and OnFailure as lines, Node gets nothing new" \
  || { fail "the unit: Rust gets its start limit and OnFailure as lines, Node gets nothing new"; cat /tmp/render.log | tail -5; head -8 /tmp/agent-unit-rust; }

# The fallback helper, as OnFailure runs it.
fresh; mkdir -p /etc/controlclaw/runtime /etc/systemd/system; : > /tmp/systemctl.log
echo '/usr/bin/node /opt/controlclaw/agent/dist/index.js' > /etc/controlclaw/runtime/controlclaw-agent.node-exec
echo '1.0.0' > /etc/controlclaw/runtime/controlclaw-agent.release
bash /work/roles/controlclaw/files/cc-runtime-fallback controlclaw-agent.service
drop=/etc/systemd/system/controlclaw-agent.service.d/50-runtime-fallback.conf
grep -qx 'ExecStart=/usr/bin/node /opt/controlclaw/agent/dist/index.js' "$drop" 2>/dev/null \
  && grep -qx 'OnFailure=' "$drop" && python3 -c 'import json,sys;d=json.load(open("/etc/controlclaw/runtime/controlclaw-agent.fallback"));sys.exit(not (d["release"]=="1.0.0" and d["reason"]=="crash-loop" and "last_line" not in d))' \
  && grep -q 'systemctl start controlclaw-agent' /tmp/systemctl.log \
  && pass "fallback: node put back, marker left, unit started" || fail "fallback: node put back, marker left, unit started"
bash /work/roles/controlclaw/files/cc-runtime-fallback sshd >/dev/null 2>&1
[ $? = 2 ] && pass "fallback refuses a unit it does not know" || fail "fallback refuses a unit it does not know"

echo
[ "$fails" = 0 ] && echo "all rust-runtime checks passed" || { echo "$fails check(s) failed"; exit 1; }
