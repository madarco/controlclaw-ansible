#!/usr/bin/env bash
# Add a release to releases.json, commit it and tag it.
#
#   scripts/release.sh <version> "change" ["change" ...]
#
# Run it on the commit you are about to promote (docs/ops/base-image.md in the controlclaw repo),
# then push that commit and the tag. The console shows the version on every agent and firewall,
# and the changes in the update dialogs, so keep each change to one short plain sentence a
# customer can read.
#
# Versions: major for a breaking release or one that needs a manual step, minor for features,
# patch for fixes. The entry carries no commit: a file cannot name the commit that adds it, so the
# release commit is the one that adds the entry, and the tag points at it.
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: scripts/release.sh <version> \"change\" [\"change\" ...]" >&2
  exit 2
fi

root=$(git rev-parse --show-toplevel)
cd "$root"
version=$1
shift

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "release.sh: the working tree has uncommitted changes; commit or stash them first" >&2
  exit 1
fi
if git rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
  echo "release.sh: tag v$version already exists" >&2
  exit 1
fi

# The OpenClaw this release installs has to have been upgraded to, on real boxes, from every version
# customers run (controlclaw apps/saas/scripts/upgrade-matrix.sh), and nothing newer may reach a box
# by itself: OpenClaw 2026.11.4 came out after 1.47.0 was tested, auto-patch installed it, and agents
# updated from 2026.9.x stopped (T-oc114). The matrix's results.json goes in
# openclaw-upgrade-tests/<version>.json, committed before this runs.
defaults=roles/controlclaw/defaults/main.yml
if [ -f "$defaults" ]; then
  python3 - "$defaults" <<'PY' || exit 1
import json, re, sys
text = open(sys.argv[1]).read()
def var(name):
    m = re.search(rf'^{name}:\s*"?([^"\s#]+)"?', text, re.M)
    return m.group(1) if m else None
pin, auto = var("openclaw_version"), var("openclaw_auto_patch")
if auto is None or auto.lower() != "false":
    sys.exit("release.sh: openclaw_auto_patch is on; a release installs exactly the OpenClaw it was tested with (T-oc114)")
record = f"openclaw-upgrade-tests/{pin}.json"
try:
    rows = json.load(open(record))
except (OSError, ValueError):
    sys.exit(f"release.sh: no upgrade test for OpenClaw {pin}: run apps/saas/scripts/upgrade-matrix.sh and commit its results.json as {record}")
failed = [r.get("path", "?") for r in rows if not r.get("pass") or r.get("after") != pin]
if not rows or failed:
    sys.exit(f"release.sh: the upgrade test in {record} did not pass to {pin}: {', '.join(failed) or 'no paths'}")
print(f"OpenClaw {pin}: upgrade tested from " + ", ".join(r["path"] for r in rows))
PY
fi

python3 - "$version" "$(date -u +%F)" "$@" <<'PY'
import json, re, sys

version, date, changes = sys.argv[1], sys.argv[2], sys.argv[3:]
SEMVER = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")

def key(v):
    m = SEMVER.fullmatch(v)
    if not m:
        sys.exit(f"release.sh: '{v}' is not a version like 1.4.0")
    return tuple(int(p) for p in m.groups())

key(version)
changes = [c.strip() for c in changes if c.strip()]
if not changes:
    sys.exit("release.sh: give at least one change")

try:
    with open("releases.json") as f:
        releases = json.load(f)
except FileNotFoundError:
    releases = []

if releases and key(version) <= key(releases[0]["version"]):
    sys.exit(f"release.sh: {version} is not newer than {releases[0]['version']}")

releases.insert(0, {"version": version, "date": date, "changes": changes})
with open("releases.json", "w") as f:
    json.dump(releases, f, indent=2, ensure_ascii=False)
    f.write("\n")
PY

git add releases.json
git commit -q -m "Release v$version"
git tag "v$version"

sha=$(git rev-parse HEAD)
cat <<MSG
Tagged v$version at $sha.
Promote it (docs/ops/base-image.md), then push the tag to both remotes:
  release_sha=$sha
  git push prod "\${release_sha}":refs/heads/next
  # wait for the candidate image, then:
  git push prod "\${release_sha}":refs/heads/main
  git push origin "\${release_sha}":refs/heads/main
  git push prod v$version && git push origin v$version
MSG
