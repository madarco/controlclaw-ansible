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
