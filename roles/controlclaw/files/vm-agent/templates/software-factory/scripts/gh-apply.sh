#!/bin/bash
# The GitHub CLI, a pinned release with its checksum, into ~/.local/bin. No root is needed.
set -euo pipefail
. "$CC_TEMPLATE_DIR/scripts/lib.sh"
version=2.102.0
case "$(dpkg --print-architecture)" in
  amd64) arch=amd64; sum=bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386 ;;
  arm64) arch=arm64; sum=7862c86c72f43df3a2d93ddde6f473285b4e2af61b494849846827e513ef6484 ;;
  *) echo "no gh build for this machine"; exit 1 ;;
esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fetch "https://github.com/cli/cli/releases/download/v${version}/gh_${version}_linux_${arch}.tar.gz" "$sum" "$tmp/gh.tar.gz"
tar -xzf "$tmp/gh.tar.gz" -C "$tmp"
mkdir -p "$BIN"
install -m 755 "$tmp/gh_${version}_linux_${arch}/bin/gh" "$BIN/gh"
echo "installed gh ${version}"
