#!/bin/bash
# ripgrep, a pinned release with its checksum, into ~/.local/bin.
set -euo pipefail
. "$CC_TEMPLATE_DIR/scripts/lib.sh"
version=15.2.0
case "$(uname -m)" in
  x86_64) target=x86_64-unknown-linux-musl; sum=33e15bcf1624b25cdd2a55813a47a2f95dbe126268203e76aa6a585d1e7b149c ;;
  aarch64) target=aarch64-unknown-linux-gnu; sum=a740b91c82eaf9914cfedd353572f2791cbe0162c84101ee0951058f4dcbc90d ;;
  *) echo "no ripgrep build for this machine"; exit 1 ;;
esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fetch "https://github.com/BurntSushi/ripgrep/releases/download/${version}/ripgrep-${version}-${target}.tar.gz" "$sum" "$tmp/rg.tar.gz"
tar -xzf "$tmp/rg.tar.gz" -C "$tmp"
mkdir -p "$BIN"
install -m 755 "$tmp/ripgrep-${version}-${target}/rg" "$BIN/rg"
echo "installed ripgrep ${version}"
