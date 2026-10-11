#!/bin/bash
# uv, a pinned release with its checksum, into ~/.local/bin. It also does what pip does (`uv pip`).
set -euo pipefail
. "$CC_TEMPLATE_DIR/scripts/lib.sh"
version=0.13.0
case "$(uname -m)" in
  x86_64) target=x86_64-unknown-linux-gnu; sum=1468ebd5a5541121837c5a2817b9972ba6090fa6caa3d142620850a47fb75154 ;;
  aarch64) target=aarch64-unknown-linux-gnu; sum=3ccfb6af6e242433eb552f7d9676abd5412c6595c497e990d9c8cb7b5bd4d2c3 ;;
  *) echo "no uv build for this machine"; exit 1 ;;
esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fetch "https://github.com/astral-sh/uv/releases/download/${version}/uv-${target}.tar.gz" "$sum" "$tmp/uv.tar.gz"
tar -xzf "$tmp/uv.tar.gz" -C "$tmp"
mkdir -p "$BIN"
install -m 755 "$tmp/uv-${target}/uv" "$tmp/uv-${target}/uvx" "$BIN/"
echo "installed uv ${version}"
