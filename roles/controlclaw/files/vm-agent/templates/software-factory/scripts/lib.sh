# Shared by the install scripts: a pinned download whose sha256 is checked before anything is unpacked.
# Usage: fetch <url> <sha256> <file>
fetch() {
  curl -fsSL --retry 2 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c - >/dev/null || { echo "the download of $(basename "$1") does not have the expected checksum"; rm -f "$3"; exit 1; }
}
# The agent's own tools go here. The folder is at the END of the PATH, so nothing in it can stand
# in for a system command.
BIN="$HOME/.local/bin"
