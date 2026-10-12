#!/bin/bash
# The agent's own tools (~/.local/bin) on its PATH, after the system's. A start-up file is written
# by a script, not by a `line` step, so whoever confirms a template sees it as something that runs.
set -euo pipefail
LINE='export PATH="$PATH:$HOME/.local/bin"'
touch "$HOME/.profile"
if ! grep -qxF "$LINE" "$HOME/.profile"; then
  # A last line with no line end would be glued to ours.
  if [ -s "$HOME/.profile" ] && [ -n "$(tail -c1 "$HOME/.profile")" ]; then printf '\n' >> "$HOME/.profile"; fi
  printf '%s\n' "$LINE" >> "$HOME/.profile"
fi
