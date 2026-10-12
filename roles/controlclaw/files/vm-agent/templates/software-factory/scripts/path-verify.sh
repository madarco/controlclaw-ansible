#!/bin/bash
grep -qxF 'export PATH="$PATH:$HOME/.local/bin"' "$HOME/.profile" 2>/dev/null || { echo "~/.profile does not put ~/.local/bin on the PATH"; exit 1; }
