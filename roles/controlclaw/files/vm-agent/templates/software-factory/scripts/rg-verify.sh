#!/bin/bash
"$HOME/.local/bin/rg" --version >/dev/null 2>&1 || command -v rg >/dev/null 2>&1 || { echo "ripgrep is not installed"; exit 1; }
