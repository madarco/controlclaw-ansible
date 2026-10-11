#!/bin/bash
"$HOME/.local/bin/gh" --version >/dev/null 2>&1 || command -v gh >/dev/null 2>&1 || { echo "gh is not installed"; exit 1; }
