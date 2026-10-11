#!/bin/bash
"$HOME/.local/bin/uv" --version >/dev/null 2>&1 || command -v uv >/dev/null 2>&1 || { echo "uv is not installed"; exit 1; }
