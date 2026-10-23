#!/usr/bin/env bash
# Starts Typst Local (run ./setup.sh first). Settings come from .env.
set -euo pipefail
cd "$(dirname "$0")"
[[ -x .node/bin/node ]] && export PATH="$PWD/.node/bin:$PATH"
[[ -f public/editor.js ]] || { echo "Not set up yet: run ./setup.sh first." >&2; exit 1; }
exec node server/index.js "$@"
