#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python -m compileall -q diagnostic_browser tests
python -m pytest -q tests
for file in diagnostic_browser/static/*.js; do node --check "$file"; done
