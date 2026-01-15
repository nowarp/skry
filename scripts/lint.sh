#!/bin/bash
set -e
cd "$(dirname "$0")/.."
ruff check $@ src/
ty check src/ 2>&1 | grep -v "^WARN " || true
