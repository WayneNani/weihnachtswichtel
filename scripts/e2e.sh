#!/usr/bin/env bash
# Browser end-to-end tests (tests/e2e/*.test.mjs) with the preinstalled playwright library + Chromium.
#
#   scripts/e2e.sh              # expects scripts/build-all.sh to have run
#   scripts/e2e.sh --build      # build first (WASM, web, debug server)
#   scripts/e2e.sh tests/e2e/04-leave.test.mjs   # single file
#
# One browser process per test file, files run one after another (--test-concurrency=1).
# Node 22's `node --test` does not accept a directory, hence the glob.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/home/user/wichtel-target}"

if [[ "${1:-}" == "--build" ]]; then
  shift
  scripts/build-all.sh
fi

if [[ $# -eq 0 ]]; then
  set -- 'tests/e2e/*.test.mjs'
fi
exec node --test --test-concurrency=1 "$@"
