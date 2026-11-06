#!/usr/bin/env bash
# Build everything needed to run the app locally:
#   1. scripts/build-wasm.sh          → web/src/wasm-pkg/
#   2. npm run build (web/)           → web/dist/ (incl. dist/pkg/)
#   3. cargo build -p wichtel-server  → serves web/dist via rust-embed
#
#   scripts/build-all.sh              # server in debug mode (default)
#   scripts/build-all.sh --release    # server in release mode
#
# Then: cargo run -p wichtel-server (or the binary under $CARGO_TARGET_DIR) → http://127.0.0.1:8080
# Honors CARGO_TARGET_DIR and CARGO_BUILD_JOBS.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SERVER_PROFILE=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --release) SERVER_PROFILE=(--release); shift ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

echo "==> WASM"
scripts/build-wasm.sh

echo "==> Web"
(
  cd web
  [[ -d node_modules ]] || npm ci --no-audit --no-fund
  npm run build
)
if [[ ! -f web/dist/pkg/wichtel_wasm_bg.wasm ]]; then
  echo "web/dist/pkg is missing the WASM module" >&2
  exit 1
fi

echo "==> Server"
cargo build -p wichtel-server "${SERVER_PROFILE[@]}"

echo "done: $(cd "${CARGO_TARGET_DIR:-$ROOT/target}" && pwd)/$([[ ${#SERVER_PROFILE[@]} -gt 0 ]] && echo release || echo debug)/wichtel-server"
