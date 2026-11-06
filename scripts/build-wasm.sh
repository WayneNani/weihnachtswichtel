#!/usr/bin/env bash
# Build crates/wichtel-wasm for the browser.
#
#   scripts/build-wasm.sh                 # → web/src/wasm-pkg (wasm-bindgen --target web)
#   scripts/build-wasm.sh --out-dir DIR   # other output directory
#
# Requires the Rust target wasm32-unknown-unknown and wasm-bindgen-cli in exactly the version of
# `wasm-bindgen` in Cargo.lock. Honors CARGO_TARGET_DIR (default: ./target) and CARGO_BUILD_JOBS.
# wasm-opt is not used (optional, not required).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT_DIR="web/src/wasm-pkg"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

TARGET=wasm32-unknown-unknown
PROFILE=wasm-release
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
WASM="$TARGET_DIR/$TARGET/$PROFILE/wichtel_wasm.wasm"

# wasm-bindgen-cli must match the library version exactly.
WANT="$(grep -A1 '^name = "wasm-bindgen"$' Cargo.lock | sed -n 's/^version = "\(.*\)"$/\1/p')"
BINDGEN="$(command -v wasm-bindgen || echo "$HOME/.cargo/bin/wasm-bindgen")"
if [[ ! -x "$BINDGEN" ]]; then
  echo "wasm-bindgen not found (need wasm-bindgen-cli $WANT)" >&2
  exit 1
fi
HAVE="$("$BINDGEN" --version | awk '{print $2}')"
if [[ "$HAVE" != "$WANT" ]]; then
  echo "wasm-bindgen $HAVE found, but Cargo.lock has $WANT" >&2
  exit 1
fi

cargo build --target "$TARGET" --profile "$PROFILE" -p wichtel-wasm

rm -rf "$OUT_DIR"
"$BINDGEN" --target web --remove-name-section --remove-producers-section \
  --out-dir "$OUT_DIR" "$WASM"

echo "wasm (cargo):        $(wc -c < "$WASM") bytes  $WASM"
echo "wasm (wasm-bindgen): $(wc -c < "$OUT_DIR/wichtel_wasm_bg.wasm") bytes  $OUT_DIR/wichtel_wasm_bg.wasm"
echo "gzip -9:             $(gzip -9 -c "$OUT_DIR/wichtel_wasm_bg.wasm" | wc -c) bytes"
