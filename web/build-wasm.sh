#!/usr/bin/env bash
# Reproducible build of the Logos web client's WebAssembly module + JS bindings,
# plus the brand assets the page references. Mirrors how scripts/build-ios.sh
# produces the iOS bindings: generated output is gitignored and rebuilt from here.
#
# Why this script exists: the ml-kem RNG path pulls getrandom 0.4, whose browser
# backend must be selected with a build-time cfg (`getrandom_backend="wasm_js"`)
# passed via RUSTFLAGS — it is NOT expressible in Cargo.toml alone. Forget it and
# the wasm build fails to link. This captures the exact, working invocation.
#
# Output (all under web/public/, all gitignored):
#   public/wasm/logos_wasm.js + logos_wasm_bg.wasm   (wasm-bindgen `--target web`)
#   public/logos-icon.png, public/logos-wordmark.png (copied from ../brand)
set -euo pipefail

WBVER="0.2.125"                       # MUST equal the wasm-bindgen crate version in Cargo.lock
WEB_DIR="$(cd "$(dirname "$0")" && pwd)"
# Repo root = parent of web/ (overridable for unusual layouts).
REPO_DIR="${LOGOS_REPO:-$(cd "$WEB_DIR/.." && pwd)}"
OUT_DIR="$WEB_DIR/public/wasm"
WASM="$REPO_DIR/target/wasm32-unknown-unknown/release/logos_wasm.wasm"

export PATH="$HOME/.cargo/bin:$PATH"

# 1. Toolchain: wasm32 target (idempotent).
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true

# 2. Resolve a matching wasm-bindgen CLI (PATH → known /tmp drop → cargo install).
if command -v wasm-bindgen >/dev/null 2>&1 && [ "$(wasm-bindgen --version | awk '{print $2}')" = "$WBVER" ]; then
  WB=wasm-bindgen
elif [ -x "/tmp/wasm-bindgen-${WBVER}-x86_64-unknown-linux-musl/wasm-bindgen" ]; then
  WB="/tmp/wasm-bindgen-${WBVER}-x86_64-unknown-linux-musl/wasm-bindgen"
else
  echo "wasm-bindgen $WBVER not found; installing the CLI (one-time, slow)…"
  cargo install wasm-bindgen-cli --version "$WBVER" --locked
  WB=wasm-bindgen
fi
echo "Using wasm-bindgen: $WB ($($WB --version))"

# 3. Build the crate for wasm32 with the required getrandom backend cfg.
#    (Scoped to this command only — never affects native/iOS/relay builds.)
( cd "$REPO_DIR" && \
  RUSTFLAGS='--cfg getrandom_backend="wasm_js"' \
  cargo build -p logos-wasm --release --target wasm32-unknown-unknown )

# 4. Generate ES-module bindings (matches app.js: `import init from logos_wasm.js`).
mkdir -p "$OUT_DIR"
"$WB" --target web --out-dir "$OUT_DIR" --out-name logos_wasm "$WASM"

# 5. Stage brand assets the page references (kept DRY — single source in ../brand).
cp "$REPO_DIR/brand/logos-icon.png"               "$WEB_DIR/public/logos-icon.png"
cp "$REPO_DIR/brand/logos-wordmark-transparent.png" "$WEB_DIR/public/logos-wordmark.png"

echo "✓ Built web client assets:"
ls -la "$OUT_DIR"
echo "  + public/logos-icon.png, public/logos-wordmark.png"
