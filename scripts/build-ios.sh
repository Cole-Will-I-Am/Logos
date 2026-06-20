#!/usr/bin/env bash
# Build LogosKit.xcframework + Swift bindings from the logos-ffi crate.
#
# REQUIRES macOS + Xcode (uses lipo/xcodebuild). Run on a Mac or a macOS CI
# runner. The Rust crate and the Swift binding generation themselves are
# cross-platform; only the xcframework assembly is macOS-only.
set -euo pipefail
cd "$(dirname "$0")/.."

LIB=logos_ffi
OUT=ios/bindings
XCF=target/ios/LogosKit.xcframework

# 1. Swift bindings (interface-only; generated from a host build — platform-independent).
cargo build -p logos-ffi --release
HOSTLIB=$(ls target/release/lib${LIB}.dylib 2>/dev/null || ls target/release/lib${LIB}.so)
rm -rf "$OUT"; mkdir -p "$OUT"
cargo run -p logos-ffi --bin uniffi-bindgen -- generate \
  --library "$HOSTLIB" --language swift --out-dir "$OUT"

# 2. iOS static libs: device + simulator (arm64 + x86_64 lipo'd).
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
cargo build -p logos-ffi --release --target aarch64-apple-ios
cargo build -p logos-ffi --release --target aarch64-apple-ios-sim
cargo build -p logos-ffi --release --target x86_64-apple-ios
mkdir -p target/ios
lipo -create \
  target/aarch64-apple-ios-sim/release/lib${LIB}.a \
  target/x86_64-apple-ios/release/lib${LIB}.a \
  -output target/ios/lib${LIB}-sim.a

# 3. Headers dir (C header + modulemap renamed to module.modulemap).
HEAD=target/ios/headers
rm -rf "$HEAD"; mkdir -p "$HEAD"
cp "$OUT/${LIB}FFI.h" "$HEAD/"
cp "$OUT/${LIB}FFI.modulemap" "$HEAD/module.modulemap"

# 4. Assemble the xcframework (device + simulator slices).
rm -rf "$XCF"
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/lib${LIB}.a -headers "$HEAD" \
  -library target/ios/lib${LIB}-sim.a -headers "$HEAD" \
  -output "$XCF"

echo "Built $XCF and Swift bindings in $OUT/"
echo "Add $OUT/${LIB}.swift to the LogosKit Swift package and link the xcframework."
