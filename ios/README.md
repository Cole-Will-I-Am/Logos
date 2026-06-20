# Logos iOS

The iOS app is a thin SwiftUI UI over the Rust core — **no crypto or protocol
logic lives in Swift.** The core is exposed via UniFFI (`crates/logos-ffi`).

## Layout (P2)

- `crates/logos-ffi` — UniFFI wrapper around `logos-client` (`LogosClient` object,
  `IncomingMessage`, `LogosError`). Builds + Swift bindings generate on any
  platform (verified on Linux).
- `scripts/build-ios.sh` — **macOS-only**: builds `LogosKit.xcframework` (device +
  simulator slices) and regenerates the Swift bindings into `ios/bindings/`
  (gitignored — they're build artifacts).
- `ios/LogosApp/` *(next)* — the SwiftUI app (XcodeGen `project.yml`, CI-buildable)
  depending on the `LogosKit` package.

## Build (on macOS / CI)

```sh
./scripts/build-ios.sh        # → target/ios/LogosKit.xcframework + ios/bindings/
```

The generated `ios/bindings/logos_ffi.swift` is added as a source in the `LogosKit`
Swift package; the xcframework is its binary target.

## Swift API (generated)

```swift
let client = try LogosClient.create(path: storePath, serverUrl: relay, username: "alice")
try client.send(to: "bob", message: "hello")
let msgs = try client.recv()   // [IncomingMessage(from:text:)]
```

## Status / constraints

- `logos-ffi` + binding generation: ✅ verified on Linux.
- xcframework + app build + TestFlight: macOS/CI (Xcode required).
- App Store IPAs are **not** bit-for-bit reproducible (Apple re-signs) — we rely on
  the open Rust core + binary transparency, per the design blueprint.
- EXPERIMENTAL / UNAUDITED — see repo root.
