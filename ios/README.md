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
- `ios/LogosKit/` — SwiftPM package. `Package.swift` (committed) + a committed
  `Sources/LogosKit/LogosKit.swift`; the generated binding
  (`Sources/LogosKit/Generated/logos_ffi.swift`) and `LogosFFI.xcframework` are
  produced by the build script (gitignored).
- `ios/LogosApp/` — the SwiftUI app: `project.yml` (XcodeGen) + `Sources/`.
  Screens now cover Onboarding → Conversations → Chat → Settings plus identity
  Verify, Contacts, recovery phrase, a dedicated AI chat (BYOK + on-device, with
  `@mention` + Loose Ends), E2EE group chats, photo/file sharing, and "what the
  relay sees" transparency panels (polling `recv()` off-main). Depends on the
  local `LogosKit` package.

## Build & run (on macOS)

```sh
./scripts/build-ios.sh          # builds LogosKit.xcframework + Swift bindings
cd ios/LogosApp && xcodegen     # generates LogosApp.xcodeproj
open LogosApp.xcodeproj         # build/run in Xcode (point Relay URL at the deployed relay)
```

The generated `logos_ffi.swift` becomes a source in `LogosKit`; the xcframework is
its binary target.

## Swift API (generated)

```swift
// `password` wraps the at-rest store (Argon2id); pass nil only in test/dev.
let client = try LogosClient.create(path: storePath, serverUrl: relay, username: "alice", password: passphrase)
try client.send(to: "bob", message: "hello")
let msgs = try client.recv()   // [IncomingMessage(from:text:)]
```

## Status / constraints

- `logos-ffi` + binding generation: ✅ verified on Linux.
- xcframework + app build + TestFlight: macOS/CI (Xcode required).
- Live on TestFlight (latest v0.1.28); App Store submission in prep.
- App Store IPAs are **not** bit-for-bit reproducible (Apple re-signs) — we rely on
  the open Rust core + binary transparency, per the design blueprint.
- EXPERIMENTAL / UNAUDITED — see repo root.
