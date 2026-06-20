# Logos Roadmap

Logos implements the "Sealed" ultra-secure-messenger blueprint. This file keeps
the **whole** program in view while we build it phase by phase. Status legend:
✅ done · 🔜 next · ⏳ planned · 🔒 gate.

## Where we are

| Phase | Scope | Status |
|------|-------|:--:|
| **P0 — Crypto core** | identity (Ed25519+X25519+ML-KEM-1024 prekeys), PQXDH hybrid handshake, Double Ratchet (FS+PCS), sealed sender | ✅ |
| **P1 — Relay + client + CLI** | minimal-trust axum relay (auth'd + ACK'd mailbox, KEM-prekey pool), sync FFI-friendly client, `logos` CLI, end-to-end tests | ✅ |
| **P1.5 — Security-review hardening** | transactional decrypt, cert↔identity binding + TOFU, one-time ML-KEM, domain-separated sigs, panic removal, persisted server key | ✅ |
| **P2 — iOS app** | `logos-ffi` (UniFFI) ✅ → `LogosKit.xcframework` + SwiftUI app (source ✅, CI build validating) → deploy relay (localhost ✅, public TLS pending) → TestFlight (needs signing) | 🚧 |
| **P3 — Key transparency** | append-only verifiable log of identity keys + client auditing/gossip (the real fix for relay-as-cert-authority; upgrades TOFU) | ⏳ |
| **P4 — Groups (MLS)** | `openmls` group messaging | ⏳ |
| **P5 — Advanced privacy** | onion/mixnet transport, blinded/rotating mailbox ids, PSI contact discovery, multi-device | ⏳ |
| **Cross-cutting hardening** | redb relay persistence + TTL, Argon2id client-store encryption, prekey-fetch rate limits, full zeroization, reproducible-build/binary-transparency CI | ⏳ |
| **External security audit** | protocol + implementation + infra | 🔒 gate before any real-world use |

Open non-blocking review items folded into the phases above: F-08 (rate limits →
hardening), F-12 (full zeroization → hardening), blinded mailbox (→ P5), F-02
endgame (→ P3).

### P2 status (in progress)

- ✅ `logos-ffi` (UniFFI) — compiles + FFI smoke test + Swift binding generation, all verified on Linux.
- ✅ `LogosKit` SwiftPM package + SwiftUI app source (`ios/LogosApp`) — authored; not yet compiled locally (no Mac here).
- ✅ Relay deployed on the VPS as `logos-relay.service` (systemd) — **localhost-only** for now.
- ✅ CI workflow (`.github/workflows/ios.yml`) — Linux Rust checks + macOS xcframework + Simulator app build.
- 🚧 **Green CI build** — validating the Swift on a macOS runner. (Account spending limit blocks private-repo Actions, so builds run via the flip-public pattern; revert to private after each run.)
- ⬜ **Public TLS relay endpoint** so a device can connect (currently localhost).
- ⬜ **TestFlight / device build** — needs an Apple developer account + signing secrets.

---

## P2 — iOS app (next; detailed plan)

**Goal:** ship Logos as a real iOS app. The Rust core stays the single source of
crypto truth; Swift is a thin UI over it via a generated binding. No crypto or
protocol logic is reimplemented in Swift.

### 2.1 `logos-ffi` crate (UniFFI)  — *buildable/verifiable on Linux*
- New crate `crates/logos-ffi` that wraps `logos-client` with **UniFFI**
  (proc-macro mode). The client API is already sync + plain types, which UniFFI
  maps cleanly.
- Exports:
  - `LogosClient` as a `uniffi::Object` wrapping `Mutex<logos_client::Client>`
    (UniFFI object methods take `&self`, so mutable client state lives behind an
    internal lock). Methods: `create(path, serverUrl, username)`,
    `load(path, serverUrl)`, `username()`, `send(to, message)`,
    `recv() -> [IncomingMessage]`, `safetyNumber(forContact)`.
  - `IncomingMessage { from: String, text: String }` as a `uniffi::Record`.
  - `LogosError` as a `uniffi::Error` (from the existing single-message `ClientError`).
- Output: a `cdylib`/`staticlib` + generated Swift bindings (`logos_ffi.swift`,
  a C header, a modulemap). `cargo build -p logos-ffi` and `uniffi-bindgen
  generate ... --language swift` both run on Linux → we can verify the crate
  compiles and the Swift binding generates here, before any Mac is involved.

### 2.2 Packaging → `LogosKit.xcframework`  — *needs macOS/CI*
- Cross-compile the staticlib for: `aarch64-apple-ios` (device),
  `aarch64-apple-ios-sim` + `x86_64-apple-ios` (simulator, lipo'd).
- `xcodebuild -create-xcframework` bundles the staticlibs + headers + modulemap;
  wrap as a SwiftPM package **`LogosKit`** exposing the generated Swift API.
- Use **`cargo-swift`** to automate the above, with a committed `scripts/build-ios.sh`
  fallback. (lipo/xcodebuild are macOS-only → this step runs on a macOS GitHub
  Actions runner, the same no-Mac-needed CI pattern used for SEER/DB8.)

### 2.3 SwiftUI app (`ios/`)  — *source authored on Linux, built on macOS/CI*
- `ios/` with an **XcodeGen `project.yml`** (CI-buildable), depending on `LogosKit`.
- Screens:
  - **Onboarding** — pick a username, `LogosClient.create(...)`; store file in the
    app sandbox; show the recovery caveat (no server-side recovery).
  - **Conversations** — list of contacts/threads (from the local store).
  - **Chat** — message list + composer; `send`; **poll `recv()` off the main
    thread** on a timer (push comes later). Render the EXPERIMENTAL banner.
  - **Verify** — safety-number display/compare per contact (the TOFU/MITM defense
    surfaced to users).
  - **Settings** — username, server URL, "this is experimental/unaudited."
- Store key handling: keep the client store in the sandbox now; **later** wrap its
  encryption key with the iOS Keychain / Secure Enclave (ties into the hardening
  phase + the blueprint's hardware-backed-keys goal).

### 2.4 Deploy the relay  — *needed for the app to function*
- `logos-server` (axum) deployed as a systemd service on the VPS behind TLS
  (e.g. `relay.logos.<domain>`), persisting its signing key (`LOGOS_KEY`) and
  data dir. (Still in-memory store until the redb hardening item — fine for a
  TestFlight beta; flagged.)

### 2.5 CI
- GitHub Actions: a Linux job (`cargo test`/`clippy` for the whole workspace +
  `logos-ffi` build + Swift binding gen) and a macOS job (xcframework + app
  build → TestFlight), mirroring the SEER pipeline.

### P2 milestones / gates
1. `logos-ffi` compiles on Linux, Swift bindings generate, a Rust-side smoke test
   drives the wrapped `LogosClient` end-to-end against an in-process relay. ← we
   can fully do/verify this here.
2. `scripts/build-ios.sh` + `cargo-swift` config produce `LogosKit.xcframework`
   (verified on macOS/CI).
3. SwiftUI app: onboard → send/recv between two devices/simulators via the
   deployed relay.
4. Relay deployed + TestFlight build.

### Honest constraints (carried from the blueprint)
- **iOS App Store binaries are not bit-for-bit reproducible** (Apple re-signs/
  encrypts) → we lean on the open Rust core + binary-transparency, not reproducible
  IPAs.
- The xcframework + app build require macOS (Xcode); only that step is off-Linux.
- Still **EXPERIMENTAL/UNAUDITED** — the audit gate (🔒) precedes any real use,
  regardless of how polished the app is.

---

## Sequencing rationale

P2 (iOS) makes Logos a usable product and is the stated target. **P3 (key
transparency) is the most security-significant follow-up** — it removes the relay
as identity authority (the F-02 endgame) and turns TOFU into continuous
verification, so it should land before any "trust us" public positioning. P4/P5
broaden capability (groups) and strengthen metadata protection (mixnet, blinded
mailbox). The audit gate stands in front of real-world use throughout.
