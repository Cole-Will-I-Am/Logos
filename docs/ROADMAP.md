# Logos Roadmap

Logos implements the "Sealed" ultra-secure-messenger blueprint. This file keeps
the **whole** program in view while we build it phase by phase. Status legend:
✅ done · 🔜 next · ⏳ planned · 🔒 gate.

> The detailed security *target* lives in
> [`SIGNAL_PLUS_BLUEPRINT.md`](SIGNAL_PLUS_BLUEPRINT.md) (workstreams, release
> gates, "Signal-plus" definition-of-done). **This file = where we are + what's
> next; the blueprint = where we're going.**
>
> Future capability, not scheduled: [`VOICE_CALLS_ROADMAP.md`](VOICE_CALLS_ROADMAP.md)
> — 1:1 audio-only E2EE calls (WebRTC + signaling over the existing channel; gated
> on push). A separate plane from messaging; comes after notifications + hardening.

## ✅ Recently shipped (account & recovery) — 2026-06

- **Persistent relay** — registrations + queued envelopes survive restarts (atomic
  `snapshot.json`); the server signing key is reused so apps keep their pin.
- **Honest "username taken"** — a registration 409 is surfaced as `UsernameTaken`,
  not the misleading "can't reach the relay" (0.1.9).
- **Identity recovery phrase** — identities are now seed-derived (HKDF over a 32-byte
  master seed) → a **24-word BIP39** backup. `restore` re-derives the same keys and
  reclaims the username on a new device (same key → contacts see no key-change).
  Settings → *Back up your identity*; onboarding → *Restore from a recovery phrase*.
  Recovers identity + username only — not message history or contacts.
- **Reconnect after restore** — peer-side *Reset secure session* (Verify screen)
  re-establishes a stale session when a contact restored/reinstalled with the SAME
  identity (keeps verification). Logos deliberately won't auto-reset a live session
  from an inbound handshake (replay-clobber defense); **automatic, replay-safe
  re-establishment (epoch/root-key aware) is a tracked follow-up.**
- **Multi-account** (multiple usernames per device) — design in
  [`MULTI_ACCOUNT_PLAN.md`](MULTI_ACCOUNT_PLAN.md); not yet implemented.

- **External-review hardening batch (done):** **iOS at-rest encryption** — the
  identity store and chat history are now encrypted with a device-only Keychain key
  (`StoreKey`; Argon2id in the Rust core for the store, ChaCha20-Poly1305 for the
  history snapshot), auto-migrating legacy plaintext on next save; **username grammar**
  (`logos_proto::validate_username`, enforced relay-side + pre-flighted client-side →
  typed `InvalidUsername`); **CLI store password** (`--password`/`LOGOS_PASSWORD`, no
  more hardcoded value); **time-panic saturation** (`now()` no longer `.unwrap()`s);
  **sealed-sender claim narrowed** in UI copy (contents are PQ-hybrid; the sender-
  hiding envelope is classical X25519).

Remaining from the external review: **key transparency** (the big one — append-only
verifiable log; do before any public "trust us" positioning), then an **external
audit**. Hybridizing the sealed-sender envelope for PQ sender-metadata is also open.

## ▶︎ Resuming — current state + next steps (handoff)

**Live now:** iOS app on TestFlight through **v0.1.18** (no-Mac CI pipeline; ASC creds,
app record, signing — see `CI_TESTFLIGHT_SETUP.md` and the reusable `ios-testflight`
skill). Public relay **relay.manticthink.com** deployed (Cloudflare tunnel; persistent +
red-team-hardened). `main` is the built/verified branch — build from `main`. Whole-repo VPS
backups in `/srv/backups/logos/`. The full 1:1 red-team report is `docs/REDTEAM-2026-06.md`
(kept LOCAL, not committed — it lists open follow-ups).

**Shipped to date:** 1:1 E2EE (PQXDH + Double Ratchet + sealed sender + TOFU), identity
**recovery phrase** (24-word seed; 48-word legacy full-key), **at-rest encryption**
(device Keychain key for store + history), **persistent relay**, **local contacts**, the
**full 1:1 red-team remediation** (all HIGH/MEDIUM + cheap LOW), **BYOK AI**
(Anthropic/OpenAI/Ollama, device→provider, relay never in the path) + **on-device AI
default** (Apple Foundation Models) + **1:1 catch-up summaries**, and now **E2EE group
chats — sender-key v1 core** (P4.0a static + P4.0b membership/rekey-on-removal) + the
**M1 prekey-replenishment** prereq (0.1.18). **Caveat: group chats are CORE + PROTOCOL
only — there is NO group UI yet** (the FFI doesn't surface groups; iOS app is unchanged
for users, 1:1 wire byte-identical). Group chats were adversarially reviewed (5-reviewer
workflow; 13 confirmed → 8 fixed, 4 documented as v1 limitations).

**Agreed next build order (resume here):**

1. ✅ On-device AI provider (0.1.17).
2. ✅ **Group chats — sender-key v1 core**: P4.0a (static create/send/recv) + P4.0b
   (add/remove + **rekey-on-removal**, admins, rename) + M1 prekey replenishment. On
   `main`, shipped in 0.1.18. See [`GROUP_CHAT_PLAN.md`](GROUP_CHAT_PLAN.md) → "Implemented
   status" + "Known limitations".
3. 🔜 **P4.0c — iOS group UI** (makes groups user-visible — the remaining group piece):
   expose groups through `logos-ffi` (`create_group`/`send_group`/`add_member`/
   `remove_member`/`groups`/`group_members`; extend the FFI `IncomingMessage` with the
   group id) → SwiftUI create-group (contacts picker) / group chat view (sender name per
   message) / member list + admin controls.
4. ⏳ **AI-1 — on-device semantic search + memory** (see
   [`AI_NATIVE_BLUEPRINT.md`](AI_NATIVE_BLUEPRINT.md)): grounded, source-cited search over
   local history on the existing BYOK/on-device plumbing.
5. ⏳ **P4.1 — MLS** (openmls): replace the sender-key core for O(log N) rekey,
   post-compromise security, and transcript consistency; relay becomes an ordered
   delivery service.

**Group-chat v1 known limitations (documented in `GROUP_CHAT_PLAN.md`; deferred — none a
confidentiality break):** simultaneous mutual session init (a pre-existing 1:1 issue —
needs session tie-break); best-effort fan-out with no delivery acks; the 5-poll quarantine
cap vs deferred sender-key arrival; bootstrap-race early-message loss.

**Open security follow-ups (tracked):** M1 client prekey-replenishment ✅ DONE (signed-prekey
*rotation* still open) · **P3 key transparency** (the F-02 endgame — do before any public
"trust us" claim) · L1 quadratic skipped-key eviction · L2 sealed-sender PQ metadata · L7
pin CI build tools · the group-chat limitations above · **external professional crypto audit
= the real production gate.**

## ▶︎ Security-review follow-ups (open — from PR #1 `security-review-fixes`)

PR #1 landed a security review of the crypto/glue layers (mailbox key-confusion,
ratchet/store durability, prekey-replay reset, key persistence, doc drift; with
new regression tests). **Caveat:** PR #1 changed `mailbox_id` to hash the full
identity (`ed||dh`) — a **wire/format change**, so existing client stores and any
deployed relay must be reset together when it merges.

Still open (NOT in PR #1), roughly by priority:

1. **iOS UI / error surfacing** *(high)* — ✅ **mostly done** (see `docs/DESIGN.md`).
   `Session` now tracks per-message `MessageStatus` and marks a bubble sent only
   after `client.send` returns; send failures/refusals render honestly in the thread
   (status row + tap-to-retry). MITM/TOFU refusals are surfaced via a **typed** error:
   `logos-client::ClientError` is now an enum (`IdentityChanged`/`NotRegistered`/
   `Network`/`Other`) mapped 1:1 onto the FFI `LogosError`, so the identity-changed
   interstitial fires on a real key change (not a string heuristic). First-run
   `Application Support` is created up front; the store is set `isExcludedFromBackup`
   + `FileProtection(.completeUnlessOpen)`. **Residual:** `recv`/poll-loop errors
   still only set `lastError` (rendered on onboarding) — a connectivity indicator on
   the conversations list is a follow-up; and the FileProtection class is a tradeoff
   for background polling (not at-rest store encryption — that's the Argon2id item).
2. **Hybridize sealed sender (PQ metadata)** *(medium)* — the sealed-sender
   envelope uses classical X25519 to the recipient's static identity key, so
   sender-identity metadata is not post-quantum (harvest-now-decrypt-later),
   unlike message keys (PQXDH). Hybridize using the recipient's ML-KEM prekey, or
   explicitly scope it out in the threat model.
3. **Full zeroization (F-12)** *(medium, defense-in-depth)* — `RatchetState`/
   `Skipped` (and the per-message `decrypt()` clone), PQXDH `dh1..dh4`/`ss`, sealed
   `shared`/`key`/`plaintext`, and the client `Store` secrets are not zeroized,
   despite the crates advertising FS/PCS and `logos-identity` advertising
   ZeroizeOnDrop. Derive `ZeroizeOnDrop` (with `#[zeroize(skip)]` on public fields).
4. **CI supply-chain (F-08 sibling)** *(medium)* — SHA-pin every `uses:`
   (`dtolnay/rust-toolchain@stable` is a mutable branch), add `cargo deny`/`cargo
   audit`, pin the toolchain version in `rust-toolchain.toml`. (PR #1 already added
   `permissions: contents: read` + `if-no-files-found: error`.)
5. **Relay abuse controls** *(low/medium)* — `/v1/mailbox` posting and
   `/v1/directory` fetches are unauthenticated; PR #1 added a per-mailbox cap, but
   rate limiting, TTL sweeping, and one-time-prekey replenishment are still needed
   (fold into the redb persistence item). Also persist `next_id` (in-memory reset
   to 0 enables stale-ACK replay after restart).
6. **Client response-size cap** *(medium)* — PR #1 added HTTP timeouts; still cap
   relay response body size before deserializing (a malicious relay can return a
   giant JSON body → OOM).
7. **Nits** — `now()` unwraps panic if the device clock is < 1970 (crosses FFI as
   an app crash); consider binding prekey ids in the PQXDH transcript `info`
   (defense-in-depth; DH legs already bind the key values); replace server
   `Mutex::lock().unwrap()` with poison-tolerant locking.

**CI note:** private-repo Actions are blocked by a GitHub account spending limit, so
each build runs via flip-public → run → revert-private. Build locally-equivalent
with `cargo test --workspace`; the iOS build is `gh workflow run build` (while public).

## Where we are

| Phase | Scope | Status |
|------|-------|:--:|
| **P0 — Crypto core** | identity (Ed25519+X25519+ML-KEM-1024 prekeys), PQXDH hybrid handshake, Double Ratchet (FS+PCS), sealed sender | ✅ |
| **P1 — Relay + client + CLI** | minimal-trust axum relay (auth'd + ACK'd mailbox, KEM-prekey pool), sync FFI-friendly client, `logos` CLI, end-to-end tests | ✅ |
| **P1.5 — Security-review hardening** | transactional decrypt, cert↔identity binding + TOFU, one-time ML-KEM, domain-separated sigs, panic removal, persisted server key | ✅ |
| **P2 — iOS app** | `logos-ffi` (UniFFI) ✅ → `LogosKit.xcframework` + SwiftUI app (source ✅, CI build validating) → deploy relay (localhost ✅, public TLS pending) → TestFlight (needs signing) | 🚧 |
| **P3 — Key transparency** | append-only verifiable log of identity keys + client auditing/gossip (the real fix for relay-as-cert-authority; upgrades TOFU) | ⏳ |
| **P4 — Groups (E2EE)** | sender-key v1: **P4.0a static** ✅ + **P4.0b membership/rekey-on-removal** ✅ (core, 0.1.18) · **P4.0c iOS group UI** 🔜 · **P4.1 MLS** (openmls) ⏳ — [`GROUP_CHAT_PLAN.md`](GROUP_CHAT_PLAN.md). E2EE, NOT Telegram server-readable | 🚧 |
| **P5 — Advanced privacy** | onion/mixnet transport, blinded/rotating mailbox ids, PSI contact discovery, multi-device | ⏳ |
| **AI-native track** | private AI layer — design in [`AI_NATIVE_BLUEPRINT.md`](AI_NATIVE_BLUEPRINT.md). **AI-0 = BYOK** (user's own Anthropic/OpenAI/Ollama key, device→provider direct, relay never in the AI path; Keychain-stored) + 1:1 catch-up summary → local search/memory → group catch-up. Relay stays blind; cloud AI = explicit per-use consent | 🔜 |
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
- ✅ **CI build green** — the SwiftUI app + LogosKit.xcframework compile on a macOS runner (`macos-15`/Xcode 16); Rust workspace checks pass on Linux. (Private-repo Actions are blocked by an account spending limit, so builds run via the flip-public pattern, reverting to private after each run.)
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
