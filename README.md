# Logos

<p align="center"><img src="brand/logos-wordmark.png" alt="Logos" width="280"></p>

> ## ⚠️ EXPERIMENTAL — UNAUDITED. DO NOT USE FOR REAL SECRETS.
> Logos is a research implementation of an end-to-end-encrypted messenger. Its
> cryptographic protocol is **assembled from audited primitives but has not
> itself been audited**. Security claims must follow an external audit, never
> precede it. Treat this as a learning/reference build only.

Logos is an end-to-end-encrypted messenger that treats its own server as hostile:
no server-readable content, sender identity hidden from the relay, and
**post-quantum-hybrid** key agreement by default. Identity is username-first —
**no phone numbers, ever**. The target client is an **iOS app** (see below); the
core is Rust so it can be shared across platforms via a Swift FFI binding.

Built on audited primitive crates (`*-dalek`, RustCrypto `ml-kem`,
`chacha20poly1305`, `hkdf`, `hmac`) and implemented strictly against the
published Signal **Double Ratchet** and **PQXDH** specifications. We reuse
audited *primitives*; we do not invent cryptography.

## Status: live on TestFlight (v0.1.28) → App Store submission prep

A full SwiftUI iOS app ships from this core on TestFlight (latest **v0.1.28**) and
is now in App Store submission prep. Beyond 1:1 E2EE it has **E2EE group chats**,
**photo/file sharing**, identity **recovery phrases**, **at-rest encryption**, a
**private AI layer** (BYOK + on-device, dedicated assistant chat + @mention +
Loose Ends), and in-app **relay-transparency** panels. The relay runs publicly at
`relay.manticthink.com`. (Still EXPERIMENTAL/UNAUDITED per the banner above — the
external audit gates any real-world use.)

`cargo test --workspace` → **56 passing**, including an end-to-end integration
test where two clients exchange encrypted messages through a live relay, plus
security regression tests (replay/redelivery, corrupt-store, key-persistence).

| Crate | Responsibility |
|-------|----------------|
| `logos-identity` | Ed25519 + X25519 identity, signed/one-time prekeys, **ML-KEM-1024** prekeys, prekey-bundle verification, safety numbers |
| `logos-ratchet` | **Double Ratchet** (FS + post-compromise security, out-of-order handling) |
| `logos-pqxdh` | **PQXDH** hybrid handshake (X25519 X3DH legs + ML-KEM-1024) → ratchet root key, transcript-bound |
| `logos-sealed` | **Sealed sender** — server-signed certs + ephemeral-X25519 envelope; hides the sender from the relay |
| `logos-proto` | Shared wire types + endpoint contract |
| `logos-server` | Minimal-trust relay (axum): public-key directory, opaque mailbox queue, **authenticated fetch + ACK-based deletion**, sealed-sender cert issuance |
| `logos-client` | Sync, FFI-friendly client engine: register / send / recv; file-backed session store |
| `logos-cli` | `logos` dev binary (`register` / `send` / `recv` / `whoami`) + `logos-echo` test bot (echoes messages — a round-trip / App Review test buddy) |

The relay never sees message plaintext, and sealed sender keeps it from learning
who sent a delivered message. Mailbox **fetch is authenticated** (the caller
proves control of the identity key and the server derives the mailbox from it, so
only the owner can read) and deletion is **ACK-based** (envelopes are removed only
after the client durably processes and ACKs them). Honest caveats (tracked, not
yet closed): the relay still sees recipient mailbox + timing; mailbox ids are
stable (not blinded/rotating); `/v1/mailbox/{id}` posting is open by design (any
sender can deliver), bounded only by a per-mailbox cap (rate limiting / TTL is
future work); one-time prekeys can be drained by unauthenticated directory fetches
(replenishment + rate limits are future work); and the relay currently issues the
sealed-sender certificates, so under a fully malicious operator that authority
should move to key transparency / a separate issuer (sender identity is already
TOFU-pinned client-side as a first defense).

## Quickstart

```sh
cargo run -p logos-server &                                   # relay on 127.0.0.1:8787
S=http://127.0.0.1:8787
cargo run -p logos-cli -- --store alice.json register alice
cargo run -p logos-cli -- --store bob.json   register bob
cargo run -p logos-cli -- --store alice.json send bob "hello bob"
cargo run -p logos-cli -- --store bob.json   recv             # -> alice: hello bob
```

## iOS app (the target client)

The `logos-client` engine is **synchronous with plain types**, so it's wrapped for
Swift with **UniFFI** (`crates/logos-ffi`) and shipped as an **xcframework** — no
async crossing the FFI boundary; the relay stays server-side Rust.

- `crates/logos-ffi` — UniFFI wrapper (`LogosClient` / `IncomingMessage` /
  `LogosError`); compiles + Swift bindings generate on Linux (✅ verified).
- `ios/LogosKit` — SwiftPM package over the generated binding + xcframework.
- `ios/LogosApp` — SwiftUI app (onboarding · conversations · 1:1 + group chat · contacts/verify · dedicated AI chat · settings · relay-transparency panels).
- `scripts/build-ios.sh` + `.github/workflows/ios.yml` — build the xcframework and
  compile the app on a macOS CI runner (no local Mac needed).

See [`ios/README.md`](ios/README.md). Full phase status is tracked in
[`docs/ROADMAP.md`](docs/ROADMAP.md).

> Note on reproducible builds: per the design blueprint, App Store binaries can't
> be bit-for-bit reproduced (Apple re-signs/encrypts), so iOS will lean on the
> open Rust core + binary-transparency rather than reproducible IPAs.

## Build & test

```sh
cargo test --workspace        # 56 tests
cargo clippy --workspace --all-targets
cargo fmt --check
```

## Roadmap

Done: crypto core (identity / PQXDH / ratchet / sealed) · relay + client + CLI ·
end-to-end test · `logos-ffi` (UniFFI) + iOS SwiftUI app on TestFlight · at-rest
encryption (device Keychain key) · persistent relay · recovery phrases · E2EE
group chats (sender-key v1, in the UI) · BYOK + on-device AI layer.

Next: **key transparency** log + auditing (removes the relay as cert authority —
the big one) · **MLS groups** (openmls) · on-device semantic search/memory ·
persistent relay store (redb) + TTL sweep · mixnet/onion transport · multi-device
· chat-history backup · abuse defenses · **external security audit** (gating any
real use).

## Design docs

- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — the exact handshake / ratchet /
  sealed-sender / relay construction (written to be auditable).
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — assets, adversaries, and
  what is explicitly out of scope.
- [`docs/SIGNAL_PLUS_BLUEPRINT.md`](docs/SIGNAL_PLUS_BLUEPRINT.md) — roadmap for
  turning Logos from a research messenger into a credible Signal-plus system.

## License

AGPL-3.0-only.
