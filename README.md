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

## Status: working 1:1 E2EE walking skeleton ✅

`cargo test --workspace` → **22 passing**, including an end-to-end integration
test where two clients exchange encrypted messages through a live relay.

| Crate | Responsibility |
|-------|----------------|
| `logos-identity` | Ed25519 + X25519 identity, signed/one-time prekeys, **ML-KEM-1024** prekeys, prekey-bundle verification, safety numbers |
| `logos-ratchet` | **Double Ratchet** (FS + post-compromise security, out-of-order handling) |
| `logos-pqxdh` | **PQXDH** hybrid handshake (X25519 X3DH legs + ML-KEM-1024) → ratchet root key, transcript-bound |
| `logos-sealed` | **Sealed sender** — server-signed certs + ephemeral-X25519 envelope; hides the sender from the relay |
| `logos-proto` | Shared wire types + endpoint contract |
| `logos-server` | Minimal-trust relay (axum): public-key directory, opaque mailbox queue, **delete-on-deliver**, sealed-sender cert issuance |
| `logos-client` | Sync, FFI-friendly client engine: register / send / recv; file-backed session store |
| `logos-cli` | `logos` dev binary: `register` / `send` / `recv` / `whoami` |

The relay never sees message plaintext, and sealed sender keeps it from learning
who sent a delivered message. Honest caveats (tracked, not yet closed): it still
sees recipient mailbox + timing; mailbox fetch is not yet authenticated/ACK-based
(a known address could be drained — fix in progress); and it currently issues the
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
- `ios/LogosApp` — SwiftUI app (onboarding → conversations → chat → settings).
- `scripts/build-ios.sh` + `.github/workflows/ios.yml` — build the xcframework and
  compile the app on a macOS CI runner (no local Mac needed).

See [`ios/README.md`](ios/README.md). Status is tracked in
[`docs/ROADMAP.md`](docs/ROADMAP.md) (P2).

> Note on reproducible builds: per the design blueprint, App Store binaries can't
> be bit-for-bit reproduced (Apple re-signs/encrypts), so iOS will lean on the
> open Rust core + binary-transparency rather than reproducible IPAs.

## Build & test

```sh
cargo test --workspace        # 22 tests
cargo clippy --workspace --all-targets
cargo fmt --check
```

## Roadmap

Done: crypto core (identity / PQXDH / ratchet / sealed) · relay + client + CLI ·
end-to-end test.

Next: `logos-ffi` (UniFFI) + iOS SwiftUI app · persistent relay store (redb) +
TTL sweep · encryption-at-rest for the client store (Argon2id) · **key
transparency** log + auditing · MLS groups · mixnet/onion transport ·
multi-device · backups/recovery · abuse defenses · **external security audit**
(gating any real use).

## Design docs

- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — the exact handshake / ratchet /
  sealed-sender / relay construction (written to be auditable).
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — assets, adversaries, and
  what is explicitly out of scope.

## License

AGPL-3.0-only.
