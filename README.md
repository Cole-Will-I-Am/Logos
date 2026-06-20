# Logos

> ## ⚠️ EXPERIMENTAL — UNAUDITED. DO NOT USE FOR REAL SECRETS.
> Logos is a research implementation of an end-to-end-encrypted messenger. Its
> cryptographic protocol is **assembled from audited primitives but has not
> itself been audited**. Security claims must follow an external audit, never
> precede it. Treat this as a learning/reference build only.

Logos is the first phase of an ultra-secure messenger that treats its own server
as hostile: no server-readable content, sender identity hidden from the relay,
and **post-quantum-hybrid** key agreement by default. Identity is username-first
— **no phone numbers, ever**.

This phase implements the **cryptographic core** of a 1:1 messenger as a Rust
workspace, built on audited primitive crates (`*-dalek`, RustCrypto `ml-kem`,
`chacha20poly1305`, `hkdf`, `hmac`) and implemented strictly against the
published Signal **Double Ratchet** and **PQXDH** specifications. We reuse
audited *primitives*; we do not invent cryptography.

## What's implemented (Phase 1 — crypto core) ✅

| Crate | Responsibility | Tests |
|-------|----------------|:----:|
| `logos-identity` | Ed25519 identity + X25519 DH keys, prekey bundles, **ML-KEM-1024** prekeys, safety numbers | 8 |
| `logos-ratchet` | **Double Ratchet** (X25519 + HKDF-SHA256 + ChaCha20-Poly1305): forward secrecy + post-compromise security, skipped/out-of-order keys | 5 |
| `logos-pqxdh` | **PQXDH** hybrid handshake (X25519 X3DH legs + ML-KEM-1024) → ratchet root key; transcript-bound | 4 |
| `logos-sealed` | **Sealed sender**: server-signed sender certificates + ephemeral-X25519 envelope; hides the sender from the relay | 4 |

`cargo test --workspace` → **21 passing**, including an end-to-end test that runs
a full PQXDH handshake and then exchanges Double-Ratchet messages.

## Security properties (of the crypto core)

- **Post-quantum hybrid:** an attacker must break **both** X25519 **and**
  ML-KEM-1024 to recover a session key (harvest-now-decrypt-later resistance).
- **Forward secrecy + post-compromise security:** via the Double Ratchet.
- **Sender anonymity vs. the relay:** sealed sender means a server-side observer
  sees only an opaque blob addressed to a mailbox, never who sent it.
- **Authentication:** prekey bundles and sender certificates are signature-bound;
  safety numbers allow out-of-band verification.

## Roadmap (not yet built — Phase 2+)

The networked transport and apps are the next increment:

- `logos-proto` / `logos-server` (axum + redb): minimal-trust relay — encrypted
  mailbox, store-and-forward, delete-on-deliver, TTL; key directory; sender-cert issuance.
- `logos-client` / `logos-cli`: `register` / `send` / `recv` / `verify` over the relay.
- Later (per the design blueprint): MLS groups, key-transparency log + auditing,
  mixnet/onion transport, multi-device, backups/recovery, abuse defenses,
  reproducible-build CI, mobile clients.

## Build & test

```sh
# Rust stable (see rust-toolchain.toml)
cargo test --workspace      # 21 tests
cargo clippy --workspace
cargo fmt --check
```

## Design docs

- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — the exact handshake / ratchet /
  sealed-sender construction (written to be auditable).
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — assets, adversaries, and
  what is explicitly out of scope.

## License

AGPL-3.0-only.
