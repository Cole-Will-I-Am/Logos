# Blueprint Progress

This file tracks implementation status for each workstream item in
[`SIGNAL_PLUS_BLUEPRINT.md`](SIGNAL_PLUS_BLUEPRINT.md). Status legend:

- **DONE** — implemented and tested.
- **PARTIAL** — scaffolding/design in place, real code landed, but not yet
  complete/audited/production-ready.
- **TODO** — not yet started or only documented as future work.

> All changes are on branch `kimi/signal-plus-blueprint`. Logos remains
> **EXPERIMENTAL and UNAUDITED**; this progress tracker is not a security claim.

## Phase 0 — Hardening Foundation

| Item | Status | Note | Commit(s) |
|------|--------|------|-----------|
| Encrypted client store (Argon2id-wrapped at rest) | TODO | | |
| Full zeroization of secrets | DONE | ZeroizeOnDrop/Zeroize on identity, ratchet, PQXDH results, sealed-sender secrets, client Store/Session/prekey secrets. | (pending commit) |
| Panic-free FFI boundary | PARTIAL | `Client::load` already validates store structure; continue hardening all fallible paths. | |
| Relay persistence | PARTIAL | JSON snapshot of directory, mailboxes, next_id loaded/saved atomically; redb is the future production target. | (pending commit) |
| TTL sweep | DONE | Envelopes stamped with expiry; background task sweeps every 60s. | (pending commit) |
| Rate limits + abuse controls | PARTIAL | Per-mailbox posting token bucket; per-IP limits require connect-info plumbing (tracked). | (pending commit) |
| Prekey replenishment | DONE | `/v1/replenish` endpoint + `ReplenishRequest`; **client-side M1 replenishment shipped** (low-watermark top-up + pending-publish retry-until-confirmed). Signed-prekey *rotation* still TODO. | main (0.1.18) |
| Request/response size caps | DONE | Relay request body cap + client response body cap + fetch envelope cap. | (pending commit) |
| CI supply-chain hardening | DONE | SHA-pinned actions, pinned Rust 1.96.0, cargo-deny + cargo-audit steps, deny.toml. | (pending commit) |

## Phase 1 — Protocol Evidence

| Item | Status | Note | Commit(s) |
|------|--------|------|-----------|
| Stable protocol spec | PARTIAL | [`PROTOCOL.md`](PROTOCOL.md) documents current Phase 1 construction. | |
| Test vectors | TODO | | |
| Fuzz targets | TODO | | |
| Property tests | PARTIAL | Security-regression tests exist in `crates/logos-client/tests/audit_poc.rs`; expand to full property suite. | |
| Formal model | TODO | | |
| First external review | TODO | | |

## Phase 2 — Identity Superiority

| Item | Status | Note | Commit(s) |
|------|--------|------|-----------|
| Key transparency service | TODO | | |
| Client inclusion/consistency verification | TODO | | |
| Gossip checkpoints | TODO | | |
| Device transparency | TODO | | |
| Anonymous registration tokens | TODO | | |

## Phase 3 — Continuous PQ

| Item | Status | Note | Commit(s) |
|------|--------|------|-----------|
| Triple-Ratchet-style design doc | TODO | | |
| Implementation behind protocol version flag | TODO | | |
| Downgrade detection | TODO | | |
| Formal model | TODO | | |
| External audit | TODO | | |

## Phase 4 — Metadata Superiority

| Item | Status | Note | Commit(s) |
|------|--------|------|-----------|
| Hybrid sealed sender (PQ metadata) | TODO | | |
| Blinded rotating mailboxes | TODO | | |
| Delivery tokens | TODO | | |
| Envelope padding | TODO | | |
| Private/high-risk transport modes | TODO | | |

## Phase 5 — Product Parity

| Item | Status | Note | Commit(s) |
|------|--------|------|-----------|
| Multi-device | TODO | | |
| Groups / MLS | PARTIAL | E2EE **sender-key v1** core shipped — P4.0a static + P4.0b membership/**rekey-on-removal** (`logos-ratchet::senderkey`; see `GROUP_CHAT_PLAN.md`). **iOS group UI (P4.0c) SHIPPED** (group FFI + SwiftUI create-group/group-chat/member-list/admin controls). Only MLS/`openmls` (P4.1) remains TODO. Adversarially reviewed; v1 limitations documented. | main (0.1.25) |
| Attachments | DONE | Photo + file sharing shipped. | main (0.1.22) |
| Backups/recovery | TODO | | |
| Push notification hardening | TODO | | |
| Calls | TODO | | |

## Cross-Cutting

| Item | Status | Note | Commit(s) |
|------|--------|------|-----------|
| External audits (all gates) | TODO | | |
| Fuzzing in CI | TODO | | |
| Dependency auditing in CI | TODO | | |
| Published test vectors | TODO | | |
| Formal/semi-formal models | TODO | | |

