# DeepSeek Review: `kimi/signal-plus-blueprint`

**Review date:** 2026-06-21
**Scope:** `git diff origin/main...HEAD` (1 commit, 16 files, +683/−74)
**Reviewer:** DeepSeek (adversarial code+security agent)
**Disposition:** NOT rubber-stamped. Every claim verified against the diff.

---

## 1. Overall Verdict

The branch is **mergeable as-is** — it builds clean, all tests pass, clippy and
fmt are green, and the core cryptographic changes (zeroization, AEAD key/nonce
lifecycle, transactional prekey consumption, response caps) are sound. No
regressions were introduced; existing audit PoC tests continue to pass.

However, the branch should not be considered "Phase 0 complete." Three
high-severity findings and several medium ones need attention before the relay
rate-limiting and client response-size-cap story is genuinely done. The
encrypted client store is **underclaimed** (marked TODO but fully implemented
and wired in) — update the progress tracker.

Logos remains **EXPERIMENTAL and UNAUDITED** throughout; no false safety claims
were introduced.

---

## 2. Build / Test / Clippy / Fmt Results

| Check | Result |
|-------|--------|
| `cargo build --workspace` | **PASS** (6.09s, 0 errors) |
| `cargo test --workspace` | **PASS** (all 37 tests, 0 failures) |
| `cargo clippy --workspace --all-targets -- -D warnings` | **PASS** (0 warnings) |
| `cargo fmt --check` | **PASS** (clean) |

Toolchain: Rust 1.96.0 (pinned in `rust-toolchain.toml`).

---

## 3. Findings by Severity

### HIGH

**H1 — TOCTOU race in `post_mailbox` rate limiter**
- `crates/logos-server/src/lib.rs:434-445`
- The rate-limit check (`rate_limiter.check`) and the envelope push happen in
  **separate `Mutex` lock acquisitions**. Between the two, a concurrent request
  can also pass the check, defeating the token-bucket cap for burst traffic.
- The mailbox size cap (`MAX_MAILBOX_MESSAGES = 4096`) provides a hard backstop,
  and the TTL sweep eventually drains excess, so the blast radius is bounded.
  Still, the rate limiter is not providing its intended guarantee.
- **Fix:** Hold a single lock for check + push, or use the check result to
  reserve a token that is "spent" atomically with the push.

**H2 — Client response size limits only applied to `/v1/fetch`**
- `crates/logos-client/src/lib.rs:106` (`read_body_with_limit` exists)
- `crates/logos-client/src/lib.rs:291` (`server_key` uses bare `.json()`)
- `crates/logos-client/src/lib.rs:409` (`cert` uses bare `.json()`)
- `crates/logos-client/src/lib.rs:435` (`directory` uses bare `.json()`)
- The blueprint (B3) requires caps on *every* client response parser. Only
  `fetch` uses `read_body_with_limit`. A malicious/compromised relay could
  return a multi-gigabyte directory or cert response, forcing unbounded
  buffering before `serde_json::from_slice` fails.
- In practice `server_key` (32 bytes) and `cert` (small) are low-risk, but
  `directory` carries prekey material and could be inflated.
- **Fix:** Route all relay responses through `read_body_with_limit` (or
  `reqwest::blocking::Client` with a global body limit).

**H3 — `KemSecret` wrapper lacks `Zeroize`/`ZeroizeOnDrop`**
- `crates/logos-identity/src/kem.rs:24` (`pub struct KemSecret(Dk)`)
- The inner `ml_kem::DecapsulationKey1024` zeroizes on drop (the crate's
  `zeroize` feature is enabled in `Cargo.toml:16`), but the newtype wrapper
  does not derive `Zeroize` or `ZeroizeOnDrop`. If the wrapper is moved,
  cloned, or serialized without going through the inner type's `Drop`, the
  ML-KEM-1024 secret key bytes could persist in memory.
- The same applies to `KemSharedSecret` (a bare `[u8; 32]` typedef) — the
  shared secret `ss` in `logos-pqxdh`'s `initiate`/`respond` is fed into
  `ikm` (which is zeroized in `derive`) but the `ss` local itself is not
  explicitly zeroized.
- **Fix:** Derive `ZeroizeOnDrop` on `KemSecret` and `KemSharedSecret`, and
  add explicit `.zeroize()` calls on `ss` in `logos-pqxdh`.

### MEDIUM

**M1 — Rate-limiter state not persisted across relay restarts**
- `crates/logos-server/src/lib.rs:307-311` (`SerializableState` struct)
- The JSON snapshot saves `next_id`, `directory`, and `mailboxes`, but
  **omits `rate_limiter`**. After a restart, all token buckets reset to full
  burst capacity. An attacker who can trigger a restart (crash, OOM, host
  reboot) gets a fresh rate-limit budget.
- **Fix:** Include `rate_limiter` in `SerializableState`.

**M2 — No server-side envelope cap on `/v1/fetch`**
- `crates/logos-server/src/lib.rs:474-490`
- The server returns *all* envelopes in the mailbox. The client truncates to
  `MAX_FETCH_ENVELOPES` (1000) and has `read_body_with_limit` (16 MiB), so
  the client is protected. But the server does unnecessary serialization work
  for envelopes the client will discard, and a very large mailbox could cause
  a slow/large response.
- **Fix:** Cap the server-side iteration to `MAX_FETCH_ENVELOPES` (or a
  server-side constant) and return the oldest-first.

**M3 — No bound on prekey count in `/v1/replenish`**
- `crates/logos-server/src/lib.rs:514-540`
- `entry.one_time.extend(req.one_time_prekeys)` and
  `entry.kem_one_time.extend(req.kem_prekeys)` accept unbounded input. An
  identity owner could upload millions of prekeys, bloating their directory
  entry and the JSON snapshot.
- **Fix:** Enforce a per-pool cap (e.g., 1000 one-time prekeys, 500 KEM
  prekeys) and reject replenish requests that would exceed it.

**M4 — Stale doc-comment on `Store` struct**
- `crates/logos-client/src/lib.rs:157-159`
- The comment says "Phase-1: stored as plaintext JSON — encryption-at-rest
  (Argon2id-wrapped) is a tracked follow-up" but the code now encrypts via
  `encrypted_store`. The comment is misleading.
- **Fix:** Update the comment to reflect the current encrypted-at-rest reality.

**M5 — Blueprint underclaims encrypted client store**
- `docs/BLUEPRINT_PROGRESS.md:16` marks "Encrypted client store" as **TODO**
- The implementation is complete and wired in:
  - `crates/logos-client/src/encrypted_store.rs` — full Argon2id + ChaCha20-Poly1305
  - `crates/logos-client/src/lib.rs:334,381` — `load` and `save` use it
  - `crates/logos-ffi/src/lib.rs:81,97` — FFI passes `password` through
  - All tests use encrypted stores
- **Fix:** Mark it **DONE** in the progress tracker.

### LOW

**L1 — Prekey secret wrappers lack `ZeroizeOnDrop`**
- `crates/logos-identity/src/lib.rs` — `SignedPreKeySecret`, `OneTimePreKeySecret`,
  `KemPreKeySecret`
- The inner types (`X25519Secret`, `KemSecret`) handle their own zeroization,
  so this is defense-in-depth, not a live leak.
- **Fix:** Derive `ZeroizeOnDrop` on the wrappers for consistency.

**L2 — `dh_out` temporary in `kdf_rk` not explicitly zeroized**
- `crates/logos-ratchet/src/lib.rs:98`
- The DH output is a stack-allocated `[u8; 32]` that is overwritten when the
  stack frame pops. Low risk; explicit zeroization would be belt-and-suspenders.
- **Fix:** Add `.zeroize()` on the DH output after HKDF expansion.

**L3 — Snapshot content not validated on load**
- `crates/logos-server/src/lib.rs:258-270`
- `load_snapshot` deserializes JSON and directly assigns `next_id`,
  `directory`, `mailboxes` without structural validation. A corrupted snapshot
  could set `next_id` to a value that causes ID collisions.
- **Fix:** Validate `next_id` monotonicity and mailbox/directory invariants.

**L4 — Dev CLI hardcodes test password**
- `crates/logos-cli/src/main.rs:38-48`
- Uses `Some("test-password")` literally. Acceptable for a dev tool; the
  `EXPERIMENTAL — UNAUDITED` banner is present.
- **Fix (future):** Prompt for password or read from env var.

---

## 4. Per-Workstream Assessment

### Phase 0 — Hardening Foundation

| Blueprint Item | Claimed | Actual | Verdict |
|---------------|---------|--------|---------|
| Encrypted client store | TODO | **Fully implemented** (encrypted_store module, wired into load/save, FFI passes password) | Underclaim — mark DONE |
| Full zeroization of secrets | DONE | Core paths done (Store::drop, RatchetState, InitiatorResult, ResponderResult, AEAD key/nonce, sealed-sender key/nonce/shared/plaintext). Gaps: KemSecret wrapper (H3), prekey wrappers (L1), ML-KEM ss local (H3). | DONE with minor gaps |
| Panic-free FFI boundary | PARTIAL | Accurate. `Client::load` validates identity_secret length. Other fallible paths still need hardening. | PARTIAL (honest) |
| Relay persistence | PARTIAL | JSON snapshot of directory + mailboxes + next_id with atomic write. Rate-limiter not persisted (M1). redb is future work. | PARTIAL (honest) |
| TTL sweep | DONE | Background task every 60s, envelopes stamped with expiry, empty mailboxes pruned, stale rate-limit buckets evicted. | DONE |
| Rate limits + abuse controls | PARTIAL | Per-mailbox token bucket implemented. TOCTOU race (H1). Per-IP missing (tracked). | PARTIAL (honest) |
| Prekey replenishment | DONE | `/v1/replenish` endpoint, `ReplenishRequest` wire type, signature verification, identity-match check. No prekey-count cap (M3). | DONE with minor gap |
| Request/response size caps | DONE | Server: 1 MiB body limit. Client: `read_body_with_limit` on fetch only (H2). | PARTIAL — fetch-only is not "done" |
| CI supply-chain hardening | DONE | SHA-pinned actions, pinned Rust 1.96.0, cargo-deny + cargo-audit, deny.toml. | DONE |

### Phase 1–5

All items correctly marked TODO or PARTIAL. No overclaims detected. The
"Property tests" PARTIAL claim is honest — `audit_poc.rs` exists with 6
security-regression tests but is not a full property suite.

---

## 5. Cryptographic & Security Soundness

### What's solid

- **AEAD key/nonce lifecycle:** Message keys are derived via HKDF from one-time
  message keys, used once, then zeroized. No key/nonce reuse path.
- **Ratchet advance-before-transmit:** `send()` persists the advanced ratchet
  state *before* the HTTP POST, preventing crash-induced key reuse.
- **ACK-after-save:** `recv()` saves state before ACKing, so messages are never
  deleted from the server before being durably processed.
- **Transactional prekey consumption:** One-time prekeys are only removed
  *after* the full handshake + first ratchet decrypt succeeds (F-05 fix).
- **Prekey replay resistance:** Inbound prekey messages do not reset existing
  sessions (`process_envelope` checks `sessions.contains_key`).
- **Garbage envelope draining:** Undecryptable envelopes are ACK-dropped rather
  than quarantined forever (F-08 fix).
- **Mailbox binding to Ed25519:** `mailbox_id` hashes `ed || dh`, preventing
  the `{attacker_ed, victim_dh}` cross-user read attack. Verified by
  `poc_vcrit_mailbox_not_readable_or_drainable_with_foreign_ed`.
- **Sender certificate ↔ handshake binding:** `establish_and_decrypt` verifies
  `cert.sender_identity == initial.initiator_identity` before trusting the
  sender.
- **Sealed-sender ephemeral keys:** Fresh `X25519Secret::random_from_rng(OsRng)`
  per envelope. Shared secret, derived key, nonce, and plaintext all zeroized.
- **Encrypted store:** Argon2id (default params: 19 MiB, t=2, p=1) with fresh
  128-bit salt and 96-bit nonce per encryption. ChaCha20-Poly1305 AEAD.
  Atomic write (tmp + rename). Wrong password fails closed.
- **Skip bounds:** `MAX_SKIP = 1000` per chain step, `MAX_SKIP_TOTAL = 2000`
  global, with saturating arithmetic to prevent overflow.
- **Server signing key persistence:** Present-but-invalid key file is a fatal
  error (no silent rotation). Valid key preserved. Missing key generated `0600`.

### What needs attention

- TOCTOU in rate limiter (H1)
- Missing response caps on non-fetch endpoints (H2)
- `KemSecret`/`KemSharedSecret` zeroization gaps (H3)
- Rate-limiter not persisted (M1)
- No server-side fetch envelope cap (M2)
- No replenish prekey-count cap (M3)

### What's absent (by design, not a regression)

- No key transparency (Phase 2)
- No continuous PQ ratchet (Phase 3)
- No hybrid sealed sender (Phase 4)
- No multi-device/groups/backups (Phase 5)
- No per-IP rate limits (requires connect-info plumbing)
- No production-grade relay store (redb is future work)
- No fuzzing, formal models, or external audit (Phase 1+)

---

## 6. Regressions

None. All 37 pre-existing tests pass. The `new_state_at` signature change was
correctly propagated to all call sites (server `main.rs`, key persistence
tests). The `Client::load`/`Client::create` password parameter was propagated
to the FFI crate, CLI, and all integration tests.

---

## 7. Summary

Kimi's Phase 0 implementation is **substantially correct** and delivers real
security value: zeroization covers the critical paths, the encrypted store is
fully wired (despite being underclaimed), TTL sweep and prekey replenishment
work, and CI supply-chain hardening is complete. The three HIGH findings are
real but have bounded blast radius; they should be fixed before claiming
Phase 0 done. The MEDIUM findings are polish items. No overclaims were
detected; if anything, the encrypted store is underclaimed.

**Recommendation:** Merge after fixing H1–H3, or merge now with those findings
tracked as immediate follow-up work. Update `BLUEPRINT_PROGRESS.md` to mark
the encrypted store as DONE.
