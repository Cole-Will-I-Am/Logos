# Signal-Plus Blueprint

> Status: planning/specification. This document defines what Logos must build before
> it can credibly claim to be stronger than Signal on any security axis. It is not a
> claim that Logos is currently safer than Signal. The current implementation remains
> **experimental, unaudited, and unsuitable for real secrets** until the audit gates
> below are closed.

## 1. North-star claim

Logos should not claim to be "more encrypted than Signal." Signal already has a
mature, heavily scrutinized end-to-end encryption stack.

The credible target claim is narrower and measurable:

> Signal-grade content security, stronger identity privacy, stronger metadata
> resistance, public key transparency, and continuous post-quantum protection —
> with external audits before public security claims.

This means Logos must first reach Signal-class correctness and maturity, then
surpass Signal on specific axes:

| Axis | Baseline to match | Logos differentiator |
|---|---|---|
| Message confidentiality | Default E2EE, Double Ratchet, PQ session setup | Match, then add continuous PQ ratcheting |
| Identity | Strong safety-number model | No phone numbers ever; username-first; public key transparency |
| Sender privacy | Sealed-sender-style sender hiding | Match, then hybridize sealed sender for PQ metadata protection |
| Recipient/timing metadata | Still difficult in mainstream messengers | Blinded rotating mailboxes, padding, private transport modes |
| Trust bootstrapping | Safety-number verification | Key transparency + client auditing + gossip |
| Client security | Hardened app storage and lifecycle | Hardware-backed local store, explicit recovery, no cloud backup by default |
| Evidence | Audit history, formal protocol design, operational maturity | External audits, formal models, fuzzing, reproducible/binary transparency |

## 2. Current Logos state

Already implemented or partially implemented:

- Username-first identity; no phone number dependency.
- Ed25519 signing identity plus X25519 DH identity.
- Signed X25519 prekeys.
- ML-KEM-1024 prekeys.
- PQXDH-style hybrid session setup.
- Double Ratchet for 1:1 sessions.
- Sealed-sender envelope that hides sender identity from the relay.
- Authenticated mailbox fetch.
- ACK-based deletion after durable client processing.
- TOFU identity pinning and identity-change refusal.
- iOS/SwiftUI client scaffold over the Rust core.

Known blockers that prevent real-world security claims:

- No external audit.
- No key transparency.
- Client store is still plaintext JSON.
- Relay store is still not production-grade durable storage.
- Recipient mailbox and timing metadata remain visible to the relay.
- Mailbox IDs are stable rather than blinded/rotating.
- Mailbox posting is open and needs real abuse controls.
- Directory fetches can drain one-time prekeys.
- No prekey replenishment path.
- No multi-device.
- No groups.
- No backup/recovery story.
- No continuous post-quantum ratchet.
- Sealed sender metadata protection is classical X25519, not PQ-hybrid.
- Full zeroization is incomplete.
- CI supply-chain hardening is incomplete.
- No formal model or published test vectors.

## 3. Release gates

### Gate A — no real-secret usage

Logos must keep the experimental/unaudited warning until all of the following are
true:

- Protocol audit completed.
- Rust implementation audit completed.
- iOS integration audit completed.
- Relay/infra audit completed.
- Formal model exists for handshake, ratchet, sealed sender, and key transparency.
- Client store is encrypted at rest.
- Relay has persistence, TTL, rate limits, response-size limits, and abuse controls.
- Key transparency is live and audited by clients.
- Prekey replenishment is implemented.
- CI includes fuzzing, dependency auditing, supply-chain checks, and protocol vectors.

### Gate B — no "better than Signal" claim

Logos can only claim to beat Signal on an axis after that axis has:

- a written threat model,
- implementation,
- tests,
- formal or semi-formal analysis,
- external review,
- clear user-facing behavior,
- and production telemetry that does not compromise privacy.

No broad claim should be made. Prefer axis-specific claims, for example:

- "No phone number required."
- "Publicly auditable identity-key history."
- "Hybrid post-quantum sender-metadata envelope."
- "Rotating blinded mailboxes reduce recipient-linkability at the relay."

## 4. Workstream A — local client hardening

Priority: immediate.

### A1. Encrypted client store

Replace plaintext JSON with an encrypted store.

Requirements:

- AEAD-encrypted store file.
- Argon2id passphrase mode for CLI/dev.
- iOS Keychain-wrapped random store key for app mode.
- Keychain access class chosen deliberately for background polling tradeoffs.
- `isExcludedFromBackup = true` by default.
- Optional encrypted export for user-controlled backup.
- Versioned migrations.
- Store corruption detection.
- Atomic writes retained.

Acceptance tests:

- Store file contains no plaintext username, message text, identity key, ratchet key,
  prekey secret, or contact identity.
- Crash during write preserves either old or new valid store.
- Wrong passphrase/key fails closed.
- Migration from plaintext dev store requires explicit opt-in and never happens silently.

### A2. Full zeroization

Zeroize:

- identity secret bytes,
- signed prekey secrets,
- one-time X25519 prekeys,
- ML-KEM prekey secrets,
- PQXDH DH outputs,
- ML-KEM shared secrets,
- ratchet root keys,
- chain keys,
- message keys,
- skipped keys,
- sealed-sender shared secret, derived key, and decrypted plaintext buffer.

Use `Zeroize` / `ZeroizeOnDrop` and avoid unnecessary clones. Where clones are needed
for transactional safety, document the exposure and zeroize staged copies.

### A3. Panic-free FFI boundary

All Rust errors crossing Swift must be typed and recoverable.

Requirements:

- No `unwrap()` / `expect()` on data derived from disk, network, clock, relay, or user input.
- FFI maps security states distinctly:
  - identity changed,
  - not registered,
  - network error,
  - corrupt store,
  - decrypt failed,
  - relay abuse/rate limit,
  - experimental unsupported state.

## 5. Workstream B — relay hardening

Priority: immediate.

### B1. Persistent relay store

Replace in-memory relay state with durable storage.

Persist:

- directory entries,
- one-time prekey queues,
- ML-KEM prekey queues,
- last-resort KEM prekeys,
- mailbox queues,
- ACK state,
- monotonically increasing message IDs,
- server signing key metadata.

Requirements:

- TTL sweep for stale envelopes.
- Durable `next_id`; no restart replay ambiguity.
- Bounded mailbox size.
- Bounded total storage.
- No plaintext logs of usernames, mailbox IDs, IPs, or envelope metadata beyond what is
  strictly necessary for abuse prevention.

### B2. Rate limits and abuse controls

Add layered abuse controls without destroying sealed sender.

Controls:

- Per-mailbox queue cap.
- Per-IP coarse ingress limits.
- Per-delivery-token limits for established contacts.
- Proof-of-work fallback for unauthenticated first contact.
- Anonymous abuse tokens for account/username creation.
- Directory fetch limits to prevent prekey draining.
- Prekey replenishment endpoint.

Acceptance tests:

- Unauthenticated directory fetches cannot exhaust a user into last-resort-only mode.
- Open mailbox posting cannot cause unbounded storage growth.
- Legitimate first contact remains possible without revealing sender identity.

### B3. Response-size caps

Every client response parser must enforce size limits before deserialization.

Minimum caps:

- directory response,
- fetch response,
- envelope ciphertext,
- certificate response,
- server-key response,
- prekey replenishment response.

## 6. Workstream C — key transparency

Priority: highest security differentiator.

Current TOFU pinning blocks key substitution after first contact, but it does not solve
malicious first contact. Key transparency is the fix.

### C1. Transparency log

Build an append-only Merkle log containing:

- username,
- account identity key,
- device identity keys,
- signed prekey commitments,
- ML-KEM prekey batch commitments,
- key rotation events,
- device add/remove events,
- recovery/reset events.

Properties:

- append-only consistency proofs,
- inclusion proofs,
- signed checkpoints,
- public monitors,
- client auditing,
- gossip through normal messages,
- split-view detection.

### C2. Client behavior

On contact start:

1. Fetch directory bundle.
2. Verify signed bundle.
3. Verify transparency inclusion.
4. Verify latest checkpoint consistency.
5. TOFU-pin local identity.
6. Surface verification state to user.

On key change:

- block sending by default,
- show high-friction interstitial,
- preserve old identity record,
- require explicit reset or verified recovery path.

### C3. Claim unlocked

After audit:

> Logos makes identity-key history publicly auditable instead of relying only on
> first-contact trust and manual safety-number comparison.

## 7. Workstream D — continuous post-quantum ratcheting

Priority: required to match modern Signal direction.

PQXDH protects session setup. It does not continuously heal against future quantum
attack after long-running sessions. Add a Triple-Ratchet-style construction.

### D1. Design target

Keep the existing Double Ratchet and mix in a sparse post-quantum ratchet:

```text
classical_step = DoubleRatchetStep(...)
pq_step        = SparsePqRatchetStep(...)
message_key    = KDF(classical_step || pq_step || transcript_context)
```

Requirements:

- no downgrade to classical-only without a visible state transition,
- bounded bandwidth overhead,
- sparse rather than every-message KEM overhead,
- safe behavior after device compromise,
- audited state transitions,
- replay and reordering resistance,
- versioned transcript binding.

### D2. Design questions to settle before code

- Which ML-KEM parameter set for ongoing ratchet?
- How often should PQ epochs rotate?
- How is KEM material chunked across normal messages?
- How many future decapsulation secrets may exist at once?
- What is the UX when a peer does not support continuous PQ mode?
- How are downgrade attempts detected and surfaced?

### D3. Acceptance tests

- Classical ratchet compromise alone cannot reveal future messages after a PQ epoch update.
- PQ ratchet compromise alone cannot reveal future messages after a classical DH ratchet.
- Captured traffic cannot be downgraded to classical-only unnoticed.
- Reordered PQ-ratchet material does not desynchronize the session.
- Old clients fail safely.

## 8. Workstream E — sealed sender plus

Priority: metadata-security differentiator.

Current sealed sender hides sender identity from the relay, but the envelope is protected
with classical X25519 to the recipient identity key. Upgrade it to PQ-hybrid.

### E1. Hybrid sealed sender

Envelope key derivation:

```text
x_shared = X25519(eph_x25519_sender, recipient_identity_dh)
p_shared = ML-KEM.Encapsulate(recipient_metadata_kem_prekey)
key      = HKDF(x_shared || p_shared, transcript)
```

Envelope carries:

- X25519 ephemeral public key,
- ML-KEM ciphertext,
- padded encrypted sender certificate,
- encrypted inner payload.

### E2. Metadata prekeys

Recipient publishes metadata-specific ML-KEM prekeys, separate from session-initiation
prekeys.

Requirements:

- signed by identity,
- rotated/replenished,
- committed into key transparency,
- rate-limited fetch,
- fallback behavior clearly scoped.

### E3. Padding

Add envelope padding classes:

- tiny,
- normal text,
- media pointer,
- group control,
- recovery/control.

Do not leak message type where avoidable.

## 9. Workstream F — blinded rotating mailboxes

Priority: metadata-security differentiator.

Current relay sees a stable recipient mailbox and timing. Replace stable mailboxes with
rotating blinded mailboxes.

### F1. Mailbox derivation

```text
mailbox_id = HMAC(delivery_secret, epoch || sender_context || purpose)
```

Where possible:

- `delivery_secret` is known only to recipient and authorized senders,
- `epoch` rotates on a fixed schedule,
- `sender_context` prevents all senders from using the same mailbox,
- old epochs expire after a grace window.

### F2. First contact

First contact cannot rely on an existing delivery secret. Use a restricted first-contact
mailbox plus abuse controls:

- blinded first-contact token,
- small message size,
- strict rate limit,
- proof-of-work fallback,
- user-visible request inbox.

### F3. Private transport modes

Offer three modes:

| Mode | Description |
|---|---|
| Standard | Direct TLS relay, low latency |
| Private | Onion-routed relay path, slower |
| High-risk | Delayed batching, padding, cover traffic, slowest |

Do not default to high-risk mode unless latency and battery impact are acceptable.

## 10. Workstream G — multi-device and recovery

Priority: product parity and safety.

### G1. Device model

Each account has an identity and each device has its own signed device identity.

```text
account identity
  ├── device identity A
  ├── device identity B
  └── device identity C
```

Requirements:

- every device addition is logged in key transparency,
- contacts can see device changes,
- high-risk chats can require manual approval of new devices,
- device revocation is signed and logged,
- no silent fanout to unknown devices.

### G2. Recovery

Recovery must not create a silent impersonation path.

Options:

- no recovery by default,
- user-exported encrypted recovery bundle,
- social recovery with threshold signatures,
- hardware-bound recovery key.

Every recovery/reset event must be transparent and visible to contacts.

## 11. Workstream H — groups

Priority: product parity.

Near-term:

- small groups using sender-key style encryption,
- explicit membership changes,
- per-device membership visibility.

Long-term:

- MLS/OpenMLS,
- hybrid post-quantum group extensions when practical,
- group transparency log commitments,
- sealed-sender-compatible group delivery.

Requirements:

- no silent member addition,
- auditable membership history,
- post-compromise recovery after member removal,
- metadata-minimized delivery.

## 12. Workstream I — verification, fuzzing, and audits

### I1. Test vectors

Publish vectors for:

- identity encoding,
- safety numbers,
- signed prekey verification,
- ML-KEM prekey verification,
- PQXDH root-key derivation,
- ratchet message encryption/decryption,
- skipped-key behavior,
- sealed sender envelope,
- mailbox ID derivation,
- key-transparency inclusion proof.

### I2. Fuzz targets

Fuzz:

- prekey bundle parser,
- initial message parser,
- ratchet message parser,
- sealed envelope parser,
- relay request parser,
- store loader,
- transparency proof verifier.

### I3. Property tests

Properties:

- forged decrypt does not mutate ratchet state,
- crash after send cannot reuse key/nonce,
- ACK never deletes unprocessed messages,
- prekey replay cannot reset an existing session,
- key substitution is blocked after pinning,
- transparency split views are detected through gossip,
- response-size caps fail closed,
- prekey draining is bounded.

### I4. Formal models

Model:

- PQXDH handshake,
- Double Ratchet state transition,
- continuous PQ ratchet,
- sealed sender certificate binding,
- hybrid sealed sender,
- key transparency assumptions,
- mailbox blinding threat model.

Tools to evaluate:

- Tamarin / ProVerif for protocol properties,
- Kani or similar for Rust state-machine invariants,
- sanitizers/Miri where useful.

### I5. External audits

Separate audits:

1. Protocol design audit.
2. Rust crypto implementation audit.
3. iOS client/storage audit.
4. Relay/infra audit.
5. Key transparency audit.
6. Abuse/privacy review.

## 13. Sequencing

### Phase 0 — hardening foundation

- Encrypted client store.
- Full zeroization.
- Response-size caps.
- Relay persistence.
- TTL sweep.
- Rate limits.
- Prekey replenishment.
- CI supply-chain checks.

### Phase 1 — protocol evidence

- Stable protocol spec.
- Test vectors.
- Fuzz targets.
- Property tests.
- Formal model for current handshake/ratchet/sealed sender.
- First external review.

### Phase 2 — identity superiority

- Key transparency service.
- Client inclusion/consistency verification.
- Gossip checkpoints.
- Device transparency.
- Anonymous registration tokens.

### Phase 3 — continuous PQ

- Triple-Ratchet-style design doc.
- Implementation behind protocol version flag.
- Downgrade detection.
- Formal model.
- External audit.

### Phase 4 — metadata superiority

- Hybrid sealed sender.
- Blinded rotating mailboxes.
- Delivery tokens.
- Envelope padding.
- Private/high-risk transport modes.

### Phase 5 — product parity

- Multi-device.
- Groups.
- Attachments.
- Backups/recovery.
- Push notification hardening.
- Calls, if in scope.

## 14. Definition of done for "Signal-plus"

Logos can be positioned as Signal-plus only when:

- Message content security is at least Signal-class.
- Continuous PQ ratcheting is implemented and audited.
- No phone number or email is required.
- Key transparency is live and client-enforced.
- Sender metadata is PQ-hybrid sealed.
- Recipient mailboxes are blinded/rotating.
- Local storage is encrypted and audited.
- Relay abuse controls are deployed without plaintext visibility.
- Multi-device changes are transparent.
- All major protocol components have test vectors.
- Fuzzing and dependency auditing run continuously.
- External audits are public or summarized with enough detail to be useful.

Until then, the honest product label remains:

> Research messenger. Strong design goals. Not audited. Not for real secrets.
