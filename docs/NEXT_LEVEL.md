# Next-Level Program

A product/UX track layered on top of the Signal-plus blueprint. The thesis: Logos is
the only system that is simultaneously **true E2EE + on-device private AI +
post-quantum + metadata-resistant + identity-not-phone-number**. The highest-value
features are the ones that intersection *uniquely enables* — not generic chat parity.

> **Status:** EXPERIMENTAL & UNAUDITED. Nothing here is a security claim. This doc
> tracks intent and sequencing, not guarantees.

## Guiding rule for this track

Client-side and UI work can ship through normal review. **Anything that touches the
cryptographic protocol, the wire format, the ratchet, or the relay's trust model is
design-and-audit-gated**: it gets a design note + a `THREAT-MODEL.md` update + review
*before* implementation, and it does not ship as a blind implementation. This is the
same principle the README states — security claims follow audit, never precede it.

## Risk tiers

- **A — Client-only.** No protocol/wire/relay change. Pure app code. Normal review.
- **B — Additive wire.** Small, backward-compatible proto/relay additions. Needs
  versioning, back-compat with deployed clients/relay, and CI. Careful but tractable.
- **C — Cryptographic / protocol design.** New signed types, ratchet/transport
  changes, or trust-model shifts. Requires a design doc, threat-model update, and
  external review/audit before merge. **Do not ship blind.**

## Status legend

DONE · IN PROGRESS · DESIGN NEEDED · TODO

---

## Pillar 1 — Private AI as a lens over your encrypted life

The moat. On-device by default; cloud only behind explicit per-action consent; the
relay is never in the path.

| Feature | Tier | Status | Notes |
|---|---|---|---|
| **Loose Ends** — on-device pass for unanswered questions, promises, deadlines | A | **DONE (v1, ephemeral)** | `LooseEndsView.swift`. Inbox entry → results open the chat. Ephemeral by design (nothing message-derived at rest). |
| Loose Ends v2 — persistent, encrypted-at-rest, resolve-memory | A/B | TODO | Persist via the encrypted client store (not plain UserDefaults) so derived content keeps the at-rest posture. Merge re-scans by (peer, normalized text). |
| **Local semantic search** across all conversations | A | DESIGN NEEDED | On-device embeddings over the encrypted history; cross-chat recall. Pick an embedding path (Apple NL embeddings vs. a bundled small model). Index must live encrypted at rest. |
| **Tone preview before send** — private "how will this land?" on a draft | A | TODO | On-device only (never send a *draft* to cloud). Optional composer affordance; flag harsh/ambiguous, offer a softer rewrite. Reuses `AIClient` on-device path. |
| **Morning brief** — on-device daily digest across threads | A | TODO | Builds on Loose Ends + catch-up. Optional local notification; generation stays on-device. |
| Ambient on-device translation (original one tap away) | A | TODO | Local translation of inbound; always reversible to source. Pairs well with E2EE (translation provably never hit a server). |

## Pillar 2 — Cryptographic identity as a social primitive

Only a key-based, username-first system can do these tastefully.

| Feature | Tier | Status | Notes |
|---|---|---|---|
| **Identity passport** — signed, scannable identity card | B | DESIGN NEEDED | Extends existing QR (`LogosQR`). Scanning TOFU-pins the real key, not a spoofable handle. Mostly additive, but define the signed payload + verification carefully. |
| **Verifiable introductions** (web of trust, consumer-grade) | C | DESIGN NEEDED | Alice signs an introduction carrying her *already-verified* safety number for Bob, so Carol starts from "vouched by someone you verified." New signed type in the core (`logos-identity`) + threat-model work. Keep transitive vs. direct verification visibly distinct. **Audit-gated.** |
| **Duress unlock** — second passphrase → decoy/locked state | B/C | DESIGN NEEDED | Ties into `StoreKey` / Argon2id store. Get the security model right (no oracle that reveals a decoy exists). **Audit-gated.** |

## Pillar 3 — Make the invisible security tangible

Turn the honest threat model into a trust surface competitors can't copy.

| Feature | Tier | Status | Notes |
|---|---|---|---|
| **"What the relay sees" panel** | A | **DONE** | `RelayVisibilityView.swift` → Settings ▸ Privacy & security. Plain-language can/can't-see + an honest "not closed yet" section straight from `THREAT-MODEL.md`. |
| **Post-quantum status, made legible** — per-chat "Quantum-secure" signal | B | DESIGN NEEDED | Requires the core/FFI to expose which handshake a session used (PQXDH/ML-KEM-1024). Add an FFI getter; surface a quiet badge + one-tap explainer. |
| **Sealed-sender, visualized** — teach the "delivered without knowing who" moment | A | TODO | Small explainer/animation on first sealed receipt. Pure UI. |
| **"Static" mode** — padding + scheduled cover traffic per conversation | C | DESIGN NEEDED | Maps to the blueprint's envelope-padding / high-risk transport. Surface as a shield the user raises. Real metadata-defense design + relay coordination. **Audit-gated.** |

## Parity to close (with a Logos twist)

The inert thread needs these to retain Signal/iMessage refugees.

| Feature | Tier | Status | Notes |
|---|---|---|---|
| Reactions | B | TODO | Small typed wire addition; back-compat for clients that don't understand it. |
| Replies / quotes | B | TODO | Reference a prior message id on the wire; render a quoted stub. |
| Edit / delete-for-everyone | B | TODO | Tombstone/replace semantics; define what the relay/peer can infer. |
| Typing & read receipts (between people) | B | DESIGN NEEDED | Privacy-sensitive: must be opt-in and must not leak more metadata to the relay. |
| Voice notes — **transcribed on-device** | A/B | TODO | Local transcription (Apple Speech): searchable, accessible, never sent to a server; feeds Pillar 1 search. |
| Disappearing messages — **delete the key, not just the UI** | C | DESIGN NEEDED | Cryptographic expiry (drop ratchet material), provably gone. Ratchet-adjacent. **Audit-gated.** |

---

## Done in the first build pass (branch `feature/next-level`)

1. **"What the relay sees" panel** (Pillar 3, Tier A) — `RelayVisibilityView.swift`,
   linked from Settings.
2. **Loose Ends v1** (Pillar 1, Tier A) — `LooseEndsView.swift`, inbox entry +
   on-device extraction, ephemeral.

> iOS was **not** compiled in the authoring environment (no macOS/Xcode). Both
> features are written against the existing `Session` / `AIClient` / design-system
> APIs and pass structural checks, but need a Mac or the macOS CI runner to build and
> a device pass to verify before merge.

## Recommended sequencing

1. **Land the two Tier-A features above** (build on CI, device QA, merge). Add the
   remaining Tier-A items next: sealed-sender explainer, tone preview, Loose Ends v2.
2. **Tier-A parity + voice notes** in parallel — cheap retention wins.
3. **Tier-B with care:** reactions, replies, edit/delete, identity passport,
   PQ-status FFI getter + badge. Each needs wire versioning and back-compat with the
   live relay and deployed TestFlight clients.
4. **Tier-C only behind design docs + threat-model updates + external review:**
   verifiable introductions, duress unlock, Static mode, key-deleting disappearing
   messages. These are the most differentiated *and* the most dangerous to get wrong —
   they gate on the same audit the rest of Logos does.

## Suggested PR split

Don't merge this as one branch. Suggested PRs: (1) relay-visibility panel,
(2) Loose Ends v1, (3) sealed-sender explainer, (4) tone preview, then Tier-B/C each
as its own reviewed PR with its design note.
