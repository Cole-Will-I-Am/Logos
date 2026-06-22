# Verifiable Introductions — design note & threat-model delta

**Status: DESIGN ONLY. Not implemented. Crypto-touching → gated on external audit before any
build.** This document exists so the feature can be reviewed and, eventually, audited *before*
a line of protocol code is written — per the project rule that security claims follow audits,
never precede them. Nothing here is shipped or promised.

---

## 1. Problem

Today, trust in Logos is established **pairwise**: Alice verifies Bob by comparing a safety
number out of band (in person, over a trusted channel). That's strong, but it doesn't compose.
If Alice has verified both Bob and Carol, and she introduces them, Bob and Carol still start
from **trust-on-first-use (TOFU)** with each other — they have no way to benefit from the fact
that someone they *both* already trust has vouched for each of their keys.

The goal is to let a mutually-trusted introducer transfer a **verifiable** statement — "the key
I verified for Bob is *this* one" — to Carol, so Carol's client can flag a later key mismatch as
a real anomaly rather than silently accepting whatever the relay serves on first contact.

This narrows the one window TOFU leaves open: a malicious relay swapping keys *before* the first
pairwise contact, which a plain safety-number flow can't catch until an out-of-band compare.

## 2. Goals / non-goals

**Goals**
- An introducer can issue a signed, offline-verifiable **introduction voucher** binding a
  contact's username to the exact identity key the introducer verified.
- The recipient's client verifies the voucher against the introducer's *already-pinned* key —
  no new trust root, no server involvement.
- A later key change for the introduced contact is surfaced against the vouched key, turning a
  silent TOFU swap into a loud, attributable warning.

**Non-goals**
- Not a web of trust / transitive auto-trust. A voucher is **evidence**, never automatic
  verification. The user still decides; the UI never says "verified" off a voucher alone.
- Not key transparency (that's the separate, larger F-02 endgame). This composes pairwise trust;
  it does not remove the relay's certificate-issuing authority.
- No new long-lived key material, no new server endpoints in v1 (vouchers ride the existing
  E2EE 1:1 channel).

## 3. Construction (sketch — to be specified precisely under audit)

An **introduction voucher** is a statement signed by the introducer's identity key:

```
voucher = Sign_introducer(
    domain        = "logos-introduction-v1",   // domain separation, prevents cross-protocol reuse
    subject_user  = "@bob",
    subject_idkey = <Bob's full IdentityPublic the introducer has pinned>,   // ed || dh
    safety_number = <the safety number the introducer verified for Bob>,
    issued_at     = <coarse timestamp>,
    audience      = <Carol's identity key>      // binds the voucher to one recipient
)
```

Flow (Alice introduces Bob to Carol):
1. Alice's client constructs `voucher` for Bob, **audience-bound to Carol**, and signs it with
   Alice's identity key.
2. Alice sends it to Carol over their **existing verified 1:1 channel** (it's just a structured
   message; no relay trust needed).
3. Carol's client verifies the signature against **Alice's already-pinned identity key** (Carol
   must already have verified Alice — vouchers from unverified introducers are shown as untrusted
   and never auto-applied). It checks domain, audience == Carol, and freshness.
4. Carol's client stores the voucher as **corroborating evidence** for Bob. When Carol first
   contacts Bob (or if Bob's key later changes), it compares the live key to the vouched
   `subject_idkey`:
   - match → a quiet "vouched by Alice" badge; still requires Carol's own decision to mark verified.
   - mismatch → a **loud** warning ("Alice verified a different key for Bob") — this is the
     attack-catching case.

Key points for the eventual spec: domain-separated signatures, audience binding (no replay to a
third party), bound to the *full* identity (`ed || dh`), and **no transitivity** — a voucher
never sets `verified = true` on its own.

## 4. Security properties (intended)

- **Detects pre-first-contact key substitution** by the relay for an introduced contact, which
  pairwise TOFU alone cannot, *if* the introducer is honest and already verified.
- **No new trust root:** verification chains only to keys the recipient already pinned themselves.
- **Server-blind:** vouchers are E2EE between introducer and recipient; the relay learns nothing
  new and gains no new authority.
- **Non-transitive by design:** evidence, not a verdict — bounded blast radius if an introducer is
  wrong or coerced.

## 5. Threat-model delta (the part that needs scrutiny)

This is exactly where an audit matters; the honest new exposures:

- **Malicious/compromised introducer.** A dishonest Alice can vouch a key she controls for "@bob,"
  steering Carol toward a MITM. Mitigations: voucher is evidence not auto-trust; the UI attributes
  it to Alice by name; Carol can still do a direct safety-number compare; never elevate to
  "verified" without the user. Residual risk: a user who over-trusts a vouched badge. **UX must not
  let a voucher *look* like first-party verification.**
- **Replay / misbinding.** Without audience binding + domain separation, a voucher could be
  replayed to a third party or reused across contexts. Addressed by binding to the recipient's key
  and a versioned domain string — to be verified formally.
- **Metadata to the introducer.** Alice learns Carol and Bob are now connected (she introduced
  them) — inherent to introductions; should be stated plainly in UI.
- **Staleness / revocation.** A voucher attests to a key at a point in time; if Bob rekeys
  legitimately, an old voucher now "mismatches." Needs a revocation/refresh story (coarse
  timestamps + a re-vouch path) so legitimate rekeys don't read as attacks.
- **Coercion.** An introducer compelled to vouch a hostile key. Same bounded-blast-radius
  reasoning; out of scope to fully solve, must be acknowledged.

## 6. UX guardrails (non-negotiable)
- A voucher renders as *"Alice verified this key for Bob"* — clearly second-hand, attributed, and
  visually distinct from the user's own green "Verified."
- A mismatch is loud and blocks nothing silently — it routes into the existing identity-changed
  interstitial.
- The user can always ignore a voucher and verify directly.

## 7. Open questions for the audit
1. Exact signature scheme & encoding (reuse `logos-identity` Ed25519 + domain-sep helpers).
2. Revocation/refresh model for legitimate rekeys.
3. Whether vouchers may be relayed indirectly (extra metadata risk) or strictly 1-hop, in-band.
4. Interaction with future key transparency (does KT subsume this, or complement it?).
5. Group analogue (vouch membership/roster) — likely a separate note.

## 8. Why this is gated
Every item here touches identity, signing, and trust evaluation — the core of a security tool.
Shipping it as unaudited homemade crypto would directly violate the project's stated principle.
The path is: **review this note → formal spec → external audit of the spec → implement → audit the
implementation → only then surface any user-facing "vouched" trust signal.** Until then it stays a
plan.
