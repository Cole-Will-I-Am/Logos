# Logos Protocol (Phase 1 crypto core)

This document specifies exactly what the Phase-1 crates compute, so the
construction can be reviewed/audited. **EXPERIMENTAL — UNAUDITED.**

Notation: `||` concatenation; `DH(a, B)` = X25519 Diffie–Hellman of secret `a`
with public `B`; `HKDF` = HKDF-SHA256; `HMAC` = HMAC-SHA256; `AEAD` =
ChaCha20-Poly1305.

## 1. Identity (`logos-identity`)

Each identity has two keypairs (documented deviation from Signal's single XEdDSA
key, to stay on audited `*-dalek` APIs):

- **Signing:** Ed25519 `(ik_sig_priv, ik_sig_pub)`.
- **DH:** X25519 `(ik_dh_priv, ik_dh_pub)`.

`IdentityPublic.encode() = ik_sig_pub(32) || ik_dh_pub(32)`.

**Prekey bundle** (published to the directory, fetched to start a session):
identity public, a signed X25519 prekey `SPK` (Ed25519 signature over `SPK_pub`),
an optional one-time X25519 prekey `OPK`, and a signed **ML-KEM-1024** prekey
`KPK` (signature over the encapsulation-key bytes). `verify()` checks the `SPK`
and `KPK` signatures bind to the identity.

**Safety number:** `SHA256("logos-safety-number-v1" || min(encA,encB) ||
max(encA,encB))`, rendered as 6 groups of 5 digits.

## 2. PQXDH handshake (`logos-pqxdh`)

Initiator A, responder B. A fetches and **verifies** B's bundle, then:

```
EK_A            = fresh X25519 ephemeral
DH1 = DH(ik_dh_A, SPK_B)
DH2 = DH(EK_A,    ik_dh_B)
DH3 = DH(EK_A,    SPK_B)
DH4 = DH(EK_A,    OPK_B)          # only if a one-time prekey is present
(KEM_CT, SS)    = ML-KEM-1024.Encapsulate(KPK_B)

F   = 0xFF repeated 32 times       # single-curve domain separator (X3DH)
IKM = F || DH1 || DH2 || DH3 [|| DH4] || SS
info = SHA256("LogosPQXDHv1-transcript" || enc(IK_A) || enc(IK_B) || EK_A_pub || KEM_CT)
RK   = HKDF(salt = 0^32, ikm = IKM, info = info)   # 32-byte root key
```

The **initial message** carries: `IK_A`, `EK_A_pub`, the selected prekey ids, and
`KEM_CT`. B re-derives the identical `DH1..DH4`, decapsulates `KEM_CT` with its KEM
secret to get `SS`, and computes the same `RK`.

- **Hybrid** (caveat below re: reusable KEM prekey): recovering `RK` requires breaking both X25519 (the DH legs) and
  ML-KEM-1024 (`SS`).
- **Transcript binding:** identities, ephemeral, and KEM ciphertext are bound via
  `info`, so a tampered/downgraded handshake yields a different key (tested).
- `DH4` is included iff a one-time prekey was used; the initial message signals
  this so both sides agree on the `IKM` layout.

`RK` seeds the Double Ratchet. B's `SPK` is the ratchet's initial DH key.

## 3. Double Ratchet (`logos-ratchet`)

Standard Double Ratchet (Perrin/Marlinspike) over the primitives.

```
KDF_RK(rk, dh)  : okm = HKDF(salt=rk, ikm=dh, info="LogosRatchetRootKDFv1", 64)
                  -> (rk' = okm[0..32], ck = okm[32..64])
KDF_CK(ck)      : mk = HMAC(ck, 0x01);  ck' = HMAC(ck, 0x02)
mk -> AEAD      : okm = HKDF(salt=0^32, ikm=mk, info="LogosRatchetMsgKeyv1", 44)
                  -> key = okm[0..32], nonce = okm[32..44]
```

Each message key is unique, so the fixed-per-message derived nonce can never
repeat (critical for ChaCha20-Poly1305). The header `(dh_pub, pn, n)` is bound as
associated data: `AD = caller_ad || dh_pub || pn_be || n_be`. Out-of-order
delivery is handled by storing skipped message keys, bounded by `MAX_SKIP = 1000`.

DH-ratchet, symmetric-ratchet, and skip logic follow the spec exactly
(`init_initiator` / `init_responder`, `encrypt`, `decrypt`).

## 4. Sealed sender (`logos-sealed`)

**Sender certificate** (issued by the registration service, which holds an
Ed25519 server key): signature over
`"LogosSenderCertv1" || username || 0x00 || enc(identity) || expires_be`.

**Seal** to recipient R (their `ik_dh_R`):

```
E              = fresh X25519 ephemeral
shared         = DH(E_priv, ik_dh_R)
(key, nonce)   = HKDF(salt = E_pub || ik_dh_R, ikm = shared, info="LogosSealedSenderv1", 44)
plaintext      = postcard(SealedContent{ cert, payload })
ciphertext     = AEAD(key, nonce, plaintext, ad = E_pub || ik_dh_R)
envelope       = { E_pub, ciphertext }
```

The relay sees only `{ mailbox_id, envelope }` — no sender. R derives the same
`shared` with `ik_dh_R_priv`, decrypts, then **verifies the certificate** against
the known server key and checks expiry before trusting the sender identity.

## Session continuity & sender identity (Phase 2)

- The relay-issued sealed-sender **certificate is delivery authorization only**.
  A message's true sender identity is the **PQXDH initiator identity**, which the
  handshake proves (DH1 = DH(IK_A, SPK_B) only matches if the initiator holds
  IK_A's private key). The client therefore requires
  `cert.sender_identity == initial.initiator_identity`.
- **TOFU pinning:** the client records each contact's identity on first sighting
  (directory fetch or first inbound prekey message) and **refuses** a later
  mismatch — blocking a malicious relay from forging a certificate to impersonate
  or to reset/hijack a known contact's session. Continuous detection still needs a
  key-transparency log (future work).
- **No prekey-replay session reset:** an inbound prekey (session-initiation)
  message for a contact that **already has a session** is ACK-dropped, never used
  to re-establish. Otherwise replaying the captured initial envelope — which
  re-derives the same root key whenever the handshake fell back to the reusable
  last-resort KEM prekey / used no one-time X25519 prekey — would clobber the live
  ratchet and break the conversation. A genuine re-key therefore requires an
  explicit, out-of-band session reset (future UI work).
- **Idempotent receive:** the client only ACKs (deletes) an envelope after it is
  durably processed; a replayed/duplicate message that no longer decrypts on a
  live session, and unsealable/garbage envelopes, are ACK-dropped so they cannot
  accumulate and be re-fetched on every poll.

## Known limitations / open items

- **Relay is the certificate authority.** A fully malicious relay can mint certs
  for *new* (not-yet-pinned) usernames. Real fix: key transparency + separate/
  blinded issuer. TOFU mitigates this for established contacts only.
- **Mailbox fetch is authenticated + ACK-based** (F-04/F-07): `/v1/fetch` and
  `/v1/ack` require an identity-key signature, the server derives the mailbox from
  the proven identity (only the owner can read), and envelopes are deleted only
  when the client ACKs them after durable processing. (Mailbox ids are still
  *stable* — derived from the recipient DH key — so blinded/rotating ids remain
  future work, but they can no longer be read or drained without the private key.)
- **One-time ML-KEM prekeys + last-resort** (F-05): each handshake consumes a
  one-time signed ML-KEM prekey (deleted after use); a reusable last-resort prekey
  is used only when the pool is depleted. So the "breaking both X25519 *and*
  ML-KEM" property holds with PQ forward secrecy for one-time-prekey sessions;
  only sessions that fell back to the last-resort key share its longer-lived
  secret (until it is rotated).
- **Mailbox posting is open by design** (any sender can deliver a sealed
  envelope), bounded only by a per-mailbox length cap on the relay. Rate limiting
  and TTL sweeping are future work.
- **One-time prekeys can be drained by unauthenticated directory fetches** (each
  fetch consumes one X25519 + one ML-KEM one-time prekey); there is no
  replenishment path yet, so a drained user falls back to the reusable last-resort
  KEM prekey + no one-time X25519 prekey for new sessions. Rate limiting +
  replenishment are future work.
- Single device per identity; no multi-device fan-out.
- Client store is plaintext JSON (Argon2id encryption-at-rest planned).
- The composed protocol is **unaudited**.
