# Logos Threat Model (condensed)

Scoped to the Phase-1 crypto core. The full program's threat model follows the
"Sealed" design blueprint; this is the subset the current code targets.

## Protected assets

- **Message content** — plaintext of 1:1 messages.
- **Sender identity** — who sent a delivered message (vs. the relay).
- **Long-term identity keys** and **session/ratchet state**.
- **Social graph / metadata** — minimized (full metadata protection is later-phase).

## Adversaries in scope

- **Malicious / compromised relay (server):** can store, reorder, drop, and read
  everything it holds. Logos ensures it holds only opaque ciphertext and (with
  sealed sender) cannot learn the sender. It still learns recipient mailbox +
  timing (mitigated only by later-phase mixnet/onion modes).
- **Network adversary:** passive capture, including **harvest-now-decrypt-later**
  → mitigated by PQXDH hybrid (must break X25519 *and* ML-KEM-1024).
- **Active key-substitution (MITM) at session setup:** mitigated by signed prekey
  bundles + safety-number verification. (Continuous detection needs the
  later-phase key-transparency log.)
- **Malicious peer:** authenticated per-message; tampering/replay across ratchet
  state is rejected (AEAD + header binding).

## Explicitly out of scope

- **Endpoint compromise** (malware on a device while plaintext exists): no
  messenger can defeat this. We reduce blast radius (FS, PCS, key hygiene) only.
- **Global passive traffic-analysis adversary:** the direct transport leaks
  timing/volume; only later-phase mixnet mode raises this cost, and a true global
  adversary can still attempt long-term correlation.
- **Coerced device unlock**, **malicious hardware / RNG**, and **compromised
  build/supply chain** (addressed later via reproducible builds + binary transparency).
- **Metadata beyond sender-hiding** (recipient mailbox, group membership): later phases.

## Current honest residual risks (Phase 1)

- **No key transparency yet** → a malicious directory could substitute a
  contact's identity key at first contact undetected unless users compare safety
  numbers out of band.
- **No relay implemented yet** → recipient/timing metadata protections are design,
  not code, at this phase.
- **Unaudited composition** → forward secrecy / PCS / hybrid guarantees hold only
  if the assembled protocol is correct; this requires an external audit.
