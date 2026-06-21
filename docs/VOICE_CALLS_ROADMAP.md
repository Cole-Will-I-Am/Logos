# Voice Calls Roadmap — 1:1, audio-only (future workstream)

> Status: **planning, not scheduled.** This is a "later down the road" capability,
> not part of the current [`SIGNAL_PLUS_BLUEPRINT.md`](SIGNAL_PLUS_BLUEPRINT.md)
> (which is metadata/identity/crypto-focused). Calling stays **experimental and
> unaudited** like the rest of Logos; no "secure calling" claim until audited.

Scope here is deliberately narrow: **1:1, audio only, end-to-end encrypted, and
identity-verified.** Video and group calls are explicitly out of scope (separate,
harder workstreams — see the bottom).

## 0. The key framing

Messaging is **asynchronous store-and-forward** (an opaque mailbox the client polls
every ~3s). A call is **synchronous real-time media** (sub-150ms, continuous UDP
streams). These are *different planes*. Calling does **not** extend the messaging
stack — it adds a parallel real-time stack alongside it. Almost all of the work is
that new plane; the existing crypto/identity layer is reused for *authentication*,
not transport.

## 1. Architecture (target)

- **Media: WebRTC.** Don't hand-roll real-time media. WebRTC provides Opus audio,
  SRTP/DTLS-SRTP encryption, NAT traversal (ICE), jitter buffer, echo cancellation,
  packet-loss concealment, and congestion/bandwidth control. iOS integration uses
  Google's libwebrtc framework (a large binary dependency) bridged into Swift. The
  Rust core does **not** participate in media — WebRTC lives on the native side.
- **Signaling over the existing E2EE channel.** SDP offer/answer + ICE candidates
  are small and can travel as ordinary Logos E2EE messages — so signaling inherits
  Logos's encryption and identity. (Caveat: the 3s poll is too slow for snappy
  setup; signaling needs the low-latency path below.)
- **NAT traversal: STUN + TURN.** Run `coturn` on the VPS. Most calls go
  peer-to-peer (STUN only); ~10–30% (symmetric NAT) fall back to **TURN**, which
  relays the *encrypted* media (can't read it) at real bandwidth cost.
- **E2EE + authentication (the important part).** WebRTC's DTLS-SRTP encrypts media
  between the two endpoints. The DTLS certificate fingerprint is carried in the
  (already-E2EE) signaling and **must be bound to the peer's Logos identity** —
  ideally checkable against the existing **safety number** — so a malicious relay
  can't MITM the media handshake. This is exactly the Signal/WhatsApp model, and
  Logos's verification layer drops straight into it.
- **Ringing: PushKit → CallKit.** A native incoming-call experience (ring,
  lock-screen answer) requires a **VoIP push** (PushKit) that reports immediately to
  CallKit. **Logos has no push today** — this is the gating prerequisite for real
  incoming calls.

## 2. Prerequisites (must land first)

1. **Push notifications** (APNs + a relay→device push path). None exist today; this
   gates incoming-call ringing (Phase V2). Voice calls should come *after* the
   notifications workstream.
2. **A low-latency signaling channel** (WebSocket or push-driven), since the 3s poll
   is too slow for call setup.
3. **FFI/Swift surface** to start / answer / end a call and to ferry signaling blobs
   through the existing client (or do signaling entirely Swift-side over the client).

## 3. Phases

### Phase V0 — Spike & decisions (small)
Pick the bindings and write a design note + tiny proof-of-concept. Decisions to
settle: libwebrtc-iOS vs `webrtc.rs`; coturn deployment + credential model;
signaling encoding and how DTLS fingerprints bind to Logos identity. **Gate:** a
documented design and a throwaway demo of two WebRTC peers connecting with manually
shuttled signaling.

### Phase V1 — Foreground 1:1 audio MVP
Both apps open; a manual **Call** button in the chat. Signaling over the E2EE
channel; ICE with STUN + TURN fallback; DTLS-SRTP media; fingerprints bound to the
verified identity; minimal in-call UI (mute / end / timer / connection state). **No
ringing yet.** **Gate:** a verified, end-to-end-encrypted audio call between two real
devices, including the TURN fallback path.

### Phase V2 — Real incoming calls
PushKit VoIP push + CallKit for native ring / answer / decline from lock screen and
backgrounded/closed app. Full call state machine (ringing / connecting / active /
ended / missed / busy). **Depends on the push prerequisite.** **Gate:** reliably
ringing a closed-app device and answering from the lock screen.

### Phase V3 — Reliability & quality
ICE restart + reconnect on network change (Wi-Fi↔cellular), Opus FEC/DTX for loss
and silence, bandwidth adaptation, basic call-quality metrics, and honest failure
copy ("couldn't connect", "call dropped — reconnecting"). **Gate:** calls survive a
mid-call network switch.

### Phase V4 — Hardening & privacy
Short-lived TURN credentials (no static secrets in the app); minimize signaling
metadata; local-only **call history** (like messages — never on a server);
rate-limit/abuse controls on call setup; threat-model update. **Gate:** threat-model
section merged + abuse controls in place.

## 4. Metadata & threat-model notes

- **Content:** never on any server (DTLS-SRTP end-to-end).
- **Metadata exposed:** the relay/push sees call-setup events + timing; **TURN sees
  IP addresses + bandwidth/timing** (not content). Document this honestly. A later,
  expensive option is an always-relayed / IP-blinding mode for callers who need to
  hide their IP from the peer.
- Calls widen the metadata surface more than messaging — keep that explicit and keep
  the EXPERIMENTAL/UNAUDITED framing on the call UI.

## 5. Effort & dependencies (honest)

- **Gated on push** for a real (ringing) experience; V1 (foreground) can be a
  self-contained spike beforehand.
- **libwebrtc** is a heavy binary dependency (size + maintenance).
- **coturn** is VPS infrastructure with real bandwidth cost on relayed calls.
- Rough shape: V1 ≈ a multi-week effort; V2+ substantially more on top.

## 6. Explicitly out of scope (separate future roadmaps)

- **Video** — incremental on WebRTC once audio works (codecs/bandwidth/UI), but its
  own effort.
- **Group calls** — much harder: needs an SFU + per-sender key management (SFrame /
  insertable streams). A distinct phase, after 1:1 is solid.
- **Call recording** — deliberately excluded (privacy posture).
