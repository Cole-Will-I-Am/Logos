# Group chat plan (E2EE groups)

EXPERIMENTAL — design doc, not yet implemented. This is roadmap **P4** (blueprint
Workstream H). It defines how Logos adds **end-to-end-encrypted** group chats with a
Telegram-*like* experience (create a group, member list, admins, name/photo) — but,
unlike Telegram, the relay can never read group messages.

## Non-negotiable: E2EE, not "like Telegram"

Telegram's group chats (and normal cloud chats) are **client–server encrypted — the
server can read them**; only 1:1 "Secret Chats" are E2EE and they can't be groups. A
literal "like Telegram" group would let the Logos relay read group messages, which
breaks the project's whole premise (untrusted relay; "not even us") and the rule we
hold everywhere: *never imply privacy the code doesn't have.* So Logos groups are
**E2EE** — the UX borrows from Telegram, the trust model does not. This must stay true
through every phase; no "groups are encrypted in transit" half-measures.

## Two crypto approaches

### A. Sender-key small groups (Signal-style) — recommended v1

Each member holds a **sender key**: a symmetric hash-ratchet *chain key* (derives
per-message keys, ratcheting forward for forward secrecy) plus a *per-group signature
keypair* (signs each message so members authenticate the sender without pairwise
crypto). Mechanics:

- **Distribution:** on join, each member sends a `SenderKeyDistribution` (current chain
  state + signature public key) to every other member **over the existing pairwise
  Double Ratchet sessions** — so it's E2EE + authenticated by the 1:1 identity binding.
- **Send:** ratchet your chain → derive a message key → AEAD-encrypt → sign → produce
  **one** ciphertext.
- **Receive:** each member already has the sender's sender key → derives the same key,
  verifies the signature, decrypts.
- **Fan-out (v1):** the sender posts that one ciphertext to **each member's existing
  mailbox** (N−1 posts). *No relay change* — reuses the 1:1 mailbox + sealed sender.
- **Membership:** *add* = existing members send their sender keys to the newcomer (and
  the newcomer distributes theirs); the newcomer can't read history (forward secrecy).
  *Remove* = **everyone rotates their sender key** and redistributes to the remaining
  members (O(N)) so the removed member can't read future messages. Rekey-on-removal is
  mandatory.

Pros: builds directly on what Logos has (pairwise sessions + relay mailboxes); O(1) per
message; ships soonest. Cons: O(N) rekey on member removal; weaker post-compromise
security than the pairwise Double Ratchet (no DH ratchet in the sender chain); no
built-in transcript-consistency guarantee (a selective relay can show members different
message sets). Good for small/medium groups.

### B. MLS (RFC 9420, `openmls`) — the durable answer (P4.1)

TreeKEM gives **O(log N)** membership/rekey, strong forward secrecy + post-compromise
security at group scale, async operation, and a real standard. The correct long-term
target. Cost: a large state-machine integration (epochs, proposals/commits, welcome
messages, group-state persistence + sync) and the relay must act as an ordered
**delivery service** (commits must be applied in a consistent order). Multi-week.

### Recommendation

**Sender-key v1 (P4.0) first, MLS (P4.1) as the upgrade.** Sender-key gets real E2EE
groups onto the existing foundation quickly and teaches us the relay/UI/membership
shape; MLS replaces the crypto core once groups prove out and key transparency lands.
Be explicit in-product that v1 is small-group-oriented.

## Relay

- **v1 = per-member posting (no relay change).** The sender posts the identical envelope
  to each member's mailbox. The relay still can't read content (sealed sender), but it
  **sees N mailboxes receive correlated, same-size envelopes at the same time** → it can
  infer group membership, size, and timing. This metadata leak is the main v1 cost;
  document it honestly in-product.
- **Later option = a group mailbox + relay fan-out:** less client bandwidth, but the
  relay then learns group membership explicitly and needs authenticated group reads —
  more relay trust. Defer.
- **Metadata mitigations** (envelope padding, cover traffic, blinded/rotating mailbox
  ids, mixnet) are blueprint **P5**; groups make them more valuable.

## Membership, identity, verification

- A group = `{group_id (random), name, members: [(username, pinned identity)], admins,
  optional avatar}`. Membership + name are shared group state; the avatar can start
  local-only.
- **Admins** manage add/remove/rename (the Telegram-like surface). Removal triggers the
  mandatory rekey.
- **Verification at scale:** each member is still TOFU-pinned via their pairwise session;
  the per-group signature key is bound to that identity at distribution time. Verifying N
  members by hand doesn't scale — this is where **key transparency** (still unbuilt; the
  F-02 endgame) becomes important. Until then, surface each member's verified state and
  warn on unverified members.
- **Trust reality:** any group of N has N parties who can leak content; a removed member
  keeps messages they already received. These are inherent and must be stated plainly.

## Client / store / wire

- `logos-proto`: a `Group` record, a `SenderKeyDistribution` message (sent inside the
  pairwise `OuterMessage`), and a group message type (`group_id` + sender-key ciphertext
  + signature). The relay wire (post/fetch) is unchanged for v1 (per-member posting).
- `logos-client`: group state in the `Store` (group_id → group + my sender chain + peers'
  sender keys); APIs `create_group`, `add_member`, `remove_member`, `send_group`; `recv`
  routes inbound group envelopes by `group_id` and verifies the per-message signature.
- Sender-key chain can reuse the existing HKDF/HMAC primitives (a symmetric KDF ratchet);
  no new dependency for v1. MLS (P4.1) adds `openmls`.

## iOS surface

- Create group (pick from **contacts** → name → create), group chat view (sender name +
  avatar per message), member list + admin controls (add/remove/rename), group settings.
  Reuses the contacts address book as the member picker.

## Threat-model deltas (vs 1:1)

- N parties → any member can leak; removed members retain received history.
- Relay can drop/reorder/inject per member (handled by per-message AEAD + signature) but
  there's **no transcript-consistency guarantee** in sender-key v1 (MLS improves this).
- Relay infers group membership/size/timing from the fan-out pattern (metadata).

## Prerequisites / sequencing

- **M1 prekey lifecycle (open 1:1 follow-up) is a soft prerequisite:** sender-key
  distribution rides pairwise sessions, which consume one-time prekeys; groups multiply
  the number of pairwise handshakes, so client-side prekey replenishment should land
  first so group setup doesn't fall back to last-resort keys.
- **Key transparency** strengthens member verification; valuable before any public
  "trusted groups" claim.

## Phasing

1. **P4.0a — protocol + static group:** wire types, sender-key crypto, group state in the
   store, create/send/recv for a fixed-membership group (no add/remove). Per-member
   posting. Rust tests + a CLI group demo.
2. **P4.0b — membership:** add/remove with rekey-on-removal, admins, invites.
3. **P4.0c — iOS UI:** create/group-chat/member-list/admin, contacts as the picker.
4. **P4.1 — MLS migration:** replace the sender-key core with `openmls`; relay becomes an
   ordered delivery service; migration path for existing groups.
5. **Cross-cutting:** key transparency (member verification), P5 metadata mitigations.

## Open decisions (resolve before P4.0a)

- Per-member posting vs a relay group mailbox for v1 (recommended: per-member).
- Max group size for v1 (sender-key cost is O(N) on join/remove — suggest a soft cap,
  e.g. ≤ 32, surfaced in UI).
- Group name/avatar: shared state vs local-only to start (suggest name shared, avatar
  local v1).
- Whether to require all members verified before sensitive use (suggest: warn, don't
  block, until key transparency).

## Implemented status (P4.0a + P4.0b)

P4.0a (static group: create/send/recv) and P4.0b (membership: add/remove with
rekey-on-removal, admins, rename) are implemented in `logos-ratchet::senderkey`,
`logos-proto` (`OuterMessage::{GroupCtrl,Group}`, `GroupControl`, `GroupMeta`,
`SenderKeyDist`), and `logos-client` (`create_group`/`send_group`/`add_member`/
`remove_member`/`rename_group`), with the M1 client-side prekey replenishment prereq.
Bootstrap rides the pairwise Double Ratchet (E2EE + identity-bound), uses a
**canonical-initiator rule** (`me < peer` initiates when no session exists; the other
replies over the established session) to avoid simultaneous pairwise initiation, and an
out-of-order pending-key buffer. Membership changes are admin-issued, **epoch**-versioned
`GroupUpdate`s; sender keys carry a **generation** so a rekey REPLACES (rather than is
ignored as a duplicate). Adversarially reviewed; the fixes from that review are applied.

## Known limitations (sender-key v1) — accepted for now, fix later

These are documented gaps the review surfaced that need larger mechanisms (out of P4.0b
scope); none is a confidentiality break, but they affect availability/robustness:

- **Simultaneous mutual session establishment.** If two members who have *no* prior 1:1
  session both initiate to each other at the same instant (e.g. concurrent group creation
  naming each other), each drops the other's handshake (the inbound-prekey replay guard).
  This is the pre-existing 1:1 limitation surfaced by group bootstrap; the canonical-
  initiator rule avoids it for member↔member distribution, but the creator's initial
  invite can still collide. Real fix: session tie-breaking in the 1:1 layer.
- **Best-effort fan-out, no delivery acks.** `send_group` posts one ciphertext per member;
  a transient relay failure to one member loses that message for them (others still get
  it; the sender chain has advanced). Needs a persistent per-member outbound retry queue.
- **Quarantine cap vs deferred group setup.** A group message that arrives before its
  sender key shares the 5-poll quarantine cap with never-decryptable envelopes; under
  unusual delay it could be dropped before the key arrives. Needs age-based or
  group-aware quarantine. (In practice keys arrive within a couple of polls.)
- **Bootstrap-race early-message loss.** A member that sends a group message *before*
  finishing sender-key distribution leaves not-yet-keyed members unable to read those
  early messages (they receive the sender's current/advanced chain state). Distribute
  before sending; storing iteration-0 forever would defeat at-rest forward secrecy.
- **No transcript consistency / membership consistency.** A malicious relay can show
  different members different message sets or withhold a `GroupUpdate` from some members
  (already noted above). MLS (P4.1) addresses this. Removed members are not notified.
