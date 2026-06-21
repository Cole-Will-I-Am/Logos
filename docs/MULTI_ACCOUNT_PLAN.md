# Multi-account plan (multiple usernames on one device)

EXPERIMENTAL — design doc, not yet implemented. Goal: let one device hold several
Logos identities — multiple usernames on the **same** relay, and/or identities on
different relays — with a switcher to move between them.

## Why this isn't possible today

The account *is* the on-device identity private key. The app keeps exactly **one
identity per relay**: the store path is derived from the relay URL
(`logos-store.json`, or `logos-store-<relaySlug>.json` for a custom relay), with
history (`logos-history[-<slug>].json`) and avatars (`logos-avatars/`) alongside.
`Session` owns a single `LogosClient`. So:

- Different **relays** can already hold different identities (public vs a private/
  Tailscale relay), but only one identity *per* relay.
- Two **different usernames on the same relay** is impossible — they'd collide on
  the same store path.

The relay itself has no such limit: its directory is keyed by username, and
`register` is idempotent for a matching identity. The constraint is purely
client-side storage + UI.

## Model

Introduce an **Account** = `(accountId, relay, username, identity store)`. Multiple
accounts may share a relay. Exactly one account is **active** at a time (lowest
resource use; mirrors the existing `switchRelay` teardown/reload pattern).

- `accountId`: a stable opaque id (UUID minted at creation), NOT derived from
  relay+username, so a username change or relay move doesn't orphan the store.
- On-disk layout (under Application Support):
  ```
  accounts/
    index.json                     # non-secret: [{id, relay, username, displayName, lastActive, unread}]
    <accountId>/
      store.json                   # the encrypted identity store (per-account key once at-rest lands)
      history.json                 # UI history snapshot
      avatars/                     # local contact photos
  ```
- `index.json` holds only non-secret switcher metadata. It still gets
  `FileProtection` + excluded-from-backup, like the stores.

## Client / Session refactor

- A light `AccountStore` (Swift) owns `index.json`: list/add/remove/setActive,
  per-account unread counts for the switcher.
- `Session` keeps owning ONE `LogosClient`, but its paths key off the **active
  accountId** instead of the relay slug. Switching account = the current
  `switchRelay` teardown (cancel polling, drop client, clear published state) then
  load the selected account's store + history. Background polling runs for the
  active account only (cross-account polling/notifications = a later phase).
- No Rust core changes required for v1 — `create`/`load`/`restore` already take an
  explicit store `path`. Multi-account is a path + UI concern.

## UX

- **Switcher**: tap the identity header (Conversations or Settings) → a sheet
  listing accounts (avatar · username · relay, with unread badges) + "Add account".
- **Add account**: → choose **Create new** (username + relay) or **Restore from
  recovery phrase**. Each new account mints a fresh `accountId` + store dir.
- **Remove account (this device)**: wipes that account's `store/history/avatars`
  locally. Note in copy: this does NOT deregister the username on the relay (the
  identity stays bound to that key; releasing a name needs a deregister endpoint —
  see Future).
- Settings shows the active account and a "Switch account" entry.

## Migration (non-destructive)

On first launch after this ships, detect legacy stores (`logos-store.json` and any
`logos-store-<slug>.json`) and import each into `accounts/index.json` with a fresh
`accountId`, moving (or, safer, copying then marking) the files into
`accounts/<id>/`. Keep a one-release fallback that still reads the legacy path if
the migration is interrupted, so an aborted upgrade can't strand an identity.

## Security notes

- Each account's store is independently encrypted once at-rest encryption lands
  (each derives its own key; the **recovery phrase is per-account**). Pairs with
  the seed-derived identity already added for recovery.
- The switcher must never surface secret material — only `index.json` metadata.
- Removing an account zeroizes/deletes local key material but cannot revoke the
  relay binding (no deregister yet).

## Phasing

1. **Storage refactor + migration** — accountId-namespaced stores, `index.json`,
   legacy import. Single active account; no visible UI change yet. (De-risks the
   data model before UI.)
2. **Switcher UI** — add/remove/switch, restore-as-new-account, unread badges.
3. **Later** — cross-account background polling + per-account notifications; a
   relay `deregister` endpoint so removing an account can free the username.

## Out of scope (v1)

Simultaneous multi-account polling/notifications; syncing accounts across a user's
devices (that's the recovery-phrase / backup story, per-account).
