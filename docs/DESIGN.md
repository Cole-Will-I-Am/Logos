# Logos — Product & UX Design

Design system, screen specs, interaction states, and a prioritized risk list for the
Logos iOS app. Companion to the implementation in `ios/LogosApp/Sources/` (a working
SwiftUI design system + redesigned screens shipped alongside this doc).

> Status of the app when this was written: a functional SwiftUI scaffold over the Rust
> core. The FFI exposes only `create/load`, `send`, `recv`, `username`, `mailbox`. No
> fingerprint, timestamps, delivery receipts, or typed errors yet. Everything below is
> written to that reality, with a clearly-marked **FFI additions** section for the few
> places the UI needs the core to tell it more.

---

## 1. Diagnosis

The scaffold works and the crypto story underneath is serious. But the UI today is
*generic iOS* — `List` + `roundedBorder` text fields + system defaults. It looks like a
demo, not a product, and worse, **it lies about security in one specific, dangerous
way**:

> **The trust bug (was the #1 risk).** `Session.send` appended the bubble *before*
> `client.send`, and the only error sink (`lastError`) was rendered solely on the
> onboarding screen. So a MITM/TOFU refusal or a dropped network send rendered as a
> normal, "delivered"-looking bubble. That is the single worst thing a security product
> can do: silently imply a message was sent securely when it wasn't. **This is now
> fixed** — see §6.1.

Beyond that, four things hold Logos back from feeling premium and trustworthy:

1. **No visual identity.** The brand is distinctive (a classical column, warm gold on
   cream — "Logos" = reason/word) but none of it reaches the screen. Default SF + system
   blue tint reads as "unfinished," which for a *security* app reads as "untrustworthy."
2. **Security is invisible or absent, never *contextual*.** There's no quiet "encrypted"
   state, no loud "identity changed" state, no verification path. Trust UX is the entire
   point of this category and it's the most underbuilt surface.
3. **Developer warts leak to users.** A raw `http://127.0.0.1:8787` relay field on the
   first screen, "Create account" (implies a server account; there isn't one), an inline
   "New chat" form glued to the top of the list.
4. **The list and thread carry no information.** No avatars, no delivery state, no
   timestamps, no unread treatment — nothing to scan.

The opportunity: Logos can occupy a real gap. **Signal** is trustworthy but austere and
utilitarian. **Telegram** is glossy but its defaults aren't E2EE and it feels busy. A
*calm, warm, considered* messenger — premium without being flashy, honest about being
experimental — is a position neither occupies.

**North star:** *quiet confidence.* When everything is fine, the app is calm and gets
out of the way. When something is wrong, it becomes unmistakable. The interface never
brags about security and never hides a problem.

---

## 2. Visual design system

Implemented in `Sources/DesignSystem.swift`. Tokens below match the code.

### 2.1 Color — "warm paper / warm charcoal"

A warm neutral base with **one** accent (gold, from the brand mark). No second accent.
Greens/ambers/reds are reserved *strictly* for security semantics so they always mean
something.

| Token | Light | Dark | Use |
|---|---|---|---|
| `canvas` | `#FAF7F1` | `#15120D` | App background |
| `surface` | `#FFFEFB` | `#1C1813` | Cards, rows, sheets |
| `surfaceAlt` | `#F1ECE2` | `#262019` | Inbound bubble, chips, fields |
| `hairline` | `#E7E0D4` | `#2E2820` | 1px separators / borders |
| `ink` | `#1A1714` | `#F4EFE6` | Primary text |
| `inkSecondary` | `#6B6357` | `#A89C88` | Secondary text |
| `inkTertiary` | `#9A9180` | `#6F6557` | Timestamps, hints |
| `gold` | `#B0894F` | `#CBA468` | Fills, send button, mark |
| `goldText` | `#8A6A38` | `#D9B777` | Gold *text/icons* (contrast-tuned) |
| `onGold` | `#231D12` | `#1A140A` | Text/glyphs **on** a gold fill (dark both modes) |
| `bubbleMine` | `#EFE2C7` | `#322817` | Outbound bubble (soft gold tint) |
| `verified` | `#3E7D55` | `#6FBF8C` | Only after safety-number compare |
| `caution` | `#B2741A` | `#E0A23E` | Identity changed |
| `danger` | `#C0392B` | `#E3675B` | Failed / can't decrypt |

**Decisions worth defending:**
- **Bubbles are soft *tints* with ink text, not solid-accent fills.** Solid-color bubbles
  are the iMessage/Telegram signature; tinted bubbles read calmer, more premium, and
  pass contrast (white-on-gold fails AA at ~2.6:1). Mine = gold-tinted, theirs = neutral
  warm — distinguishable by hue *and* alignment.
- **The dark mode is warm near-black (`#15120D`), not pure black or cool gray.** This is
  the single biggest "premium" lever and it costs nothing.
- **Gold is never the "secure" color.** "Encrypted" is quiet (gold-ink lock, no fill).
  A loud green only appears once a user has *actually verified* a safety number. Don't
  spend the trust color on a state you haven't earned.

### 2.2 Typography — serif display + sans body

The signature is a **serif** (Apple's "New York", `.serif` design) used *only* for the
wordmark, screen titles, and avatar monograms, paired with the system sans for all UI
text. This ties to the classical brand and instantly differentiates from every
sans-only competitor. Everything scales with Dynamic Type.

| Token | Spec | Use |
|---|---|---|
| `display` | largeTitle · serif · bold | "Logos" wordmark, hero |
| `title` / `title3` | title2/title3 · serif · semibold | Screen + section titles |
| `headline` | headline · sans · semibold | Names, row titles, buttons |
| `body` | body · sans | Messages, fields |
| `subhead` / `footnote` / `caption` | sans | Secondary, hints, labels |
| `mono` | body · monospaced | Safety numbers, addresses, relay URL |

### 2.3 Spacing, radius, motion

- **Spacing** (4-pt base): `xxs 4 · xs 8 · sm 12 · md 16 · lg 24 · xl 32 · xxl 48`.
- **Radius:** bubbles `18`, cards `16`, controls `14`, pills full. Continuous corners
  everywhere — rounded but not cartoonish.
- **Motion:** `micro 120ms` (press/toggle), `standard 220ms` (disclosure, scroll),
  `bubble = spring(0.34, 0.82)` (send). All interruptible; gate decorative motion behind
  `accessibilityReduceMotion`.

### 2.4 Iconography

SF Symbols, `.medium`/`.semibold`, monoline. Security vocabulary is fixed so a glyph
always means the same thing:

| Meaning | Symbol | Color |
|---|---|---|
| Encrypted (quiet) | `lock.fill` | goldText |
| Verified | `checkmark.shield.fill` | verified |
| Identity changed | `exclamationmark.shield.fill` | caution |
| Not delivered | `exclamationmark.circle.fill` | danger |
| Can't decrypt | `lock.trianglebadge.exclamationmark` | danger |
| Experimental build | `flask.fill` | inkSecondary |
| Logos mark | `building.columns.fill` | gold |

`building.columns.fill` is the column-portico that mirrors the brand mark — used as the
app's recurring glyph (onboarding, empty states) until the real vector mark is bundled.

### 2.5 Components (in `DesignSystem.swift`)

`LAvatar` (deterministic monogram, thin colored ring) · `SecurityChip` (6 levels, icon +
label + color, with VoiceOver label) · `LBanner` (neutral/caution/danger) · `LEmptyState`
· `LogosPrimary/SecondaryButtonStyle` · `cardStyle()` / `logosBackground()` modifiers ·
`Haptic`.

---

## 3. Core screens

### 3.1 Onboarding (`OnboardingView`)
Column mark + serif "Logos" + one honest line: *"End-to-end encrypted messages. No phone
number, no email."* A single `@username` field. **The relay URL moves into a collapsed
"Advanced" disclosure** with a real default — normal users never see a raw URL. An
expandable *"How encryption works"* card explains E2EE in three plain sentences (no wall
of text). The CTA is **"Create your identity"** (not "account"). A persistent, honest
footer: *"Experimental build — not security audited."*

### 3.2 Chat list (`ConversationsView`)
Quiet and scannable. Title is `@username`; **compose moves to a toolbar pencil → sheet**
(the inline form is gone). Rows: avatar · name · last-message preview · time · a security
glyph **only when it carries information** (verified ✓ / identity changed !). Encrypted is
the silent default. A dismissible "Experimental build" banner sits at the top of the
list, not in your face forever. Empty state teaches: *"No conversations yet. Start one —
your messages are end-to-end encrypted from the very first hello."*

### 3.3 Thread (`ChatView`)
Soft tinted bubbles, comfortable rhythm, selectable text. The title is tappable → opens
verification, with a tiny quiet status line beneath it (*"End-to-end encrypted"*). A
one-time **first-session chip** appears in an empty thread. Outbound bubbles carry an
honest **status row** (see §4). Composer: attach affordance, a growing field, and a send
button that fills gold only when there's something to send, with a soft haptic on send.

### 3.4 Verify identity (`VerifyView`)
The safety-number screen. Designed in full; honest that this build can't yet compute the
number (needs the fingerprint FFI — §7) and **does not fake a "verified" state**. Shows
the intended layout: grouped safety number, *Scan QR* + *Mark verified*, and the key
copy: *"Compare this number with {name} in person… Logos never asks you to trust the
relay — only the number."*

### 3.5 Settings (`SettingsView`)
Identity card (avatar, `@username`, copyable address). **Privacy & security** stated
plainly: E2EE always on, sealed sender, keys stored on-device & kept out of backups.
**Advanced** holds the relay. An honest **caution banner**: *"Experimental & unaudited."*

---

## 4. Interaction states (the trust core)

The security UX follows one rule: **calm when fine, unmistakable when wrong, never
fake.**

| State | Treatment | Friction |
|---|---|---|
| **Encrypted (normal)** | Quiet `lock.fill` under the thread title. No banner. | None |
| **First secure session** | One-time inline chip in the thread + "Verify" link. | None |
| **Sending** | Bubble shows "Sending…" + clock. Marked sent only on success. | None |
| **Sent** | Quiet time + `lock.fill`. | None |
| **Failed (network)** | Bubble shows red "Not delivered · Retry" — tap to resend in place. | Low |
| **Identity changed** | Caution interstitial in the thread; **composer is dimmed/disabled** until the user verifies or explicitly taps "Send anyway." | **High** |
| **Can't decrypt** | Distinct neutral bubble (`lock.trianglebadge.exclamationmark`) + "Why?" — not styled as a normal message. | None |
| **Experimental build** | Honest, dismissible banner; full explanation in Settings. | None |

**Motion:** threads open with the standard push; sent bubbles spring in from the
composer; the identity-changed interstitial and disclosures use `standard` with opacity +
move. Nothing animates longer than ~320ms; all respect Reduce Motion.

**Copy principles (used verbatim in the code):**
- ✅ "End-to-end encrypted" · "This identity changed" · "Message couldn't be decrypted" ·
  "This build is experimental and unaudited."
- ❌ "Military-grade encryption," "100% secure," "unhackable," or a green checkmark before
  the user has actually verified anything.

---

## 5. Accessibility

- **Dynamic Type:** all fonts are text-style based (incl. the serif via
  `.system(_:design:)`), so they scale. Layouts use `ScrollView`/`fixedSize` to avoid
  truncation at large sizes.
- **Not color alone:** every security state is icon **+** text **+** color. `SecurityChip`
  and bubble status rows carry explicit `accessibilityLabel`s ("Sent, encrypted", "Not
  delivered… double tap to retry", "Identity changed").
- **Targets:** send/compose/attach are 36–44pt; rows are full-width tappable.
- **Contrast:** the `onGold` token guarantees AA-passing text on gold fills in both
  modes; secondary text meets AA on canvas.

---

## 6. UI/UX bugs & risks (prioritized)

Grounded in the actual code and the security-review follow-ups in `ROADMAP.md`.

### 6.1 Fixed in this pass
- **[Critical · trust] False "delivered."** Bubbles were appended before `send` and errors
  only showed on onboarding. → `Session` now tracks per-message `MessageStatus`
  (`sending/sent/failed/blocked`), marks sent only after the Rust call returns, and
  distinguishes **security refusals from network errors** via typed FFI errors (below).
- **[Critical · security] Identity-change detection is now typed, not heuristic.** The core
  `ClientError` is an enum (`IdentityChanged{peer}` / `NotRegistered{peer}` / `Network` /
  `Other`), mapped 1:1 onto the FFI `LogosError`; `Session.classify` pattern-matches it.
  The identity interstitial now fires **only** on a real TOFU key mismatch from
  `pin_identity` — never on a network blip, and a network blip never masquerades as an
  attack. A directory 404 becomes a friendly "@user isn’t on Logos yet" instead of a
  generic failure.
- **[High] First-run ENOENT.** `Application Support` wasn't created before `create()`. →
  `Session.init` now creates it.
- **[High] Identity secret in backups.** Plaintext store went into iCloud/iTunes backups.
  → `Session.hardenStore()` sets `isExcludedFromBackup` + `FileProtection.completeUnlessOpen`.
  *(Defense-in-depth only — not a substitute for at-rest store encryption; Argon2id store
  encryption is still on the roadmap.)*
- **[High] Relay footgun & "Create account."** Raw localhost field on screen one; wrong
  mental model. → relay moved to Advanced with a real default; CTA is "Create your identity."
- **[Med] No states to scan.** → avatars, timestamps, status rows, contextual security
  glyphs, teaching empty states.

### 6.2 Still open (needs core/FFI or a later phase)
- **[High] No message persistence.** History is in-memory; relaunch loses the thread,
  which reads as "Logos lost my messages" (trust hit). Persist locally (encrypted),
  *or* at minimum tell the user this build doesn't keep history.
- **[Med] Verification can't actually verify.** Needs the fingerprint FFI. Until then the
  app honestly says so rather than showing a fake "Verified."
- **[Med] No new-device / restore flow.** With single-device identities, a reinstall =
  new identity = peers see "identity changed." The change copy explains this, but a real
  restore/linked-device flow is a future phase — and the threat-model implication should
  be stated, not papered over.
- **[Med] Polling latency.** 3s `recv()` poll = sluggish + battery. Doesn't break the UI,
  but "instant" needs streaming/push later.
- **[Low] Username availability isn't validated inline.** Collisions surface as a raw Rust
  error string. Add inline availability check + friendly messaging when the FFI supports it.

### 6.3 Standing risks to keep honest
- **Don't imply unverified == verified.** "Encrypted" (true today via TOFU pinning) and
  "Verified" (only after a safety-number compare) are deliberately different words,
  glyphs, and colors. Never collapse them.
- **Sealed-sender is classical-only (PQ gap).** Per ROADMAP, sender-identity metadata
  isn't post-quantum. Settings copy says "hides who sent them from the relay" — accurate
  and scoped; **don't escalate that to a quantum claim** in marketing.

---

## 7. FFI additions the UI needs

Small, well-scoped core additions that unlock the trust UX.

```rust
// 1. ✅ LANDED — typed security outcome; replaced string-matching in Session.classify().
enum LogosError { IdentityChanged{peer}, NotRegistered{peer}, Network{msg}, Client{msg} }

// 2. ✅ LANDED — identity verification (real safety numbers + verified state).
fn contact_security(&self, peer) -> ContactSecurity {safety_number?, verified, verified_at?, key_changes}
fn mark_verified(&self, peer) throws;       // after out-of-band compare
fn reset_peer_identity(&self, peer) throws; // recovery: accept a legit reinstall

// 3. TODO — richer incoming message — unlocks real timestamps & decrypt-failure bubbles.
struct IncomingMessage { from, text, sent_at: u64, kind: Plain | UndecryptableNotice }
```

(1) and (2) are done: the identity-changed interstitial is reliable, and `VerifyView`
now shows real safety numbers with an earnable "Verified" state + reinstall recovery.
Still TODO: in-app **QR show/scan** (avoids reading 60 digits) and (3) richer
`IncomingMessage` (real timestamps + an honest "can't decrypt" bubble).

---

## 8. What to do next (impact order)

1. ~~Land the typed FFI error.~~ ✅ Done (§6.1, §7.1).
2. **Persist message history (encrypted).** Removes the "it lost my messages" trust hit.
3. **Ship the fingerprint FFI + wire `VerifyView`.** Makes "Verified" real and gives
   privacy-conscious users the thing they came for.
4. **Replace polling with streaming/push.** The "instant" feel.
5. **Design the restore / linked-device flow** alongside the identity-change story.
