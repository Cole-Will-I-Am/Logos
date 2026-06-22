# Logos — Private AI-Native Messaging (blueprint)

The product vision for Logos as an **AI-native private messenger**: conversations become
searchable memory, actionable context, and human-approved coordination — *without*
becoming someone else's training data, and *without* the relay ever needing to
understand your life.

This file = the product/north-star blueprint. It is paired with the engineering
reality:
[`ROADMAP.md`](ROADMAP.md) (where we are) · [`SIGNAL_PLUS_BLUEPRINT.md`](SIGNAL_PLUS_BLUEPRINT.md)
(security target) · [`GROUP_CHAT_PLAN.md`](GROUP_CHAT_PLAN.md) (P4) ·
[`THREAT-MODEL.md`](THREAT-MODEL.md).

---

## 0. Engineering refinements (read first)

The vision below is sound. Four refinements make it *implementable inside Logos's
existing E2EE / untrusted-relay model* rather than quietly breaking it.

### R1 — The one non-negotiable: the relay stays blind, and AI must not change that

Logos's entire reason to exist is that the **relay/operator can't read your messages.**
Every AI feature must preserve that. Concretely:

- **The Logos relay/operator must NEVER receive message content for AI.** No
  server-side AI, no "send the chat to our backend to summarize." All AI runs either
  **on-device** or via the **user's own provider key, device → provider directly** (the
  relay is not in the path).
- **Cloud AI crosses the E2EE boundary — say so, every time.** The moment decrypted
  content is sent to Anthropic/OpenAI (even with the user's own key), *that content is
  no longer end-to-end encrypted* — the provider sees it. This is the same honesty rule
  as the Telegram-groups call: never imply privacy the code doesn't have. So cloud AI is
  **off by default, per-use consent, with a prompt preview of exactly what leaves the
  device, and a clear "this leaves your device" marker.** Never silent.
- **Local keeps it private.** On-device models and the **user's own Ollama endpoint**
  (their Mac/VPS) keep content fully private — nothing leaves the E2EE envelope. This is
  the default and the recommended path.
- **Other people's words.** Summarizing/searching a chat sends *the other person's*
  messages too. Cloud features that include a contact's content must make that explicit;
  prefer on-device for anything involving others' messages.

### R2 — BYOK is the architecture that makes cloud AI privacy-compatible

Bring-Your-Own-Key is not a billing convenience here — it's the privacy mechanism:

- The user supplies their **own** Anthropic / OpenAI / Ollama key (or endpoint). The
  device calls that provider **directly**; Logos's servers are never involved and never
  see the content or the key.
- The user's data is governed by **their own account + the provider's API terms**
  (Anthropic and OpenAI do **not** train on API data by default; Ollama can be fully
  local/self-hosted). Logos takes on no custody of message content for AI.
- **Keys live in the iOS Keychain** (device-only, `...ThisDeviceOnly`, never synced,
  never sent to the relay) — same posture as the at-rest `StoreKey`.
- Provider tiers, privacy-ordered: **on-device model** (most private) → **user's own
  Ollama endpoint** (private, user-controlled) → **BYOK cloud (Anthropic/OpenAI)**
  (content leaves to that provider under the user's key). Default = none configured (AI
  off).

### R3 — On-device LLM reality

iOS on-device LLMs are small. Realistic split:

- **On-device:** embeddings, semantic retrieval, classification/triage, entity/action
  extraction, short summaries — the privacy-critical, always-local layer.
- **Heavy generation** (rich catch-up summaries, drafting): the user's **Ollama
  endpoint** (their own Mac/VPS — "private cloud") or **BYOK cloud**. "Local-first" in
  practice = on-device retrieval + the user's own model server for generation.

### R4 — Reconcile with what's already built, and cut the creep

- **Phase 1 (Private Messenger Foundation) is largely DONE** in Logos: E2EE 1:1,
  recovery phrase, at-rest encryption, contacts, identity verification, relay, delivery
  state. The AI track starts from a real foundation.
- **"Group catch-up" depends on groups** → that's [`GROUP_CHAT_PLAN.md`](GROUP_CHAT_PLAN.md)
  (P4). **1:1 catch-up/summary + search are buildable now** on the existing 1:1 history.
- **Defer / heavily gate the high-creep items:** inter-agent negotiation, payments,
  reservations/delivery actions, and especially **voice-preserving translation / voice
  models** (explicit-consent-only, no exportable impersonation assets — treat as
  out-of-scope until much later). Start with **comprehension**, not autonomy.

**First AI increment (the wedge):** *catch-up summary + grounded search for 1:1 chats,
via BYOK* — proves the thesis, needs no new permissions, and the same engine extends to
group catch-up once groups land.

---

## 1. Thesis & promise

Most messengers are text-first, AI-added. Logos inverts it: a **private messenger where
conversations become searchable memory, contextual coordination, personal knowledge,
and human-approved action surfaces.**

- Product promise: *your conversations become useful context without becoming someone
  else's training data.*
- Privacy promise: *the server should not need to understand your life for the app to
  help you live it.*
- Strongest tagline: **"Messaging with memory, not surveillance."**

## 2. Product principles

1. **AI assists, humans decide.** AI suggests/summarizes/prepares; it never impersonates
   the user, makes social commitments, or acts on private context without approval.
2. **Context is visible.** Every AI answer can show its sources (messages, contacts,
   dates), whether it's inferred vs stated, and whether anything will leave the device.
3. **Local-first intelligence.** Sensitive analysis is on-device by default; cloud is
   optional, disclosed, minimized, permission-gated, never silent (see R1/R2).
4. **No fake intimacy.** Help the user be responsive/organized; never automate
   friendship, emotional replies, condolences, or voice likeness.
5. **Trust is the product.** Every feature answers "what does the server learn?" → "as
   little as possible" (for the relay: *nothing about AI*).

## 3. Architecture (4 layers)

- **L1 Messaging core** (built): identity, contacts, E2EE transport, mailbox delivery,
  sealed-sender metadata reduction, local encrypted store, recovery, verification,
  delivery state. Works without AI.
- **L2 Local context engine** (new): index local messages; per-chat semantic memory;
  summaries; extract tasks/dates/people/places/decisions; track unresolved commitments;
  NL search; private drafts; urgency/mention detection. Memory scopes: personal · chat ·
  group · contact · device · ephemeral. Local by default.
- **L3 Permissioned agent layer** (later): capability-gated actions (calendar/location/
  contacts/reservations/payments) — each opt-in, revocable, visible, chat/contact-scoped,
  locally logged; biometric approval for payments/bookings.
- **L4 Shared agent protocol** (far future): one user's local agent negotiates *minimal
  structured constraints* with another's (never raw calendars/messages); human approves
  the result in-chat.

## 4. Privacy & data model

| Data | Default location | Relay sees? |
|---|---|---|
| Message plaintext / embeddings / summaries / action items / contact memory | Device only | No |
| Calendar / location | Device only unless approved | No |
| AI prompts/responses | On-device, or device→user's provider (BYOK) | **No (relay never in the AI path)** |
| Provider API keys | iOS Keychain, device-only | No (never sent) |
| Delivery metadata / mailbox id / push token | Relay / push provider | Limited / yes |

**Cloud AI modes:** (1) **Local only** (default-private) → (2) **Private cloud assist
(BYOK)**: per-request consent + prompt preview + no-training (provider default) + delete
option → (3) **Hybrid**: on-device retrieval/classification, BYOK cloud generates from
*minimized, user-approved snippets only* (send the 3 relevant messages, not the chat).

## 5. Trust & safety (hard rules)

**Never silently:** send a message · share location/availability · book/spend · expose
contacts · summarize one person's messages *to another* · create persistent memory ·
upload content to cloud AI · use a voice likeness.

**Always show approval for:** external API calls · agent negotiation · cloud AI requests
· group summaries shared to a group · calendar writes · contact sharing · financial
activity.

**Sensitive categories** (medical/legal/financial/conflict/self-harm/minors/explicit/
credentials): draft-only, no auto-send, cite sources, recommend human review, avoid
strong claims.

**UX copy:** use "Suggested / Draft / Approve / Used these messages / Nothing sent yet /
Stored only on this device / Show source." Avoid "I handled it / Automatically replied /
I know you / Based on your relationship / Predicted emotional state."

## 6. AI-native roadmap (mapped onto Logos's phases)

| AI phase | Goal | Depends on | Status |
|---|---|---|---|
| **AI-0 — BYOK foundation** | Keychain key store + provider clients (Anthropic/OpenAI/Ollama, device→provider direct) + Settings UI + consent/preview + a first feature (**1:1 catch-up summary**) + **on-device default** (Apple Foundation Models) | L1 (done) | ✅ done (0.1.16/0.1.17). Extended since: **dedicated nameable AI assistant chat** (0.1.19), **in-chat @mention** of the assistant (0.1.20/0.1.21), **AI markdown rendering** (0.1.24). |
| **AI-1 — Local comprehension** | on-device embeddings index · grounded semantic search (source-cited) · action/mention extraction · voice-note summary | AI-0 | ⏳ — first on-device slice shipped: **Loose Ends** (unanswered questions / promises / time-sensitive items, 0.1.26; **v2 persisted + encrypted** 0.1.27). Embeddings index, grounded semantic search, and memory still planned. |
| **AI-2 — Memory** | personal/per-contact memory (editable, deletable, source-backed) · AI privacy dashboard per chat | AI-1 | ⏳ |
| **AI-3 — Group catch-up** | the flagship wedge at group scale | [P4 groups](GROUP_CHAT_PLAN.md) core ✅ (P4.0a/b + **P4.0c UI**, 0.1.25) + AI-1 | ⏳ |
| **AI-4 — Planning cards** | detect planning intent → structured plan/poll cards · calendar-read suggestions · manual approval | AI-2 | ⏳ |
| **AI-5 — Permissioned agents** | capability system + audit log + biometric-gated actions | AI-4 | ⏳ |
| **AI-6 — Shared agent protocol / multimodal** | inter-agent negotiation (minimal constraints) · translation · call summaries — heavily gated | AI-5 | ⏳ (creep risk; defer) |

**Build order:** comprehension → search/memory → group catch-up → planning → (only then,
with explicit permission) approved action. Do **not** start with autonomy.

## 7. Differentiation

- vs **Signal:** Signal-like privacy ambition **plus** AI-native local intelligence
  (don't attack Signal; out-feature on private productivity).
- vs **Telegram:** Telegram-style *utility* without centralized visibility into your life
  (and unlike Telegram, groups are actually E2EE).
- vs **iMessage/WhatsApp:** explicit hostile-server architecture, no phone number,
  user-owned identity + a private AI/memory layer.

## 8. Strategic warning

The biggest risk is **trust**, not tech. If Logos feels like an AI reading everything, a
bot speaking for users, or a cloud-AI wrapper, privacy-conscious users reject it. It must
feel like a *private assistant + local memory + intelligent inbox + human-controlled
coordination layer.* The relay learning nothing about AI is the whole game.
