//! WASM surface for the Logos web client.
//!
//! Reuses the EXACT Logos crypto crates (identity, pqxdh, ratchet, sealed, proto)
//! that the iOS app drives via FFI; here they are compiled to wasm32 + wasm-bindgen
//! so the protocol runs in the browser and private keys never leave the device.
//! JS owns transport (fetch to the relay) and persistence (IndexedDB) — exactly
//! like Swift owns them on iOS.
//!
//! - **Phase 1** (free functions): identity creation, registration payload, safety
//!   numbers — onboarding + peer lookup.
//! - **Phase 2** (`WasmClient`): 1:1 messaging. The client owns the long-term
//!   identity, prekey secrets, and per-conversation Double-Ratchet sessions. Send
//!   and receive are split into PURE-COMPUTE steps (`prepare_send` /
//!   `process_incoming`) with JS performing the async relay `fetch` in between, so
//!   the engine stays synchronous and wasm-friendly while JS handles I/O. Every
//!   wire type comes from `logos-proto`, so the bytes are identical to iOS by
//!   construction (web ↔ iOS interop, no protocol drift).
//!
//! EXPERIMENTAL — UNAUDITED.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

use logos_identity::{
    new_kem_prekey, new_one_time_prekey, new_signed_prekey, safety_number, IdentityKeyPair,
    IdentityPublic, KemSecret, PreKeyBundle,
};
use logos_pqxdh::{initiate, respond, InitialMessage};
use logos_proto::{
    ack_signed_bytes, cert_signed_bytes, fetch_signed_bytes, mailbox_id, registration_signed_bytes,
    validate_username, AckRequest, CertRequest, FetchRequest, OuterMessage, PostEnvelope,
    RegisterRequest, ServerKeyResponse, StoredEnvelope,
};
use logos_ratchet::{RatchetMessage, RatchetState};
use logos_sealed::{seal, unseal, SealedEnvelope, SenderCertificate};

fn err(e: impl ToString) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn jserr(s: String) -> JsValue {
    JsValue::from_str(&s)
}

/// Decode a 64-char hex string into a 32-byte array.
fn hex32(s: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s).map_err(|e| e.to_string())?;
    v.as_slice()
        .try_into()
        .map_err(|_| "expected 32 bytes".to_string())
}

// ===========================================================================
// Phase 1 — identity + registration + safety number (free functions).
// ===========================================================================

/// Pre-flight username check for onboarding. Returns `null` if the name is
/// registrable, else a human-readable reason (mirrors the relay's grammar).
#[wasm_bindgen]
pub fn check_username(name: &str) -> Option<String> {
    validate_username(name).err().map(|s| s.to_string())
}

/// A secret prekey persisted by the client: id + hex of the secret bytes. Used both
/// in the `build_registration` output and as the `WasmClient`'s stored prekey pools.
#[derive(Clone, Serialize, Deserialize)]
struct PkSec {
    id: u32,
    secret_hex: String,
}

#[derive(Serialize, Deserialize)]
struct SecretState {
    /// 32-byte identity master seed (the BIP39 recovery phrase encodes this) — hex.
    seed_hex: String,
    signed_prekey: PkSec,
    one_time_prekeys: Vec<PkSec>,
    kem_prekeys: Vec<PkSec>,
    last_resort_kem_prekey: PkSec,
}

#[derive(Serialize)]
struct NewAccount {
    username: String,
    identity_ed_hex: String,
    identity_dh_hex: String,
    /// Where peers deliver to us (sha256 over identity) — hex.
    mailbox: String,
    /// The exact POST /v1/register body — JS sends this to the relay verbatim.
    register_request: serde_json::Value,
    /// Secret material to persist locally (IndexedDB). NEVER sent to the relay.
    secret_state: SecretState,
}

/// Generate a fresh Logos identity and build the exact relay registration payload
/// plus the secret material to persist. `n_otk` one-time X25519 prekeys and
/// `n_kem` one-time ML-KEM prekeys are generated.
///
/// Returns a JSON string `{ username, identity_*_hex, mailbox, register_request,
/// secret_state }`. The caller POSTs `register_request` to `/v1/register`, stores
/// `secret_state` locally, and hands the whole object to `WasmClient.from_account`.
#[wasm_bindgen]
pub fn build_registration(username: &str, n_otk: u32, n_kem: u32) -> Result<String, JsValue> {
    let account = build_account(username, n_otk, n_kem).map_err(err)?;
    serde_json::to_string(&account).map_err(err)
}

fn build_account(username: &str, n_otk: u32, n_kem: u32) -> Result<NewAccount, String> {
    validate_username(username).map_err(|e| e.to_string())?;

    let (id, seed) = IdentityKeyPair::generate_seeded();
    let pubid: IdentityPublic = id.public();

    let (spk_pub, spk_sec) = new_signed_prekey(1, &id);

    let mut otk_pub = Vec::new();
    let mut otk_secret = Vec::new();
    for i in 0..n_otk {
        let (p, s) = new_one_time_prekey(i + 1);
        otk_secret.push(PkSec {
            id: s.id,
            secret_hex: hex::encode(s.secret.to_bytes()),
        });
        otk_pub.push(p);
    }

    let mut kem_pub = Vec::new();
    let mut kem_secret = Vec::new();
    for i in 0..n_kem {
        let (p, s) = new_kem_prekey(i + 1, &id);
        kem_secret.push(PkSec {
            id: s.id,
            secret_hex: hex::encode(s.secret.to_bytes()),
        });
        kem_pub.push(p);
    }

    // Last-resort KEM prekey is id 0 (used only when the one-time pool is empty).
    let (lr_pub, lr_sec) = new_kem_prekey(0, &id);

    let registration_sig = id
        .sign(&registration_signed_bytes(username, &pubid))
        .to_vec();

    let req = RegisterRequest {
        username: username.to_string(),
        identity: pubid,
        signed_prekey: spk_pub,
        kem_prekeys: kem_pub,
        last_resort_kem_prekey: lr_pub,
        one_time_prekeys: otk_pub,
        registration_sig,
    };

    Ok(NewAccount {
        username: username.to_string(),
        identity_ed_hex: hex::encode(pubid.ed),
        identity_dh_hex: hex::encode(pubid.dh),
        mailbox: mailbox_id(&pubid),
        register_request: serde_json::to_value(&req).map_err(|e| e.to_string())?,
        secret_state: SecretState {
            seed_hex: hex::encode(seed),
            signed_prekey: PkSec {
                id: spk_sec.id,
                secret_hex: hex::encode(spk_sec.secret.to_bytes()),
            },
            one_time_prekeys: otk_secret,
            kem_prekeys: kem_secret,
            last_resort_kem_prekey: PkSec {
                id: lr_sec.id,
                secret_hex: hex::encode(lr_sec.secret.to_bytes()),
            },
        },
    })
}

/// Human-comparable safety number between two identities (each given as ed/dh
/// hex), for the verify UI. Matches the iOS client byte-for-byte.
#[wasm_bindgen]
pub fn compute_safety_number(
    a_ed_hex: &str,
    a_dh_hex: &str,
    b_ed_hex: &str,
    b_dh_hex: &str,
) -> Result<String, JsValue> {
    let a = decode_identity(a_ed_hex, a_dh_hex)?;
    let b = decode_identity(b_ed_hex, b_dh_hex)?;
    Ok(safety_number(&a, &b))
}

fn decode_identity(ed_hex: &str, dh_hex: &str) -> Result<IdentityPublic, JsValue> {
    let ed = hex32(ed_hex).map_err(jserr)?;
    let dh = hex32(dh_hex).map_err(jserr)?;
    Ok(IdentityPublic { ed, dh })
}

// ===========================================================================
// Phase 2 — stateful 1:1 messaging client.
// ===========================================================================

/// A live 1:1 session with a peer. Mirrors `logos_client::Session`: the
/// Double-Ratchet state, the TOFU-pinned peer identity, whether we've sent the
/// session-opening prekey message yet, and (until then) the cached PQXDH initial
/// message to attach to the first outbound message.
#[derive(Clone, Serialize, Deserialize)]
struct Session {
    ratchet: RatchetState,
    peer_identity: IdentityPublic,
    sent_initial: bool,
    pending_initial: Option<InitialMessage>,
}

/// The full persisted client state. Serialized to JSON, encrypted at rest by JS,
/// and stored in IndexedDB. Secret prekey material is hex; sessions carry the live
/// ratchet state so a reload resumes mid-conversation.
#[derive(Serialize, Deserialize)]
struct Store {
    username: String,
    seed_hex: String,
    signed_prekey: PkSec,
    one_time: Vec<PkSec>,
    kem_one_time: Vec<PkSec>,
    kem_last_resort: PkSec,
    /// TOFU-pinned peer identities (username → identity). First sighting is trusted;
    /// a later mismatch is refused (possible relay key-substitution / MITM).
    #[serde(default)]
    contacts: HashMap<String, IdentityPublic>,
    #[serde(default)]
    sessions: HashMap<String, Session>,
    /// Fingerprints of already-consumed session-initiation messages, bounded FIFO —
    /// rejects a replayed prekey message (which would re-derive the same root key via
    /// the reusable last-resort KEM). Local only; never leaves the device.
    #[serde(default)]
    seen_initials: Vec<[u8; 32]>,
    /// The relay's Ed25519 verifying key (for sealed-sender certificate checks).
    #[serde(default)]
    server_vk: Option<[u8; 32]>,
    /// Cached short-lived sealed-sender certificate.
    #[serde(default)]
    cert: Option<SenderCertificate>,
}

impl Store {
    fn identity(&self) -> Result<IdentityKeyPair, String> {
        Ok(IdentityKeyPair::from_seed(&hex32(&self.seed_hex)?))
    }

    /// Our long-term X25519 DH private key (for unsealing inbound envelopes).
    fn dh_priv(&self) -> Result<[u8; 32], String> {
        let secret = self.identity()?.to_secret_bytes();
        secret[32..]
            .try_into()
            .map_err(|_| "bad identity secret".to_string())
    }
}

/// Outcome of processing one inbound envelope. `Delivered` is surfaced to the UI
/// and ACK-dropped; `Drop` is ACK-dropped silently (replay / forgery / garbage /
/// permanently-undeliverable); `Quarantine` is left on the relay to retry next poll
/// (a `Normal` message that arrived ahead of its session-opening `Prekey`).
enum Outcome {
    Delivered { from: String, text: String },
    Drop,
    Quarantine,
}

/// The pure-Rust messaging engine. No I/O: every method either mutates in-memory
/// state or produces/consumes JSON for JS to ship over the wire. This is the unit
/// tested natively (see the tests module); `WasmClient` is the thin wasm wrapper.
struct WebClient {
    store: Store,
}

impl WebClient {
    /// Build a client from a `build_registration` account object (username +
    /// secret_state). Sessions/contacts start empty; server key + cert are fetched
    /// lazily by JS.
    fn from_account(account_json: &str) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct AccountIn {
            username: String,
            secret_state: SecretStateIn,
        }
        #[derive(Deserialize)]
        struct SecretStateIn {
            seed_hex: String,
            signed_prekey: PkSec,
            one_time_prekeys: Vec<PkSec>,
            kem_prekeys: Vec<PkSec>,
            last_resort_kem_prekey: PkSec,
        }
        let a: AccountIn = serde_json::from_str(account_json).map_err(|e| e.to_string())?;
        Ok(Self {
            store: Store {
                username: a.username,
                seed_hex: a.secret_state.seed_hex,
                signed_prekey: a.secret_state.signed_prekey,
                one_time: a.secret_state.one_time_prekeys,
                kem_one_time: a.secret_state.kem_prekeys,
                kem_last_resort: a.secret_state.last_resort_kem_prekey,
                contacts: HashMap::new(),
                sessions: HashMap::new(),
                seen_initials: Vec::new(),
                server_vk: None,
                cert: None,
            },
        })
    }

    /// Rehydrate from a previously `export`ed state blob (a returning visit).
    fn load(state_json: &str) -> Result<Self, String> {
        let store: Store = serde_json::from_str(state_json).map_err(|e| e.to_string())?;
        Ok(Self { store })
    }

    fn export(&self) -> Result<String, String> {
        serde_json::to_string(&self.store).map_err(|e| e.to_string())
    }

    fn mailbox(&self) -> Result<String, String> {
        Ok(mailbox_id(&self.store.identity()?.public()))
    }

    // ---- sealed-sender certificate (for sending) ----

    fn needs_cert(&self, now: u64) -> bool {
        match &self.store.cert {
            Some(c) => c.expires_unix <= now + 60,
            None => true,
        }
    }

    fn cert_request(&self) -> Result<String, String> {
        let id = self.store.identity()?;
        let sig = id.sign(&cert_signed_bytes(&self.store.username, &id.public()));
        let req = CertRequest {
            username: self.store.username.clone(),
            identity: id.public(),
            sig: sig.to_vec(),
        };
        serde_json::to_string(&req).map_err(|e| e.to_string())
    }

    fn set_cert(&mut self, cert_json: &str) -> Result<(), String> {
        let cert: SenderCertificate = serde_json::from_str(cert_json).map_err(|e| e.to_string())?;
        self.store.cert = Some(cert);
        Ok(())
    }

    // ---- server verifying key (for receiving) ----

    fn set_server_key(&mut self, resp_json: &str) -> Result<(), String> {
        let r: ServerKeyResponse = serde_json::from_str(resp_json).map_err(|e| e.to_string())?;
        self.store.server_vk = Some(r.verifying_key);
        Ok(())
    }

    // ---- sending ----

    /// Encrypt `text` to `to` and return `{ mailbox, post_body }` for JS to POST to
    /// `/v1/mailbox/{mailbox}`. If no session exists yet, `bundle_json` (the peer's
    /// directory prekey bundle) MUST be supplied to open one; pass `None` once a
    /// session is established (`has_session` is true).
    ///
    /// This advances the sending ratchet — JS MUST persist `export()` BEFORE the
    /// POST so a crash can't roll the chain back and reuse a key+nonce. `sent_initial`
    /// is flipped by `confirm_sent` only after the POST succeeds, so a failed first
    /// delivery re-sends as a fresh prekey message.
    fn prepare_send(
        &mut self,
        to: &str,
        bundle_json: Option<&str>,
        text: &str,
    ) -> Result<String, String> {
        if !self.store.sessions.contains_key(to) {
            let bj = bundle_json.ok_or_else(|| "need_bundle".to_string())?;
            let bundle: PreKeyBundle = serde_json::from_str(bj).map_err(|e| e.to_string())?;
            // TOFU-pin the recipient identity; refuse if it changed (relay substitution).
            self.pin_identity(to, &bundle.identity)?;
            let id = self.store.identity()?;
            let init = initiate(&id, &bundle).map_err(|e| e.to_string())?;
            let ratchet =
                RatchetState::init_initiator(init.root_key, init.responder_signed_prekey_pub);
            self.store.sessions.insert(
                to.to_string(),
                Session {
                    ratchet,
                    peer_identity: bundle.identity,
                    sent_initial: false,
                    pending_initial: Some(init.initial_message.clone()),
                },
            );
        }

        let cert = self
            .store
            .cert
            .clone()
            .ok_or_else(|| "need_cert".to_string())?;
        let session = self
            .store
            .sessions
            .get_mut(to)
            .ok_or_else(|| "session missing".to_string())?;
        let ratchet_msg = session.ratchet.encrypt(text.as_bytes(), b"");
        let outer = if session.sent_initial {
            OuterMessage::Normal {
                ratchet: ratchet_msg,
            }
        } else {
            let initial = session
                .pending_initial
                .clone()
                .ok_or_else(|| "missing initial".to_string())?;
            OuterMessage::Prekey {
                initial,
                ratchet: ratchet_msg,
            }
        };
        let peer_identity = session.peer_identity;

        let outer_bytes = serde_json::to_vec(&outer).map_err(|e| e.to_string())?;
        let envelope = seal(&peer_identity.dh, &cert, &outer_bytes).map_err(|e| e.to_string())?;
        let body = serde_json::json!({
            "mailbox": mailbox_id(&peer_identity),
            "post_body": serde_json::to_value(PostEnvelope { envelope }).map_err(|e| e.to_string())?,
        });
        Ok(body.to_string())
    }

    fn confirm_sent(&mut self, to: &str) {
        if let Some(s) = self.store.sessions.get_mut(to) {
            s.sent_initial = true;
        }
    }

    // ---- receiving ----

    fn fetch_request(&self) -> Result<String, String> {
        let id = self.store.identity()?;
        let sig = id.sign(&fetch_signed_bytes(&id.public()));
        let req = FetchRequest {
            identity: id.public(),
            sig: sig.to_vec(),
        };
        serde_json::to_string(&req).map_err(|e| e.to_string())
    }

    /// Decrypt a batch of fetched envelopes (the `envelopes` array of a `/v1/fetch`
    /// response). Returns `{ messages: [{from, text}], ack_ids: [u64] }`. JS persists
    /// `export()` BEFORE POSTing the ack (F-07: only delete server-side after the
    /// plaintext is durably processed). `now` is unix seconds (for cert expiry).
    fn process_incoming(&mut self, envelopes_json: &str, now: u64) -> Result<String, String> {
        let server_vk = self
            .store
            .server_vk
            .ok_or_else(|| "no_server_key".to_string())?;
        let dh_priv = self.store.dh_priv()?;
        let envs: Vec<StoredEnvelope> =
            serde_json::from_str(envelopes_json).map_err(|e| e.to_string())?;

        let mut messages = Vec::new();
        let mut ack_ids = Vec::new();
        for se in &envs {
            match self.process_one(&se.envelope, &server_vk, &dh_priv, now) {
                Outcome::Delivered { from, text } => {
                    messages.push(serde_json::json!({ "from": from, "text": text }));
                    ack_ids.push(se.id);
                }
                Outcome::Drop => ack_ids.push(se.id),
                Outcome::Quarantine => {}
            }
        }
        Ok(serde_json::json!({ "messages": messages, "ack_ids": ack_ids }).to_string())
    }

    fn process_one(
        &mut self,
        env: &SealedEnvelope,
        server_vk: &[u8; 32],
        dh_priv: &[u8; 32],
        now: u64,
    ) -> Outcome {
        // A forged/garbage/expired envelope (sealed sender accepts any poster) can
        // never become decryptable — ACK-drop it.
        let (cert, payload) = match unseal(dh_priv, env, server_vk, now) {
            Ok(v) => v,
            Err(_) => return Outcome::Drop,
        };
        let outer: OuterMessage = match serde_json::from_slice(&payload) {
            Ok(v) => v,
            Err(_) => return Outcome::Drop,
        };
        match outer {
            OuterMessage::Prekey { initial, ratchet } => {
                self.decrypt_pairwise(&cert, Some(initial), ratchet)
            }
            OuterMessage::Normal { ratchet } => self.decrypt_pairwise(&cert, None, ratchet),
            // Groups aren't supported on web yet — drop control/data so they don't
            // loop forever on the relay. (Phase 3.)
            OuterMessage::GroupCtrl { .. } | OuterMessage::Group { .. } => Outcome::Drop,
        }
    }

    fn decrypt_pairwise(
        &mut self,
        cert: &SenderCertificate,
        initial: Option<InitialMessage>,
        ratchet: RatchetMessage,
    ) -> Outcome {
        let from = cert.sender_username.clone();
        match initial {
            Some(initial) => {
                // An inbound initiation must never reset an EXISTING session (a replayed
                // initial re-derives the same root key via the reusable last-resort KEM).
                if self.store.sessions.contains_key(&from) {
                    return Outcome::Drop;
                }
                let fp = initial_fingerprint(&initial, &ratchet);
                if self.store.seen_initials.contains(&fp) {
                    return Outcome::Drop;
                }
                match self.establish_and_decrypt(cert, initial, ratchet) {
                    Ok(pt) => {
                        self.remember_initial(fp);
                        Outcome::Delivered {
                            from,
                            text: String::from_utf8_lossy(&pt).into_owned(),
                        }
                    }
                    // A permanent failure (cert/identity mismatch, unknown prekey id,
                    // handshake/decrypt failure) — drop so it can't loop.
                    Err(_) => Outcome::Drop,
                }
            }
            None => match self.store.sessions.get_mut(&from) {
                Some(session) => match session.ratchet.decrypt(&ratchet, b"") {
                    Ok(pt) => Outcome::Delivered {
                        from,
                        text: String::from_utf8_lossy(&pt).into_owned(),
                    },
                    // A Normal message that no longer decrypts on a live session is a
                    // replay/corrupt duplicate — ACK-drop.
                    Err(_) => Outcome::Drop,
                },
                // No session yet: may be reordered ahead of its prekey — quarantine.
                None => Outcome::Quarantine,
            },
        }
    }

    fn establish_and_decrypt(
        &mut self,
        cert: &SenderCertificate,
        initial: InitialMessage,
        ratchet_msg: RatchetMessage,
    ) -> Result<Vec<u8>, String> {
        // The sealed-sender cert is only delivery authorization. The real sender
        // identity is the PQXDH initiator identity (proven by the handshake DH legs).
        // Bind them, then TOFU-pin, so a malicious relay can't forge a cert to
        // impersonate or hijack a known contact's session (F-02/F-03).
        if cert.sender_identity != initial.initiator_identity {
            return Err("sender certificate identity does not match handshake identity".into());
        }
        self.pin_identity(&cert.sender_username, &cert.sender_identity)?;
        if initial.signed_prekey_id != self.store.signed_prekey.id {
            return Err("unknown signed prekey id".into());
        }

        // Resolve the prekeys the initiator selected, but do NOT consume them until
        // the whole handshake + first ratchet decrypt succeeds — consuming up front
        // would let a forged prekey message permanently burn our one-time prekeys (F-05).
        let otk = match initial.one_time_prekey_id {
            Some(otk_id) => {
                let pos = self
                    .store
                    .one_time
                    .iter()
                    .position(|o| o.id == otk_id)
                    .ok_or_else(|| "unknown one-time prekey id".to_string())?;
                Some((pos, hex32(&self.store.one_time[pos].secret_hex)?))
            }
            None => None,
        };
        let one_time_priv = otk.as_ref().map(|(_, s)| *s);

        let kem_pos = if initial.kem_prekey_id == self.store.kem_last_resort.id {
            None
        } else {
            Some(
                self.store
                    .kem_one_time
                    .iter()
                    .position(|k| k.id == initial.kem_prekey_id)
                    .ok_or_else(|| "unknown kem prekey id".to_string())?,
            )
        };
        let kem_secret_hex = match kem_pos {
            None => &self.store.kem_last_resort.secret_hex,
            Some(pos) => &self.store.kem_one_time[pos].secret_hex,
        };
        let kem_secret =
            KemSecret::from_bytes(&hex::decode(kem_secret_hex).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;

        let id = self.store.identity()?;
        let spk_priv = hex32(&self.store.signed_prekey.secret_hex)?;
        let resp = respond(&id, spk_priv, one_time_priv, &kem_secret, &initial)
            .map_err(|e| e.to_string())?;
        let mut ratchet = RatchetState::init_responder(resp.root_key, resp.signed_prekey_priv);
        let pt = ratchet
            .decrypt(&ratchet_msg, b"")
            .map_err(|e| e.to_string())?;

        // Success: now commit the prekey consumption and the new session.
        if let Some((pos, _)) = otk {
            self.store.one_time.remove(pos);
        }
        if let Some(pos) = kem_pos {
            self.store.kem_one_time.remove(pos);
        }
        self.store.sessions.insert(
            cert.sender_username.clone(),
            Session {
                ratchet,
                peer_identity: cert.sender_identity,
                sent_initial: true,
                pending_initial: None,
            },
        );
        Ok(pt)
    }

    /// TOFU identity pinning: first sighting is recorded; a later mismatch is refused.
    fn pin_identity(&mut self, username: &str, identity: &IdentityPublic) -> Result<(), String> {
        match self.store.contacts.get(username) {
            Some(known) if known != identity => Err(format!(
                "identity for '{username}' changed — possible impersonation or MITM"
            )),
            Some(_) => Ok(()),
            None => {
                self.store.contacts.insert(username.to_string(), *identity);
                Ok(())
            }
        }
    }

    fn remember_initial(&mut self, fp: [u8; 32]) {
        const MAX_SEEN: usize = 512;
        if self.store.seen_initials.len() >= MAX_SEEN {
            self.store.seen_initials.remove(0);
        }
        self.store.seen_initials.push(fp);
    }

    fn peer_safety_number(&self, peer: &str) -> Result<Option<String>, String> {
        let me = self.store.identity()?.public();
        Ok(self
            .store
            .contacts
            .get(peer)
            .map(|theirs| safety_number(&me, theirs)))
    }
}

/// Local fingerprint of a session-initiation message, for replay rejection. Covers
/// the initiator ephemeral, the KEM ciphertext, and the first ratchet ciphertext —
/// enough to identify a replayed prekey envelope. Never leaves the device.
fn initial_fingerprint(initial: &InitialMessage, ratchet: &RatchetMessage) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"logos-web-initial-fp-v1");
    h.update(initial.ephemeral_pub);
    h.update(&initial.kem_ciphertext);
    h.update(&ratchet.ciphertext);
    h.finalize().into()
}

/// Stateful 1:1 messaging client — the browser analogue of iOS's `LogosClient`.
///
/// Holds the long-term identity, prekey secrets, and per-conversation ratchet
/// sessions in memory. Crypto happens here; JS owns the relay `fetch` calls and
/// persists `export()` (encrypted) to IndexedDB. All methods marshal JSON across
/// the boundary so the wire bytes stay identical to the Rust/iOS types.
#[wasm_bindgen]
pub struct WasmClient {
    inner: WebClient,
}

#[wasm_bindgen]
impl WasmClient {
    /// Construct from a fresh `build_registration` account object (after the caller
    /// has POSTed its `register_request`).
    pub fn from_account(account_json: &str) -> Result<WasmClient, JsValue> {
        Ok(WasmClient {
            inner: WebClient::from_account(account_json).map_err(jserr)?,
        })
    }

    /// Rehydrate from a previously `export`ed state blob (returning visit).
    pub fn load(state_json: &str) -> Result<WasmClient, JsValue> {
        Ok(WasmClient {
            inner: WebClient::load(state_json).map_err(jserr)?,
        })
    }

    /// The full persisted state — JS encrypts this and stores it in IndexedDB.
    pub fn export(&self) -> Result<String, JsValue> {
        self.inner.export().map_err(jserr)
    }

    pub fn username(&self) -> String {
        self.inner.store.username.clone()
    }

    pub fn mailbox(&self) -> Result<String, JsValue> {
        self.inner.mailbox().map_err(jserr)
    }

    pub fn identity_ed_hex(&self) -> Result<String, JsValue> {
        Ok(hex::encode(
            self.inner.store.identity().map_err(jserr)?.public().ed,
        ))
    }

    pub fn identity_dh_hex(&self) -> Result<String, JsValue> {
        Ok(hex::encode(
            self.inner.store.identity().map_err(jserr)?.public().dh,
        ))
    }

    /// Usernames of peers we have an open session with (for the conversation list).
    pub fn peers(&self) -> Vec<String> {
        let mut v: Vec<String> = self.inner.store.sessions.keys().cloned().collect();
        v.sort();
        v
    }

    pub fn has_session(&self, to: &str) -> bool {
        self.inner.store.sessions.contains_key(to)
    }

    pub fn needs_cert(&self, now: f64) -> bool {
        self.inner.needs_cert(now as u64)
    }

    pub fn cert_request(&self) -> Result<String, JsValue> {
        self.inner.cert_request().map_err(jserr)
    }

    pub fn set_cert(&mut self, cert_json: &str) -> Result<(), JsValue> {
        self.inner.set_cert(cert_json).map_err(jserr)
    }

    pub fn has_server_key(&self) -> bool {
        self.inner.store.server_vk.is_some()
    }

    pub fn set_server_key(&mut self, resp_json: &str) -> Result<(), JsValue> {
        self.inner.set_server_key(resp_json).map_err(jserr)
    }

    /// Prepare an outbound message. `bundle_json` is the peer's directory bundle
    /// (required to open a new session; pass `null`/`undefined` once `has_session`).
    /// Returns `{ mailbox, post_body }`. Persist `export()` BEFORE POSTing.
    pub fn prepare_send(
        &mut self,
        to: &str,
        bundle_json: Option<String>,
        text: &str,
    ) -> Result<String, JsValue> {
        self.inner
            .prepare_send(to, bundle_json.as_deref(), text)
            .map_err(jserr)
    }

    /// Mark the session's opening prekey message as delivered (call after the POST
    /// for a first message succeeds).
    pub fn confirm_sent(&mut self, to: &str) {
        self.inner.confirm_sent(to)
    }

    pub fn fetch_request(&self) -> Result<String, JsValue> {
        self.inner.fetch_request().map_err(jserr)
    }

    /// Decrypt a fetched envelope batch. `envelopes_json` is the `envelopes` array
    /// from `/v1/fetch`; `now` is unix seconds. Returns `{ messages, ack_ids }`.
    pub fn process_incoming(&mut self, envelopes_json: &str, now: f64) -> Result<String, JsValue> {
        self.inner
            .process_incoming(envelopes_json, now as u64)
            .map_err(jserr)
    }

    pub fn ack_request(&self, ack_ids_json: &str) -> Result<String, JsValue> {
        let ids: Vec<u64> = serde_json::from_str(ack_ids_json).map_err(err)?;
        let id = self.inner.store.identity().map_err(jserr)?;
        let sig = id.sign(&ack_signed_bytes(&id.public(), &ids));
        let req = AckRequest {
            identity: id.public(),
            ids,
            sig: sig.to_vec(),
        };
        serde_json::to_string(&req).map_err(err)
    }

    /// The safety number for a peer we have a session with (compare out-of-band to
    /// verify), or `null` if no session/pin yet.
    pub fn peer_safety_number(&self, peer: &str) -> Result<Option<String>, JsValue> {
        self.inner.peer_safety_number(peer).map_err(jserr)
    }
}

// ===========================================================================
// Native tests — full Alice↔Bob round trip with a mock server (no relay, no wasm).
// Proves the protocol/orchestration is correct headlessly.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use logos_sealed::issue_certificate;

    /// A mock relay key pair (the relay signs sealed-sender certs).
    fn server_keys() -> ([u8; 32], [u8; 32]) {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        (sk.to_bytes(), sk.verifying_key().to_bytes())
    }

    fn new_client(username: &str) -> (WebClient, serde_json::Value) {
        let account = build_account(username, 4, 4).unwrap();
        let account_json = serde_json::to_string(&account).unwrap();
        let client = WebClient::from_account(&account_json).unwrap();
        // The register_request the peer would publish to the directory.
        (client, account.register_request)
    }

    /// Build a directory-style prekey bundle from a peer's register_request,
    /// selecting the first one-time + kem prekey (what the relay would hand out).
    fn bundle_from_registration(reg: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "username": reg["username"],
            "identity": reg["identity"],
            "signed_prekey": reg["signed_prekey"],
            "one_time_prekey": reg["one_time_prekeys"][0],
            "kem_prekey": reg["kem_prekeys"][0],
        })
    }

    /// Give a client a fresh sealed-sender cert signed by the mock server.
    fn give_cert(client: &mut WebClient, server_seed: &[u8; 32], username: &str) {
        let id = client.store.identity().unwrap();
        let cert = issue_certificate(server_seed, username, &id.public(), 9_999_999_999);
        client
            .set_cert(&serde_json::to_string(&cert).unwrap())
            .unwrap();
    }

    fn server_key_json(vk: &[u8; 32]) -> String {
        serde_json::to_string(&ServerKeyResponse { verifying_key: *vk }).unwrap()
    }

    /// Wrap a `prepare_send` result as a one-element `/v1/fetch` envelopes array.
    fn as_envelopes(prepared: &str, id: u64) -> String {
        let v: serde_json::Value = serde_json::from_str(prepared).unwrap();
        serde_json::json!([{ "id": id, "envelope": v["post_body"]["envelope"] }]).to_string()
    }

    #[test]
    fn full_1to1_conversation_round_trip() {
        let (server_seed, server_vk) = server_keys();
        let now = 1_000_000u64;

        let (mut alice, _alice_reg) = new_client("alice");
        let (mut bob, bob_reg) = new_client("bob");

        // Both can receive: they know the server verifying key.
        alice.set_server_key(&server_key_json(&server_vk)).unwrap();
        bob.set_server_key(&server_key_json(&server_vk)).unwrap();
        give_cert(&mut alice, &server_seed, "alice");
        give_cert(&mut bob, &server_seed, "bob");

        // --- Alice opens a session to Bob (Prekey path) ---
        let bob_bundle = bundle_from_registration(&bob_reg).to_string();
        assert!(!alice.store.sessions.contains_key("bob"));
        let prepared = alice
            .prepare_send("bob", Some(&bob_bundle), "hi bob, it's alice")
            .unwrap();
        alice.confirm_sent("bob");

        let out: serde_json::Value = serde_json::from_str(
            &bob.process_incoming(&as_envelopes(&prepared, 1), now)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(out["messages"][0]["from"], "alice");
        assert_eq!(out["messages"][0]["text"], "hi bob, it's alice");
        assert_eq!(out["ack_ids"][0], 1);
        assert!(bob.store.sessions.contains_key("alice"));

        // --- Bob replies (Normal path; he already has a session) ---
        let prepared = bob.prepare_send("alice", None, "hey alice!").unwrap();
        bob.confirm_sent("alice");
        let out: serde_json::Value = serde_json::from_str(
            &alice
                .process_incoming(&as_envelopes(&prepared, 2), now)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(out["messages"][0]["from"], "bob");
        assert_eq!(out["messages"][0]["text"], "hey alice!");

        // --- Alice sends a second message (Normal path, established session) ---
        let prepared = alice.prepare_send("bob", None, "how's it going?").unwrap();
        alice.confirm_sent("bob");
        let out: serde_json::Value = serde_json::from_str(
            &bob.process_incoming(&as_envelopes(&prepared, 3), now)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(out["messages"][0]["text"], "how's it going?");

        // --- Safety numbers agree on both sides (symmetric) ---
        let a_sn = alice.peer_safety_number("bob").unwrap().unwrap();
        let b_sn = bob.peer_safety_number("alice").unwrap().unwrap();
        assert_eq!(a_sn, b_sn);
    }

    #[test]
    fn replayed_prekey_message_is_dropped_not_redelivered() {
        let (server_seed, server_vk) = server_keys();
        let now = 1_000_000u64;
        let (mut alice, _alice_reg) = new_client("alice");
        let (mut bob, bob_reg) = new_client("bob");
        bob.set_server_key(&server_key_json(&server_vk)).unwrap();
        give_cert(&mut alice, &server_seed, "alice");

        let bob_bundle = bundle_from_registration(&bob_reg).to_string();
        let prepared = alice
            .prepare_send("bob", Some(&bob_bundle), "once")
            .unwrap();
        let envs = as_envelopes(&prepared, 1);

        // First delivery is accepted.
        let out: serde_json::Value =
            serde_json::from_str(&bob.process_incoming(&envs, now).unwrap()).unwrap();
        assert_eq!(out["messages"][0]["text"], "once");

        // Exact same envelope replayed → no message, but still ACK-dropped (id present).
        let out: serde_json::Value =
            serde_json::from_str(&bob.process_incoming(&envs, now).unwrap()).unwrap();
        assert_eq!(out["messages"].as_array().unwrap().len(), 0);
        assert_eq!(out["ack_ids"][0], 1);
    }

    #[test]
    fn state_export_import_resumes_a_live_session() {
        let (server_seed, server_vk) = server_keys();
        let now = 1_000_000u64;
        let (mut alice, _) = new_client("alice");
        let (mut bob, bob_reg) = new_client("bob");
        bob.set_server_key(&server_key_json(&server_vk)).unwrap();
        give_cert(&mut alice, &server_seed, "alice");

        let bob_bundle = bundle_from_registration(&bob_reg).to_string();
        let p1 = alice
            .prepare_send("bob", Some(&bob_bundle), "first")
            .unwrap();
        alice.confirm_sent("bob");
        bob.process_incoming(&as_envelopes(&p1, 1), now).unwrap();

        // Persist + restore Alice mid-conversation, then keep sending.
        let blob = alice.export().unwrap();
        let mut alice2 = WebClient::load(&blob).unwrap();
        give_cert(&mut alice2, &server_seed, "alice");
        let p2 = alice2.prepare_send("bob", None, "after reload").unwrap();
        let out: serde_json::Value =
            serde_json::from_str(&bob.process_incoming(&as_envelopes(&p2, 2), now).unwrap())
                .unwrap();
        assert_eq!(out["messages"][0]["text"], "after reload");
    }
}
