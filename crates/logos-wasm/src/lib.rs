//! WASM surface for the Logos web client — Phase 1 (identity + registration).
//!
//! Reuses the EXACT Logos crypto crates (identity, pqxdh, ratchet, sealed, proto)
//! that the iOS app drives via FFI; here they are compiled to wasm32 + wasm-bindgen
//! so the protocol runs in the browser and private keys never leave the device.
//! JS owns transport (fetch to the relay) and persistence (IndexedDB) — exactly
//! like Swift owns them on iOS.
//!
//! EXPERIMENTAL — UNAUDITED.

use serde::Serialize;
use wasm_bindgen::prelude::*;

use logos_identity::{
    new_kem_prekey, new_one_time_prekey, new_signed_prekey, safety_number, IdentityKeyPair,
    IdentityPublic,
};
use logos_proto::{mailbox_id, registration_signed_bytes, validate_username, RegisterRequest};

fn err(e: impl ToString) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// Pre-flight username check for onboarding. Returns `null` if the name is
/// registrable, else a human-readable reason (mirrors the relay's grammar).
#[wasm_bindgen]
pub fn check_username(name: &str) -> Option<String> {
    validate_username(name).err().map(|s| s.to_string())
}

#[derive(Serialize)]
struct SecretPrekey {
    id: u32,
    secret_hex: String,
}

#[derive(Serialize)]
struct SecretState {
    /// 32-byte identity master seed (the BIP39 recovery phrase encodes this) — hex.
    seed_hex: String,
    signed_prekey: SecretPrekey,
    one_time_prekeys: Vec<SecretPrekey>,
    kem_prekeys: Vec<SecretPrekey>,
    last_resort_kem_prekey: SecretPrekey,
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
/// secret_state }`. The caller POSTs `register_request` to `/v1/register` and
/// stores `secret_state` locally; keys are generated here, in the browser.
#[wasm_bindgen]
pub fn build_registration(username: &str, n_otk: u32, n_kem: u32) -> Result<String, JsValue> {
    validate_username(username).map_err(err)?;

    let (id, seed) = IdentityKeyPair::generate_seeded();
    let pubid: IdentityPublic = id.public();

    let (spk_pub, spk_sec) = new_signed_prekey(1, &id);

    let mut otk_pub = Vec::new();
    let mut otk_secret = Vec::new();
    for i in 0..n_otk {
        let (p, s) = new_one_time_prekey(i + 1);
        otk_secret.push(SecretPrekey {
            id: s.id,
            secret_hex: hex::encode(s.secret.to_bytes()),
        });
        otk_pub.push(p);
    }

    let mut kem_pub = Vec::new();
    let mut kem_secret = Vec::new();
    for i in 0..n_kem {
        let (p, s) = new_kem_prekey(i + 1, &id);
        kem_secret.push(SecretPrekey {
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

    let account = NewAccount {
        username: username.to_string(),
        identity_ed_hex: hex::encode(pubid.ed),
        identity_dh_hex: hex::encode(pubid.dh),
        mailbox: mailbox_id(&pubid),
        register_request: serde_json::to_value(&req).map_err(err)?,
        secret_state: SecretState {
            seed_hex: hex::encode(seed),
            signed_prekey: SecretPrekey {
                id: spk_sec.id,
                secret_hex: hex::encode(spk_sec.secret.to_bytes()),
            },
            one_time_prekeys: otk_secret,
            kem_prekeys: kem_secret,
            last_resort_kem_prekey: SecretPrekey {
                id: lr_sec.id,
                secret_hex: hex::encode(lr_sec.secret.to_bytes()),
            },
        },
    };

    serde_json::to_string(&account).map_err(err)
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
    let ed = hex::decode(ed_hex).map_err(err)?;
    let dh = hex::decode(dh_hex).map_err(err)?;
    let ed: [u8; 32] = ed
        .as_slice()
        .try_into()
        .map_err(|_| err("identity ed key must be 32 bytes"))?;
    let dh: [u8; 32] = dh
        .as_slice()
        .try_into()
        .map_err(|_| err("identity dh key must be 32 bytes"))?;
    Ok(IdentityPublic { ed, dh })
}
