//! PQXDH: post-quantum-hybrid asynchronous key agreement (Signal PQXDH spec).
//!
//! Combines the classical X3DH DH legs (X25519) with an ML-KEM-1024 shared
//! secret so an attacker must break **both** X25519 and ML-KEM to recover the
//! session key — protecting against harvest-now-decrypt-later. The derived
//! secret key seeds the Double Ratchet (`logos-ratchet`).
//!
//! Implemented to the published PQXDH/X3DH specs over audited primitives.
//! EXPERIMENTAL — UNAUDITED.

use hkdf::Hkdf;
use logos_identity::{IdentityKeyPair, IdentityPublic, KemCiphertext, KemSecret, PreKeyBundle};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain-separation prefix for the single-curve (X25519) variant, per X3DH.
const F: [u8; 32] = [0xFF; 32];

#[derive(Debug, Error)]
pub enum PqxdhError {
    #[error("prekey bundle signature invalid")]
    BadBundle,
    #[error("one-time prekey was selected but its secret is missing")]
    MissingOneTimePrekey,
    #[error("identity: {0}")]
    Identity(#[from] logos_identity::IdentityError),
}

/// The first message the initiator sends; lets the responder re-derive the key.
#[derive(Clone, Serialize, Deserialize)]
pub struct InitialMessage {
    pub initiator_identity: IdentityPublic,
    pub ephemeral_pub: [u8; 32],
    pub signed_prekey_id: u32,
    pub one_time_prekey_id: Option<u32>,
    pub kem_prekey_id: u32,
    pub kem_ciphertext: Vec<u8>,
}

/// Result of running the handshake as the initiator.
#[derive(ZeroizeOnDrop)]
pub struct InitiatorResult {
    /// Shared secret key — root key for the Double Ratchet.
    pub root_key: [u8; 32],
    /// The responder's signed prekey public — the ratchet's initial DH key.
    pub responder_signed_prekey_pub: [u8; 32],
    #[zeroize(skip)]
    pub initial_message: InitialMessage,
}

/// Result of running the handshake as the responder.
#[derive(ZeroizeOnDrop)]
pub struct ResponderResult {
    pub root_key: [u8; 32],
    /// Our signed-prekey private — the ratchet's initial DH key (responder side).
    pub signed_prekey_priv: [u8; 32],
}

fn dh(secret: &X25519Secret, public: &[u8; 32]) -> [u8; 32] {
    secret
        .diffie_hellman(&X25519Public::from(*public))
        .to_bytes()
}

/// Bind the handshake transcript (identities + ephemeral + KEM ciphertext) so a
/// tampered/downgraded handshake yields a different key.
fn transcript(
    ik_a: &IdentityPublic,
    ik_b: &IdentityPublic,
    eph: &[u8; 32],
    kem_ct: &[u8],
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"LogosPQXDHv1-transcript");
    h.update(ik_a.encode());
    h.update(ik_b.encode());
    h.update(eph);
    h.update(kem_ct);
    h.finalize().to_vec()
}

fn derive(mut ikm: Vec<u8>, info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm);
    let mut sk = [0u8; 32];
    hk.expand(info, &mut sk).expect("hkdf len ok");
    ikm.zeroize();
    sk
}

/// Run PQXDH as the **initiator** against a fetched (and verified) prekey bundle.
pub fn initiate(
    me: &IdentityKeyPair,
    bundle: &PreKeyBundle,
) -> Result<InitiatorResult, PqxdhError> {
    bundle.verify().map_err(|_| PqxdhError::BadBundle)?;

    let ik_a = me.public();
    let ik_b = bundle.identity;
    let spk_b = bundle.signed_prekey.public;

    let eph = X25519Secret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = X25519Public::from(&eph).to_bytes();

    // Classical X3DH legs.
    let mut dh1 = dh(me.dh_secret(), &spk_b); // IK_A x SPK_B
    let mut dh2 = dh(&eph, &ik_b.dh); // EK_A x IK_B
    let mut dh3 = dh(&eph, &spk_b); // EK_A x SPK_B

    // Post-quantum leg.
    let kem_pub = logos_identity::KemPublic::from_bytes(&bundle.kem_prekey.public)?;
    let (kem_ct, ss) = kem_pub.encapsulate()?;

    let mut ikm = Vec::new();
    ikm.extend_from_slice(&F);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    let one_time_prekey_id = bundle.one_time_prekey.as_ref().map(|otk| {
        let mut dh4 = dh(&eph, &otk.public); // EK_A x OPK_B
        ikm.extend_from_slice(&dh4);
        dh4.zeroize();
        otk.id
    });
    ikm.extend_from_slice(&ss);

    let info = transcript(&ik_a, &ik_b, &eph_pub, &kem_ct.0);
    let root_key = derive(ikm, &info);

    dh1.zeroize();
    dh2.zeroize();
    dh3.zeroize();

    Ok(InitiatorResult {
        root_key,
        responder_signed_prekey_pub: spk_b,
        initial_message: InitialMessage {
            initiator_identity: ik_a,
            ephemeral_pub: eph_pub,
            signed_prekey_id: bundle.signed_prekey.id,
            one_time_prekey_id,
            kem_prekey_id: bundle.kem_prekey.id,
            kem_ciphertext: kem_ct.0,
        },
    })
}

/// Run PQXDH as the **responder**, re-deriving the same key from the initial message.
///
/// `signed_prekey_priv` / `one_time_prekey_priv` are the private halves of the
/// prekeys the initiator selected; `kem_secret` is the matching KEM prekey secret.
pub fn respond(
    me: &IdentityKeyPair,
    signed_prekey_priv: [u8; 32],
    one_time_prekey_priv: Option<[u8; 32]>,
    kem_secret: &KemSecret,
    msg: &InitialMessage,
) -> Result<ResponderResult, PqxdhError> {
    let ik_a = msg.initiator_identity;
    let ik_b = me.public();
    let spk_secret = X25519Secret::from(signed_prekey_priv);

    let mut dh1 = dh(&spk_secret, &ik_a.dh); // SPK_B x IK_A
    let mut dh2 = dh(me.dh_secret(), &msg.ephemeral_pub); // IK_B x EK_A
    let mut dh3 = dh(&spk_secret, &msg.ephemeral_pub); // SPK_B x EK_A

    let ss = kem_secret.decapsulate(&KemCiphertext(msg.kem_ciphertext.clone()))?;

    let mut ikm = Vec::new();
    ikm.extend_from_slice(&F);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    if msg.one_time_prekey_id.is_some() {
        let otk_priv = one_time_prekey_priv.ok_or(PqxdhError::MissingOneTimePrekey)?;
        let mut dh4 = dh(&X25519Secret::from(otk_priv), &msg.ephemeral_pub);
        ikm.extend_from_slice(&dh4);
        dh4.zeroize();
    }
    ikm.extend_from_slice(&ss);

    let info = transcript(&ik_a, &ik_b, &msg.ephemeral_pub, &msg.kem_ciphertext);
    let root_key = derive(ikm, &info);

    dh1.zeroize();
    dh2.zeroize();
    dh3.zeroize();

    Ok(ResponderResult {
        root_key,
        signed_prekey_priv,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use logos_identity::{new_kem_prekey, new_one_time_prekey, new_signed_prekey};

    fn bundle_with_secrets(
        id: &IdentityKeyPair,
        with_otk: bool,
    ) -> (PreKeyBundle, [u8; 32], Option<[u8; 32]>, KemSecret) {
        let (spk_pub, spk_sec) = new_signed_prekey(1, id);
        let (kpk_pub, kpk_sec) = new_kem_prekey(1, id);
        let (otk_pub, otk_sec) = if with_otk {
            let (p, s) = new_one_time_prekey(9);
            (Some(p), Some(s.secret.to_bytes()))
        } else {
            (None, None)
        };
        let bundle = PreKeyBundle {
            username: "bob".into(),
            identity: id.public(),
            signed_prekey: spk_pub,
            one_time_prekey: otk_pub,
            kem_prekey: kpk_pub,
        };
        (bundle, spk_sec.secret.to_bytes(), otk_sec, kpk_sec.secret)
    }

    #[test]
    fn initiator_and_responder_agree_with_one_time_prekey() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let (bundle, spk_priv, otk_priv, kem_sec) = bundle_with_secrets(&bob, true);

        let init = initiate(&alice, &bundle).unwrap();
        let resp = respond(&bob, spk_priv, otk_priv, &kem_sec, &init.initial_message).unwrap();

        assert_eq!(init.root_key, resp.root_key);
    }

    #[test]
    fn initiator_and_responder_agree_without_one_time_prekey() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let (bundle, spk_priv, _otk, kem_sec) = bundle_with_secrets(&bob, false);

        let init = initiate(&alice, &bundle).unwrap();
        let resp = respond(&bob, spk_priv, None, &kem_sec, &init.initial_message).unwrap();
        assert_eq!(init.root_key, resp.root_key);
    }

    #[test]
    fn tampered_ephemeral_breaks_agreement() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let (bundle, spk_priv, otk_priv, kem_sec) = bundle_with_secrets(&bob, true);

        let init = initiate(&alice, &bundle).unwrap();
        let mut tampered = init.initial_message.clone();
        tampered.ephemeral_pub[0] ^= 0xff;
        let resp = respond(&bob, spk_priv, otk_priv, &kem_sec, &tampered).unwrap();
        assert_ne!(init.root_key, resp.root_key);
    }

    #[test]
    fn handshake_feeds_ratchet() {
        // End-to-end: PQXDH establishes the root key, then the ratchet exchanges messages.
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let (bundle, spk_priv, otk_priv, kem_sec) = bundle_with_secrets(&bob, true);

        let init = initiate(&alice, &bundle).unwrap();
        let resp = respond(&bob, spk_priv, otk_priv, &kem_sec, &init.initial_message).unwrap();

        let mut a = logos_ratchet::RatchetState::init_initiator(
            init.root_key,
            init.responder_signed_prekey_pub,
        );
        let mut b =
            logos_ratchet::RatchetState::init_responder(resp.root_key, resp.signed_prekey_priv);
        let m = a.encrypt(b"first message after handshake", b"");
        assert_eq!(
            b.decrypt(&m, b"").unwrap(),
            b"first message after handshake"
        );
    }
}
