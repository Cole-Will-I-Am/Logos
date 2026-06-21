//! Double Ratchet (Signal spec) over audited primitives: X25519 DH ratchet,
//! HKDF-SHA256 root KDF, HMAC-SHA256 chain KDF, ChaCha20-Poly1305 AEAD.
//! Provides forward secrecy and post-compromise security for the ongoing 1:1
//! session established by `logos-pqxdh`.
//!
//! Implemented directly against the published Double Ratchet specification
//! (Perrin/Marlinspike). No novel cryptography — only the audited primitives
//! composed per spec. EXPERIMENTAL — UNAUDITED.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

pub mod senderkey;

/// Bound on how many message keys we will skip in a single chain step before
/// refusing — prevents a malicious header from forcing huge work.
const MAX_SKIP: u32 = 1000;

/// Global bound on total stored skipped message keys (across chains). Oldest are
/// evicted FIFO past this — bounds memory regardless of ratchet churn (F-09).
const MAX_SKIP_TOTAL: usize = 2000;

#[derive(Debug, Error)]
pub enum RatchetError {
    #[error("AEAD decryption failed")]
    Decrypt,
    #[error("no receiving chain established yet")]
    NoReceivingChain,
    #[error("too many skipped messages")]
    TooManySkipped,
}

/// Per-message header, authenticated as associated data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    pub dh: [u8; 32],
    pub pn: u32,
    pub n: u32,
}

impl Header {
    fn as_ad(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(40);
        v.extend_from_slice(&self.dh);
        v.extend_from_slice(&self.pn.to_be_bytes());
        v.extend_from_slice(&self.n.to_be_bytes());
        v
    }
}

/// A ratchet-encrypted message: header + AEAD ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetMessage {
    pub header: Header,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct Skipped {
    #[zeroize(skip)]
    dh: [u8; 32],
    #[zeroize(skip)]
    n: u32,
    mk: [u8; 32],
}

/// Serializable Double Ratchet state (persisted in the encrypted client store).
///
/// Dropping a `RatchetState` zeroizes the root key, DH secrets, and chain keys
/// via [`ZeroizeOnDrop`]. Public ratchet public keys and counters are skipped so
/// they remain usable for serialised wire/storage formats.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RatchetState {
    rk: [u8; 32],
    dhs_priv: [u8; 32],
    #[zeroize(skip)]
    dhs_pub: [u8; 32],
    #[zeroize(skip)]
    dhr: Option<[u8; 32]>,
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    #[zeroize(skip)]
    ns: u32,
    #[zeroize(skip)]
    nr: u32,
    #[zeroize(skip)]
    pn: u32,
    skipped: Vec<Skipped>,
}

fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(rk), dh_out);
    let mut okm = [0u8; 64];
    hk.expand(b"LogosRatchetRootKDFv1", &mut okm)
        .expect("hkdf len ok");
    let mut new_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    new_rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (new_rk, ck)
}

fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // chain key = HMAC(ck, 0x02); message key = HMAC(ck, 0x01)
    let mut m_mk = <HmacSha256 as Mac>::new_from_slice(ck).expect("hmac key");
    m_mk.update(&[0x01]);
    let mut mk = [0u8; 32];
    mk.copy_from_slice(&m_mk.finalize().into_bytes());

    let mut m_ck = <HmacSha256 as Mac>::new_from_slice(ck).expect("hmac key");
    m_ck.update(&[0x02]);
    let mut new_ck = [0u8; 32];
    new_ck.copy_from_slice(&m_ck.finalize().into_bytes());

    (new_ck, mk)
}

/// Derive a unique AEAD key + nonce from a (one-time) message key.
fn mk_to_aead(mk: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), mk);
    let mut okm = [0u8; 44];
    hk.expand(b"LogosRatchetMsgKeyv1", &mut okm)
        .expect("hkdf len ok");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (key, nonce)
}

fn aead_encrypt(mk: &[u8; 32], plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
    let (mut key, mut nonce) = mk_to_aead(mk);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .expect("aead encrypt");
    key.zeroize();
    nonce.zeroize();
    ct
}

fn aead_decrypt(mk: &[u8; 32], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, RatchetError> {
    let (mut key, mut nonce) = mk_to_aead(mk);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .map_err(|_| RatchetError::Decrypt);
    key.zeroize();
    nonce.zeroize();
    pt
}

fn dh(priv_bytes: &[u8; 32], pub_bytes: &[u8; 32]) -> [u8; 32] {
    let secret = X25519Secret::from(*priv_bytes);
    secret
        .diffie_hellman(&X25519Public::from(*pub_bytes))
        .to_bytes()
}

impl RatchetState {
    /// Initiator (Alice): has the root key from the handshake and the responder's
    /// initial ratchet public key (their signed prekey).
    pub fn init_initiator(root_key: [u8; 32], their_ratchet_pub: [u8; 32]) -> Self {
        let dhs_priv = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let dhs_pub = X25519Public::from(&dhs_priv).to_bytes();
        let dhs_priv_bytes = dhs_priv.to_bytes();
        let (rk, cks) = kdf_rk(&root_key, &dh(&dhs_priv_bytes, &their_ratchet_pub));
        Self {
            rk,
            dhs_priv: dhs_priv_bytes,
            dhs_pub,
            dhr: Some(their_ratchet_pub),
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: Vec::new(),
        }
    }

    /// Responder (Bob): has the root key and his own initial ratchet keypair (the
    /// signed prekey private key the initiator used in the handshake).
    pub fn init_responder(root_key: [u8; 32], my_ratchet_priv: [u8; 32]) -> Self {
        let dhs_pub = X25519Public::from(&X25519Secret::from(my_ratchet_priv)).to_bytes();
        Self {
            rk: root_key,
            dhs_priv: my_ratchet_priv,
            dhs_pub,
            dhr: None,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: Vec::new(),
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> RatchetMessage {
        let ck = self
            .cks
            .expect("sender chain must be initialized for the initiator's first send");
        let (new_ck, mut mk) = kdf_ck(&ck);
        self.cks = Some(new_ck);
        let header = Header {
            dh: self.dhs_pub,
            pn: self.pn,
            n: self.ns,
        };
        self.ns += 1;
        let mut ad = associated_data.to_vec();
        ad.extend_from_slice(&header.as_ad());
        let ciphertext = aead_encrypt(&mk, plaintext, &ad);
        mk.zeroize();
        RatchetMessage { header, ciphertext }
    }

    /// Decrypt a message. **Transactional**: all state changes (DH ratchet,
    /// chain advance, skipped keys) are staged on a clone and committed only if
    /// AEAD authentication succeeds — a forged/invalid message cannot mutate or
    /// desynchronize the receiver (Double Ratchet spec requirement).
    pub fn decrypt(
        &mut self,
        msg: &RatchetMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        let mut staged = self.clone();
        let pt = staged.decrypt_inner(msg, associated_data)?;
        *self = staged;
        Ok(pt)
    }

    fn decrypt_inner(
        &mut self,
        msg: &RatchetMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        if let Some(pt) = self.try_skipped(msg, associated_data)? {
            return Ok(pt);
        }
        if self.dhr.as_ref() != Some(&msg.header.dh) {
            self.skip_message_keys(msg.header.pn)?;
            self.dh_ratchet(&msg.header);
        }
        self.skip_message_keys(msg.header.n)?;
        let ck = self.ckr.ok_or(RatchetError::NoReceivingChain)?;
        let (new_ck, mut mk) = kdf_ck(&ck);
        self.ckr = Some(new_ck);
        self.nr += 1;
        let mut ad = associated_data.to_vec();
        ad.extend_from_slice(&msg.header.as_ad());
        let pt = aead_decrypt(&mk, &msg.ciphertext, &ad);
        mk.zeroize();
        pt
    }

    fn try_skipped(
        &mut self,
        msg: &RatchetMessage,
        associated_data: &[u8],
    ) -> Result<Option<Vec<u8>>, RatchetError> {
        if let Some(idx) = self
            .skipped
            .iter()
            .position(|s| s.dh == msg.header.dh && s.n == msg.header.n)
        {
            let mut mk = self.skipped[idx].mk;
            let mut ad = associated_data.to_vec();
            ad.extend_from_slice(&msg.header.as_ad());
            let pt = aead_decrypt(&mk, &msg.ciphertext, &ad)?;
            mk.zeroize();
            self.skipped.remove(idx);
            return Ok(Some(pt));
        }
        Ok(None)
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<(), RatchetError> {
        if let Some(ck) = self.ckr {
            // `until` (header.n / header.pn) is attacker-controlled; use a
            // saturating add so an extreme value can't integer-overflow here.
            if self.nr.saturating_add(MAX_SKIP) < until {
                return Err(RatchetError::TooManySkipped);
            }
            let dhr = self.dhr.expect("dhr set when ckr set");
            let mut ck = ck;
            while self.nr < until {
                let (new_ck, mk) = kdf_ck(&ck);
                ck = new_ck;
                // Global cap: bound total stored skipped keys (FIFO eviction) so a
                // sequence of ratchet steps can't grow memory without limit.
                if self.skipped.len() >= MAX_SKIP_TOTAL {
                    self.skipped.remove(0);
                }
                self.skipped.push(Skipped {
                    dh: dhr,
                    n: self.nr,
                    mk,
                });
                self.nr += 1;
            }
            self.ckr = Some(ck);
        }
        Ok(())
    }

    fn dh_ratchet(&mut self, header: &Header) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header.dh);
        let (rk1, ckr) = kdf_rk(&self.rk, &dh(&self.dhs_priv, &header.dh));
        self.rk = rk1;
        self.ckr = Some(ckr);
        let new_priv = X25519Secret::random_from_rng(rand::rngs::OsRng);
        self.dhs_pub = X25519Public::from(&new_priv).to_bytes();
        self.dhs_priv = new_priv.to_bytes();
        let (rk2, cks) = kdf_rk(&self.rk, &dh(&self.dhs_priv, &header.dh));
        self.rk = rk2;
        self.cks = Some(cks);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(root: [u8; 32]) -> (RatchetState, RatchetState) {
        // Bob's initial ratchet keypair == his signed prekey.
        let bob_priv = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let bob_pub = X25519Public::from(&bob_priv).to_bytes();
        let alice = RatchetState::init_initiator(root, bob_pub);
        let bob = RatchetState::init_responder(root, bob_priv.to_bytes());
        (alice, bob)
    }

    #[test]
    fn basic_roundtrip_both_directions() {
        let (mut a, mut b) = pair([7u8; 32]);
        let m1 = a.encrypt(b"hello bob", b"ad");
        assert_eq!(b.decrypt(&m1, b"ad").unwrap(), b"hello bob");
        let m2 = b.encrypt(b"hi alice", b"ad");
        assert_eq!(a.decrypt(&m2, b"ad").unwrap(), b"hi alice");
        let m3 = a.encrypt(b"how are you", b"ad");
        assert_eq!(b.decrypt(&m3, b"ad").unwrap(), b"how are you");
    }

    #[test]
    fn out_of_order_delivery() {
        let (mut a, mut b) = pair([9u8; 32]);
        let m1 = a.encrypt(b"one", b"");
        let m2 = a.encrypt(b"two", b"");
        let m3 = a.encrypt(b"three", b"");
        // deliver out of order: 3, 1, 2
        assert_eq!(b.decrypt(&m3, b"").unwrap(), b"three");
        assert_eq!(b.decrypt(&m1, b"").unwrap(), b"one");
        assert_eq!(b.decrypt(&m2, b"").unwrap(), b"two");
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (mut a, mut b) = pair([3u8; 32]);
        let mut m = a.encrypt(b"secret", b"ad");
        m.ciphertext[0] ^= 0xff;
        assert!(b.decrypt(&m, b"ad").is_err());
    }

    #[test]
    fn forged_message_does_not_mutate_state() {
        let (mut a, mut b) = pair([11u8; 32]);
        let m1 = a.encrypt(b"hi", b"");
        assert_eq!(b.decrypt(&m1, b"").unwrap(), b"hi");

        let before = serde_json::to_vec(&b).unwrap();
        // A forged message with a NEW dh header (would trigger a DH ratchet) but a
        // broken AEAD tag must leave the receiver completely unchanged.
        let mut forged = a.encrypt(b"tampered", b"");
        forged.header.dh = [42u8; 32];
        forged.ciphertext[0] ^= 0xff;
        assert!(b.decrypt(&forged, b"").is_err());
        assert_eq!(
            before,
            serde_json::to_vec(&b).unwrap(),
            "forged msg mutated state"
        );

        // And the receiver still works on the next legitimate message.
        let m2 = a.encrypt(b"still works", b"");
        assert_eq!(b.decrypt(&m2, b"").unwrap(), b"still works");
    }

    #[test]
    fn wrong_associated_data_rejected() {
        let (mut a, mut b) = pair([4u8; 32]);
        let m = a.encrypt(b"secret", b"ad-1");
        assert!(b.decrypt(&m, b"ad-2").is_err());
    }

    #[test]
    fn state_serializes_and_resumes() {
        let (mut a, mut b) = pair([5u8; 32]);
        let m1 = a.encrypt(b"before", b"");
        assert_eq!(b.decrypt(&m1, b"").unwrap(), b"before");
        // persist + restore Alice mid-session
        let mut restored = postcard_roundtrip(&a);
        let m2 = restored.encrypt(b"after", b"");
        assert_eq!(b.decrypt(&m2, b"").unwrap(), b"after");
    }

    fn postcard_roundtrip(state: &RatchetState) -> RatchetState {
        let json = serde_json::to_vec(state).unwrap();
        serde_json::from_slice(&json).unwrap()
    }
}
