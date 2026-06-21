//! Sender-key symmetric ratchet for E2EE group messages (roadmap P4.0a).
//!
//! A sender key is a one-directional **hash ratchet**: each member holds a 32-byte
//! chain key that derives a fresh per-message key and ratchets forward (HMAC-SHA256),
//! giving forward secrecy without a DH step. There is **no** post-compromise security
//! (no DH ratchet) — that is the documented v1 trade-off vs. the pairwise Double
//! Ratchet; MLS (P4.1) replaces this. Per-message *authenticity* is NOT provided here:
//! every group member who can decrypt also knows the chain key, so the client layer
//! signs each message with the sender's per-group Ed25519 key. This module only
//! provides confidentiality + ordering (the symmetric ratchet + AEAD).
//!
//! Mirrors the crate's Double Ratchet conventions: ChaCha20-Poly1305 AEAD over a
//! one-time message key, a **transactional** receive (state mutates only on AEAD
//! success), and a bounded skipped-key buffer for out-of-order delivery. Distinct
//! HKDF domain strings keep its key schedule independent of the pairwise ratchet.
//!
//! EXPERIMENTAL — UNAUDITED.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// Max message keys we will ratchet past in one receive before refusing — an
/// attacker-controlled `iteration` can't force unbounded work (mirrors the Double
/// Ratchet's `MAX_SKIP`).
const MAX_SKIP: u32 = 1000;

/// Global cap on stored skipped message keys (FIFO eviction past this), so a stream
/// of gaps can't grow memory without bound.
const MAX_SKIP_TOTAL: usize = 2000;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SenderKeyError {
    #[error("AEAD decryption failed")]
    Decrypt,
    #[error("message key already used or too old")]
    AlreadyUsed,
    #[error("too many skipped messages")]
    TooManySkipped,
}

/// chain key = HMAC(ck, 0x02); message key = HMAC(ck, 0x01). Same construction as the
/// pairwise chain KDF, but each sender chain is keyed by an independent random chain
/// key, so reuse of the construction is safe (no shared key ever feeds both).
fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
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

/// Derive a unique AEAD key + nonce from a one-time message key. Distinct HKDF
/// domain from the pairwise ratchet (`LogosRatchetMsgKeyv1`) so the schedules can't
/// be confused even if a key value ever coincided.
fn mk_to_aead(mk: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), mk);
    let mut okm = [0u8; 44];
    hk.expand(b"LogosSenderKeyMsgKeyv1", &mut okm)
        .expect("hkdf len ok");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (key, nonce)
}

/// Bind the message `iteration` into the AEAD associated data alongside the caller's
/// `ad` (e.g. the group id), so a ciphertext can't be lifted to a different position
/// or group even if a key ever repeated.
fn full_ad(iteration: u32, ad: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(ad.len() + 4);
    v.extend_from_slice(ad);
    v.extend_from_slice(&iteration.to_be_bytes());
    v
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

fn aead_decrypt(mk: &[u8; 32], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, SenderKeyError> {
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
        .map_err(|_| SenderKeyError::Decrypt);
    key.zeroize();
    nonce.zeroize();
    pt
}

/// The **sending** half of a sender key: a member's own forward-ratcheting chain.
/// The current `(chain_key, iteration)` is distributed to peers (over the pairwise
/// Double Ratchet) so they can construct a matching [`ReceiverChain`].
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SenderChain {
    chain_key: [u8; 32],
    #[zeroize(skip)]
    iteration: u32,
}

impl SenderChain {
    /// Create a fresh sending chain with a random initial chain key at iteration 0.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut chain_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut chain_key);
        Self {
            chain_key,
            iteration: 0,
        }
    }

    /// The current chain key — hand this (with [`iteration`](Self::iteration)) to a
    /// peer so they can decrypt from this point forward. A peer given the current
    /// state cannot read earlier messages (forward secrecy of the hash ratchet).
    pub fn chain_key(&self) -> [u8; 32] {
        self.chain_key
    }

    /// The next iteration this chain will emit.
    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    /// Ratchet once and AEAD-encrypt `plaintext`. Returns the `iteration` the message
    /// was sealed at (the receiver needs it to derive the matching key) and the
    /// ciphertext. `ad` is bound into the AEAD (the client passes the group id).
    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> (u32, Vec<u8>) {
        let iteration = self.iteration;
        let (new_ck, mut mk) = kdf_ck(&self.chain_key);
        self.chain_key.zeroize();
        self.chain_key = new_ck;
        self.iteration += 1;
        let ct = aead_encrypt(&mk, plaintext, &full_ad(iteration, ad));
        mk.zeroize();
        (iteration, ct)
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SkippedKey {
    #[zeroize(skip)]
    iteration: u32,
    mk: [u8; 32],
}

/// The **receiving** half of a peer's sender key: tracks that peer's chain so we can
/// decrypt their group messages in order, buffering keys for out-of-order delivery.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ReceiverChain {
    chain_key: [u8; 32],
    #[zeroize(skip)]
    next_iteration: u32,
    skipped: Vec<SkippedKey>,
}

impl ReceiverChain {
    /// Construct from a peer's distributed `(chain_key, iteration)`.
    pub fn new(chain_key: [u8; 32], iteration: u32) -> Self {
        Self {
            chain_key,
            next_iteration: iteration,
            skipped: Vec::new(),
        }
    }

    /// Decrypt a message sealed at `iteration`. **Transactional**: chain/skipped-key
    /// state is staged on a clone and committed only if AEAD authentication succeeds,
    /// so a forged or out-of-window message cannot desynchronize the chain.
    pub fn decrypt(
        &mut self,
        iteration: u32,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, SenderKeyError> {
        let mut staged = self.clone();
        let pt = staged.decrypt_inner(iteration, ciphertext, ad)?;
        *self = staged;
        Ok(pt)
    }

    fn decrypt_inner(
        &mut self,
        iteration: u32,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, SenderKeyError> {
        // Older than the chain head: only decryptable from the skipped buffer.
        if iteration < self.next_iteration {
            let idx = self
                .skipped
                .iter()
                .position(|s| s.iteration == iteration)
                .ok_or(SenderKeyError::AlreadyUsed)?;
            let mut mk = self.skipped[idx].mk;
            let pt = aead_decrypt(&mk, ciphertext, &full_ad(iteration, ad));
            mk.zeroize();
            let pt = pt?;
            self.skipped[idx].mk.zeroize();
            self.skipped.remove(idx);
            return Ok(pt);
        }

        // Ratchet forward to `iteration`, buffering the keys we skip past.
        if self.next_iteration.saturating_add(MAX_SKIP) < iteration {
            return Err(SenderKeyError::TooManySkipped);
        }
        let mut ck = self.chain_key;
        while self.next_iteration < iteration {
            let (new_ck, mk) = kdf_ck(&ck);
            ck.zeroize();
            ck = new_ck;
            if self.skipped.len() >= MAX_SKIP_TOTAL {
                self.skipped[0].mk.zeroize();
                self.skipped.remove(0);
            }
            self.skipped.push(SkippedKey {
                iteration: self.next_iteration,
                mk,
            });
            self.next_iteration += 1;
        }
        // Derive the key for `iteration` and try to decrypt before committing.
        let (new_ck, mut mk) = kdf_ck(&ck);
        ck.zeroize();
        let pt = aead_decrypt(&mk, ciphertext, &full_ad(iteration, ad));
        mk.zeroize();
        let pt = pt?;
        self.chain_key.zeroize();
        self.chain_key = new_ck;
        self.next_iteration = iteration + 1;
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (SenderChain, ReceiverChain) {
        let sender = SenderChain::generate();
        let receiver = ReceiverChain::new(sender.chain_key(), sender.iteration());
        (sender, receiver)
    }

    #[test]
    fn in_order_roundtrip() {
        let (mut s, mut r) = pair();
        for i in 0..5 {
            let msg = format!("message {i}");
            let (it, ct) = s.encrypt(msg.as_bytes(), b"group-1");
            assert_eq!(it, i);
            assert_eq!(r.decrypt(it, &ct, b"group-1").unwrap(), msg.as_bytes());
        }
    }

    #[test]
    fn out_of_order_delivery() {
        let (mut s, mut r) = pair();
        let (i0, c0) = s.encrypt(b"zero", b"g");
        let (i1, c1) = s.encrypt(b"one", b"g");
        let (i2, c2) = s.encrypt(b"two", b"g");
        // deliver 2, 0, 1
        assert_eq!(r.decrypt(i2, &c2, b"g").unwrap(), b"two");
        assert_eq!(r.decrypt(i0, &c0, b"g").unwrap(), b"zero");
        assert_eq!(r.decrypt(i1, &c1, b"g").unwrap(), b"one");
    }

    #[test]
    fn replay_of_consumed_message_is_rejected() {
        let (mut s, mut r) = pair();
        let (it, ct) = s.encrypt(b"once", b"g");
        assert_eq!(r.decrypt(it, &ct, b"g").unwrap(), b"once");
        // The skipped key was removed on first use; a replay can't be decrypted.
        assert_eq!(r.decrypt(it, &ct, b"g"), Err(SenderKeyError::AlreadyUsed));
    }

    #[test]
    fn tampered_ciphertext_rejected_and_state_unchanged() {
        let (mut s, mut r) = pair();
        let (i0, c0) = s.encrypt(b"first", b"g");
        assert_eq!(r.decrypt(i0, &c0, b"g").unwrap(), b"first");

        let before = serde_json::to_vec(&r).unwrap();
        let (i1, mut c1) = s.encrypt(b"second", b"g");
        c1[0] ^= 0xff;
        assert!(r.decrypt(i1, &c1, b"g").is_err());
        assert_eq!(
            before,
            serde_json::to_vec(&r).unwrap(),
            "forged msg mutated state"
        );

        // A far-future forged iteration must not desync the chain either.
        assert!(r.decrypt(500, &c1, b"g").is_err());
        assert_eq!(
            before,
            serde_json::to_vec(&r).unwrap(),
            "forged future iter mutated state"
        );

        // The next genuine message still decrypts.
        let (i1b, c1b) = s.encrypt(b"third", b"g");
        // (i1 was burned by the sender's encrypt; i1b follows it.)
        assert_eq!(i1b, i1 + 1);
        // Receiver was never advanced past i0, so it ratchets forward to i1b here.
        let (_, _) = (i1, &c1);
        assert_eq!(r.decrypt(i1b, &c1b, b"g").unwrap(), b"third");
    }

    #[test]
    fn wrong_associated_data_rejected() {
        let (mut s, mut r) = pair();
        let (it, ct) = s.encrypt(b"secret", b"group-A");
        assert!(r.decrypt(it, &ct, b"group-B").is_err());
    }

    #[test]
    fn too_large_a_gap_is_refused() {
        let (s, mut r) = pair();
        let _ = s;
        // No genuine message exists at this iteration; the gap alone must be refused
        // without doing unbounded work.
        assert_eq!(
            r.decrypt(MAX_SKIP + 1, b"x", b"g"),
            Err(SenderKeyError::TooManySkipped)
        );
    }

    #[test]
    fn state_serializes_and_resumes() {
        let (mut s, r) = pair();
        let (i0, c0) = s.encrypt(b"before", b"g");
        let mut r2: ReceiverChain =
            serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
        assert_eq!(r2.decrypt(i0, &c0, b"g").unwrap(), b"before");
        let mut s2: SenderChain = serde_json::from_slice(&serde_json::to_vec(&s).unwrap()).unwrap();
        let (i1, c1) = s2.encrypt(b"after", b"g");
        assert_eq!(r2.decrypt(i1, &c1, b"g").unwrap(), b"after");
    }
}
