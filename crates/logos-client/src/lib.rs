//! Logos client engine — ties identity, PQXDH, the Double Ratchet, and sealed
//! sender together and talks to the relay. The public API is **synchronous** and
//! uses plain types (strings/bytes) so it can be wrapped for an iOS app (Swift
//! via UniFFI / an xcframework) without async leaking across the FFI boundary.
//!
//! EXPERIMENTAL — UNAUDITED.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use logos_identity::{
    new_kem_prekey, new_one_time_prekey, new_signed_prekey, IdentityKeyPair, IdentityPublic,
    KemSecret,
};
use logos_pqxdh::{initiate, respond, InitialMessage};
use logos_proto::{
    cert_signed_bytes, mailbox_id, registration_signed_bytes, CertRequest, CertResponse,
    DirectoryResponse, FetchResponse, OuterMessage, PostEnvelope, RegisterRequest,
    ServerKeyResponse,
};
use logos_ratchet::RatchetState;
use logos_sealed::{seal, unseal, SealedEnvelope, SenderCertificate};
use serde::{Deserialize, Serialize};

const ONE_TIME_PREKEY_COUNT: u32 = 20;

#[derive(Debug, thiserror::Error)]
#[error("logos-client: {0}")]
pub struct ClientError(String);

type Result<T> = std::result::Result<T, ClientError>;

fn err<E: std::fmt::Display>(e: E) -> ClientError {
    ClientError(e.to_string())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Serialize, Deserialize)]
struct OtkSecret {
    id: u32,
    secret: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct Session {
    ratchet: RatchetState,
    peer_identity_dh: [u8; 32],
    sent_initial: bool,
    pending_initial: Option<InitialMessage>,
}

/// On-disk client state. Phase-1: stored as plaintext JSON — encryption-at-rest
/// (Argon2id-wrapped) is a tracked follow-up; local-device security is partly
/// out of scope per the threat model.
#[derive(Serialize, Deserialize)]
struct Store {
    username: String,
    identity_secret: Vec<u8>,
    signed_prekey_id: u32,
    signed_prekey_secret: [u8; 32],
    kem_prekey_id: u32,
    kem_prekey_secret: Vec<u8>,
    one_time: Vec<OtkSecret>,
    sessions: HashMap<String, Session>,
    /// TOFU-pinned identity per username (F-02/F-03): detects/blocks a relay
    /// swapping a known contact's identity key.
    #[serde(default)]
    contacts: HashMap<String, IdentityPublic>,
    server_vk: Option<[u8; 32]>,
    cert: Option<SenderCertificate>,
}

/// A received, decrypted message.
pub struct Incoming {
    pub from: String,
    pub text: String,
}

pub struct Client {
    store: Store,
    path: PathBuf,
    server_url: String,
    http: reqwest::blocking::Client,
}

impl Client {
    /// Create a new identity, register it with the relay, and persist to `path`.
    pub fn create(path: impl AsRef<Path>, server_url: &str, username: &str) -> Result<Self> {
        let identity = IdentityKeyPair::generate();
        let (spk_pub, spk_sec) = new_signed_prekey(1, &identity);
        let (kpk_pub, kpk_sec) = new_kem_prekey(1, &identity);
        let mut otk_pub = Vec::new();
        let mut otk_sec = Vec::new();
        for id in 1..=ONE_TIME_PREKEY_COUNT {
            let (p, s) = new_one_time_prekey(id);
            otk_pub.push(p);
            otk_sec.push(OtkSecret {
                id,
                secret: s.secret.to_bytes(),
            });
        }

        let reg_sig = identity.sign(&registration_signed_bytes(username, &identity.public()));
        let req = RegisterRequest {
            username: username.to_string(),
            identity: identity.public(),
            signed_prekey: spk_pub,
            kem_prekey: kpk_pub,
            one_time_prekeys: otk_pub,
            registration_sig: reg_sig.to_vec(),
        };

        let http = reqwest::blocking::Client::new();
        http.post(format!("{server_url}/v1/register"))
            .json(&req)
            .send()
            .map_err(err)?
            .error_for_status()
            .map_err(err)?;

        let server_vk: ServerKeyResponse = http
            .get(format!("{server_url}/v1/server-key"))
            .send()
            .map_err(err)?
            .json()
            .map_err(err)?;

        let store = Store {
            username: username.to_string(),
            identity_secret: identity.to_secret_bytes().to_vec(),
            signed_prekey_id: 1,
            signed_prekey_secret: spk_sec.secret.to_bytes(),
            kem_prekey_id: 1,
            kem_prekey_secret: kpk_sec.secret.to_bytes(),
            one_time: otk_sec,
            sessions: HashMap::new(),
            contacts: HashMap::new(),
            server_vk: Some(server_vk.verifying_key),
            cert: None,
        };
        let mut me = Self {
            store,
            path: path.as_ref().to_path_buf(),
            server_url: server_url.to_string(),
            http,
        };
        // F-06: acquire the sealed-sender certificate at registration time, so its
        // issuance isn't correlated by the relay with a later send.
        me.ensure_cert()?;
        me.save()?;
        Ok(me)
    }

    /// Load an existing client from `path`.
    pub fn load(path: impl AsRef<Path>, server_url: &str) -> Result<Self> {
        let bytes = std::fs::read(path.as_ref()).map_err(err)?;
        let store: Store = serde_json::from_slice(&bytes).map_err(err)?;
        Ok(Self {
            store,
            path: path.as_ref().to_path_buf(),
            server_url: server_url.to_string(),
            http: reqwest::blocking::Client::new(),
        })
    }

    pub fn username(&self) -> &str {
        &self.store.username
    }

    fn identity(&self) -> IdentityKeyPair {
        let arr: [u8; 64] = self
            .store
            .identity_secret
            .as_slice()
            .try_into()
            .expect("64-byte identity secret");
        IdentityKeyPair::from_secret_bytes(&arr)
    }

    fn identity_dh_priv(&self) -> [u8; 32] {
        self.store.identity_secret[32..].try_into().unwrap()
    }

    /// Our mailbox id (where peers deliver to us).
    pub fn mailbox(&self) -> String {
        mailbox_id(&self.identity().public().dh)
    }

    fn save(&self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.store).map_err(err)?;
        std::fs::write(&self.path, bytes).map_err(err)
    }

    fn ensure_cert(&mut self) -> Result<SenderCertificate> {
        if let Some(cert) = &self.store.cert {
            if cert.expires_unix > now() + 60 {
                return Ok(cert.clone());
            }
        }
        let identity = self.identity();
        let sig = identity.sign(&cert_signed_bytes(&self.store.username, &identity.public()));
        let req = CertRequest {
            username: self.store.username.clone(),
            identity: identity.public(),
            sig: sig.to_vec(),
        };
        let resp: CertResponse = self
            .http
            .post(format!("{}/v1/cert", self.server_url))
            .json(&req)
            .send()
            .map_err(err)?
            .error_for_status()
            .map_err(err)?
            .json()
            .map_err(err)?;
        self.store.cert = Some(resp.certificate.clone());
        Ok(resp.certificate)
    }

    fn ensure_session(&mut self, to: &str) -> Result<()> {
        if self.store.sessions.contains_key(to) {
            return Ok(());
        }
        let resp: DirectoryResponse = self
            .http
            .get(format!("{}/v1/directory/{to}", self.server_url))
            .send()
            .map_err(err)?
            .error_for_status()
            .map_err(err)?
            .json()
            .map_err(err)?;
        let bundle = resp.bundle;
        // F-02/F-03: TOFU-pin the recipient identity from the directory; refuse if
        // it changed from a previously seen value (possible relay key-substitution).
        self.pin_identity(to, &bundle.identity)?;
        let init = initiate(&self.identity(), &bundle).map_err(err)?;
        let ratchet = RatchetState::init_initiator(init.root_key, init.responder_signed_prekey_pub);
        self.store.sessions.insert(
            to.to_string(),
            Session {
                ratchet,
                peer_identity_dh: bundle.identity.dh,
                sent_initial: false,
                pending_initial: Some(init.initial_message),
            },
        );
        Ok(())
    }

    /// Encrypt and deliver `message` to `to`.
    pub fn send(&mut self, to: &str, message: &str) -> Result<()> {
        self.ensure_session(to)?;
        let cert = self.ensure_cert()?;

        let session = self.store.sessions.get_mut(to).expect("session ensured");
        let ratchet_msg = session.ratchet.encrypt(message.as_bytes(), b"");
        let outer = if !session.sent_initial {
            let initial = session
                .pending_initial
                .clone()
                .ok_or_else(|| ClientError("missing initial".into()))?;
            session.sent_initial = true;
            OuterMessage::Prekey {
                initial,
                ratchet: ratchet_msg,
            }
        } else {
            OuterMessage::Normal {
                ratchet: ratchet_msg,
            }
        };
        let peer_dh = session.peer_identity_dh;

        let outer_bytes = serde_json::to_vec(&outer).map_err(err)?;
        let envelope = seal(&peer_dh, &cert, &outer_bytes).map_err(err)?;
        let id = mailbox_id(&peer_dh);
        self.http
            .post(format!("{}/v1/mailbox/{id}", self.server_url))
            .json(&PostEnvelope { envelope })
            .send()
            .map_err(err)?
            .error_for_status()
            .map_err(err)?;
        self.save()
    }

    /// Fetch, decrypt, and return all pending messages.
    pub fn recv(&mut self) -> Result<Vec<Incoming>> {
        let id = self.mailbox();
        let resp: FetchResponse = self
            .http
            .get(format!("{}/v1/mailbox/{id}", self.server_url))
            .send()
            .map_err(err)?
            .error_for_status()
            .map_err(err)?
            .json()
            .map_err(err)?;

        let server_vk = self
            .store
            .server_vk
            .ok_or_else(|| ClientError("no server key".into()))?;
        let dh_priv = self.identity_dh_priv();
        let mut out = Vec::new();

        // F-07: process each envelope independently; a malformed/undecryptable one
        // is quarantined (skipped) rather than failing the whole batch.
        for env in resp.envelopes {
            if let Ok(inc) = self.process_envelope(&env, &server_vk, &dh_priv) {
                out.push(inc);
            }
        }
        self.save()?;
        Ok(out)
    }

    fn process_envelope(
        &mut self,
        env: &SealedEnvelope,
        server_vk: &[u8; 32],
        dh_priv: &[u8; 32],
    ) -> Result<Incoming> {
        let (cert, payload) = unseal(dh_priv, env, server_vk, now()).map_err(err)?;
        let from = cert.sender_username.clone();
        let outer: OuterMessage = serde_json::from_slice(&payload).map_err(err)?;
        match outer {
            OuterMessage::Prekey { initial, ratchet } => {
                let text = self.establish_and_decrypt(&cert, initial, ratchet)?;
                Ok(Incoming { from, text })
            }
            OuterMessage::Normal { ratchet } => {
                let session = self
                    .store
                    .sessions
                    .get_mut(&from)
                    .ok_or_else(|| ClientError(format!("no session for {from}")))?;
                let pt = session.ratchet.decrypt(&ratchet, b"").map_err(err)?;
                Ok(Incoming {
                    from,
                    text: String::from_utf8_lossy(&pt).into_owned(),
                })
            }
        }
    }

    /// TOFU identity pinning: first sighting is recorded; a later mismatch is
    /// refused (F-02/F-03). Real continuous verification needs key transparency.
    fn pin_identity(&mut self, username: &str, identity: &IdentityPublic) -> Result<()> {
        match self.store.contacts.get(username) {
            Some(known) if known != identity => Err(ClientError(format!(
                "identity for '{username}' changed — refusing (possible impersonation/MITM)"
            ))),
            Some(_) => Ok(()),
            None => {
                self.store.contacts.insert(username.to_string(), *identity);
                Ok(())
            }
        }
    }

    fn establish_and_decrypt(
        &mut self,
        cert: &SenderCertificate,
        initial: InitialMessage,
        ratchet_msg: logos_ratchet::RatchetMessage,
    ) -> Result<String> {
        // F-02/F-03: the sealed-sender cert is only delivery authorization. The
        // real sender identity is the PQXDH initiator identity (proven by the
        // handshake DH legs). Bind them, then TOFU-pin — so a malicious relay
        // can't forge a cert to impersonate or hijack a known contact's session.
        if cert.sender_identity != initial.initiator_identity {
            return Err(ClientError(
                "sender certificate identity does not match handshake identity".into(),
            ));
        }
        self.pin_identity(&cert.sender_username, &cert.sender_identity)?;
        if initial.signed_prekey_id != self.store.signed_prekey_id {
            return Err(ClientError("unknown signed prekey id".into()));
        }
        if initial.kem_prekey_id != self.store.kem_prekey_id {
            return Err(ClientError("unknown kem prekey id".into()));
        }
        let one_time_priv = match initial.one_time_prekey_id {
            Some(otk_id) => {
                let pos = self
                    .store
                    .one_time
                    .iter()
                    .position(|o| o.id == otk_id)
                    .ok_or_else(|| ClientError("unknown one-time prekey id".into()))?;
                Some(self.store.one_time.remove(pos).secret)
            }
            None => None,
        };
        let kem_secret = KemSecret::from_bytes(&self.store.kem_prekey_secret).map_err(err)?;
        let resp = respond(
            &self.identity(),
            self.store.signed_prekey_secret,
            one_time_priv,
            &kem_secret,
            &initial,
        )
        .map_err(err)?;
        let mut ratchet = RatchetState::init_responder(resp.root_key, resp.signed_prekey_priv);
        let pt = ratchet.decrypt(&ratchet_msg, b"").map_err(err)?;
        self.store.sessions.insert(
            cert.sender_username.clone(),
            Session {
                ratchet,
                peer_identity_dh: cert.sender_identity.dh,
                sent_initial: true,
                pending_initial: None,
            },
        );
        Ok(String::from_utf8_lossy(&pt).into_owned())
    }
}
