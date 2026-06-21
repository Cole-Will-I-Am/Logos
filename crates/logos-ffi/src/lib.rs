//! UniFFI surface for Logos — exposes the `logos-client` engine to Swift (iOS)
//! and other languages without reimplementing any crypto/protocol logic.
//!
//! The Rust client API is synchronous and plain-typed, so the binding is a thin
//! wrapper: a `LogosClient` object (mutable client state behind a `Mutex`, since
//! UniFFI object methods take `&self`) plus a record and an error type.
//!
//! EXPERIMENTAL — UNAUDITED.

use std::sync::{Arc, Mutex};

use logos_client::Client;

uniffi::setup_scaffolding!();

/// Errors surfaced across the FFI boundary. These are **typed** (not a single
/// string) so the UI can react precisely: `IdentityChanged` must drive the
/// high-friction identity interstitial, `NotRegistered` an "unknown user" message,
/// `Network` a quiet retry. `Client` is the catch-all for everything else.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum LogosError {
    /// A pinned contact's identity key changed — possible impersonation/MITM.
    #[error("identity for '{peer}' changed — possible impersonation or MITM")]
    IdentityChanged { peer: String },
    /// The peer isn't registered on this relay (unknown username / typo).
    #[error("'{peer}' isn't registered on this relay")]
    NotRegistered { peer: String },
    /// The chosen username is already taken on this relay — onboarding should ask
    /// for a different name (the relay was reached; it refused the name).
    #[error("the username '{username}' is already taken")]
    UsernameTaken { username: String },
    /// A recovery phrase failed to parse (wrong words / bad checksum) — restore
    /// should ask the user to re-check the words.
    #[error("that recovery phrase isn't valid — check the words and try again")]
    InvalidRecoveryPhrase,
    /// Transport-level failure reaching the relay. Retryable.
    #[error("{msg}")]
    Network { msg: String },
    /// Anything else (protocol, crypto, store, parse).
    #[error("{msg}")]
    Client { msg: String },
}

impl From<logos_client::ClientError> for LogosError {
    fn from(e: logos_client::ClientError) -> Self {
        use logos_client::ClientError as C;
        match e {
            C::IdentityChanged { peer } => LogosError::IdentityChanged { peer },
            C::NotRegistered { peer } => LogosError::NotRegistered { peer },
            C::UsernameTaken { username } => LogosError::UsernameTaken { username },
            C::InvalidRecoveryPhrase => LogosError::InvalidRecoveryPhrase,
            C::Network(msg) => LogosError::Network { msg },
            C::Other(msg) => LogosError::Client { msg },
        }
    }
}

/// A received, decrypted message.
#[derive(uniffi::Record)]
pub struct IncomingMessage {
    pub from: String,
    pub text: String,
}

/// Per-contact verification state for the verify UI.
#[derive(uniffi::Record)]
pub struct ContactSecurity {
    /// Human-comparable safety number, or `None` if no identity is pinned yet.
    pub safety_number: Option<String>,
    pub verified: bool,
    /// Unix seconds when the user marked this contact verified.
    pub verified_at: Option<u64>,
    /// How many times this contact's identity has changed (TOFU).
    pub key_changes: u32,
}

/// Stateful Logos client. Construct with `create` (new identity, registers with
/// the relay) or `load` (existing on-disk store), then `send` / `recv`.
#[derive(uniffi::Object)]
pub struct LogosClient {
    inner: Mutex<Client>,
}

#[uniffi::export]
impl LogosClient {
    /// Create a new identity, register it with the relay, and persist to `path`.
    ///
    /// `password` is stretched with Argon2id and used to encrypt the store at
    /// rest. Pass `None` only in test/dev settings.
    #[uniffi::constructor]
    pub fn create(
        path: String,
        server_url: String,
        username: String,
        password: Option<String>,
    ) -> Result<Arc<Self>, LogosError> {
        let client = Client::create(&path, &server_url, &username, password.as_deref())?;
        Ok(Arc::new(Self {
            inner: Mutex::new(client),
        }))
    }

    /// Load an existing client store from `path`.
    ///
    /// Decrypts the Argon2id-wrapped store with `password`.
    #[uniffi::constructor]
    pub fn load(
        path: String,
        server_url: String,
        password: Option<String>,
    ) -> Result<Arc<Self>, LogosError> {
        let client = Client::load(&path, &server_url, password.as_deref())?;
        Ok(Arc::new(Self {
            inner: Mutex::new(client),
        }))
    }

    /// Restore an identity from its 24-word recovery phrase onto a new device:
    /// re-derives the same keys, re-registers under `username`, and persists to
    /// `path`. Recovers the identity + username only — not history or contacts.
    #[uniffi::constructor]
    pub fn restore(
        path: String,
        server_url: String,
        username: String,
        recovery_phrase: String,
        password: Option<String>,
    ) -> Result<Arc<Self>, LogosError> {
        let client = Client::restore(
            &path,
            &server_url,
            &username,
            &recovery_phrase,
            password.as_deref(),
        )?;
        Ok(Arc::new(Self {
            inner: Mutex::new(client),
        }))
    }

    /// This identity's 24-word BIP39 recovery phrase (for the backup screen).
    /// Errors if the identity predates recovery support (legacy store).
    pub fn export_recovery_phrase(&self) -> Result<String, LogosError> {
        Ok(self
            .inner
            .lock()
            .expect("client lock")
            .export_recovery_phrase()?)
    }

    /// This client's username.
    pub fn username(&self) -> String {
        self.inner
            .lock()
            .expect("client lock")
            .username()
            .to_string()
    }

    /// Our mailbox id (where peers deliver to us).
    pub fn mailbox(&self) -> String {
        self.inner.lock().expect("client lock").mailbox()
    }

    /// Encrypt and deliver `message` to `to`.
    pub fn send(&self, to: String, message: String) -> Result<(), LogosError> {
        self.inner
            .lock()
            .expect("client lock")
            .send(&to, &message)?;
        Ok(())
    }

    /// Fetch, decrypt, and return all pending messages.
    pub fn recv(&self) -> Result<Vec<IncomingMessage>, LogosError> {
        let msgs = self.inner.lock().expect("client lock").recv()?;
        Ok(msgs
            .into_iter()
            .map(|m| IncomingMessage {
                from: m.from,
                text: m.text,
            })
            .collect())
    }

    /// Verification state for `peer` (safety number, verified flag, change count).
    pub fn contact_security(&self, peer: String) -> ContactSecurity {
        let c = self.inner.lock().expect("client lock");
        ContactSecurity {
            safety_number: c.safety_number(&peer),
            verified: c.is_verified(&peer),
            verified_at: c.verified_at(&peer),
            key_changes: c.key_changes(&peer),
        }
    }

    /// Mark `peer` as verified (after comparing safety numbers out-of-band).
    pub fn mark_verified(&self, peer: String) -> Result<(), LogosError> {
        self.inner
            .lock()
            .expect("client lock")
            .mark_verified(&peer)?;
        Ok(())
    }

    /// Recovery: accept a legitimate identity change (e.g. the peer reinstalled).
    pub fn reset_peer_identity(&self, peer: String) -> Result<(), LogosError> {
        self.inner
            .lock()
            .expect("client lock")
            .reset_peer_identity(&peer)?;
        Ok(())
    }

    /// Re-establish a stale session after `peer` restored from a recovery phrase
    /// (same identity). Clears only the local session so their next handshake is
    /// accepted; the pin/verification are kept.
    pub fn reset_session(&self, peer: String) -> Result<(), LogosError> {
        self.inner
            .lock()
            .expect("client lock")
            .reset_session(&peer)?;
        Ok(())
    }
}
