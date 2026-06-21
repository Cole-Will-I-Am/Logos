//! Logos relay — a minimal-trust store-and-forward server.
//!
//! It holds: a public-key directory (username → identity + prekeys), per-mailbox
//! queues of **opaque sealed envelopes** (delete-on-deliver), and an Ed25519 key
//! used only to issue sealed-sender certificates. It never sees message plaintext
//! and, thanks to sealed sender, never sees who sent a delivered message.
//!
//! Phase-1 store is in-memory (one process). Persistence (redb) and TTL sweeping
//! are deferred — the trust/visibility properties are identical.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, Path as AxumPath, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use ed25519_dalek::SigningKey;
use logos_identity::{
    verify, IdentityPublic, KemPreKeyPublic, OneTimePreKeyPublic, PreKeyBundle, SignedPreKeyPublic,
};
use logos_proto::{
    ack_signed_bytes, cert_signed_bytes, fetch_signed_bytes, mailbox_id, registration_signed_bytes,
    replenish_signed_bytes, validate_username, AckRequest, CertRequest, CertResponse,
    DirectoryResponse, FetchRequest, FetchResponse, PostEnvelope, RegisterRequest,
    ReplenishRequest, ServerKeyResponse, StoredEnvelope,
};
use logos_sealed::{issue_certificate, SealedEnvelope};
use serde::{Deserialize, Serialize};

const CERT_TTL_SECS: u64 = 24 * 60 * 60;

/// Bound per-mailbox queue length so an unauthenticated poster cannot grow the
/// store without limit (`/v1/mailbox/{id}` is intentionally open so any sender
/// can deliver). This caps disk/memory blast radius to one mailbox; real abuse
/// resistance (auth, rate limits, TTL sweep) is tracked separately.
const MAX_MAILBOX_MESSAGES: usize = 4096;

/// Hard cap on JSON request bodies accepted by the relay. Registration has the
/// largest legitimate body today because it uploads X25519 + ML-KEM prekey pools;
/// 1 MiB leaves room for current protocol overhead while preventing a malicious
/// peer from forcing unbounded JSON buffering before handlers run.
const MAX_RELAY_REQUEST_BODY_BYTES: usize = 1024 * 1024;

/// Default TTL for a queued envelope. Messages that are never fetched/acked are
/// automatically purged so a forgotten mailbox cannot grow without bound.
const DEFAULT_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;

/// How often the server sweeps expired envelopes.
const MAINTENANCE_INTERVAL_SECONDS: u64 = 60;

/// Snapshot debounce (red-team H1): mutations only set a `dirty` flag; this task is
/// the SOLE snapshot writer and coalesces bursts, so no request ever triggers a
/// full-state rewrite (the old per-request snapshot was O(N²) amplification). Bounds
/// crash data-loss to ~this many seconds.
const SNAPSHOT_INTERVAL_SECONDS: u64 = 5;

/// Global admission caps (red-team H2) so an unauthenticated attacker cannot exhaust
/// relay state. NOTE: per-IP limits are intentionally NOT used — the relay sits
/// behind a Cloudflare tunnel, so the socket peer is always localhost; global caps +
/// a global registration rate limit are the controls that actually bind here.
const MAX_DIRECTORY_ENTRIES: usize = 100_000;
const MAX_MAILBOXES: usize = 200_000;
/// Cap a directory entry's one-time prekey pools so `replenish` can't grow unbounded.
const MAX_PREKEY_POOL: usize = 200;

struct DirEntry {
    identity: IdentityPublic,
    signed_prekey: SignedPreKeyPublic,
    /// One-time ML-KEM prekeys (consumed per handshake), with a reusable fallback.
    kem_one_time: VecDeque<KemPreKeyPublic>,
    last_resort_kem: KemPreKeyPublic,
    one_time: VecDeque<OneTimePreKeyPublic>,
}

/// Internal envelope record, including server-side metadata (arrival time,
/// expiry) that is never exposed to clients.
#[derive(Clone, Serialize, Deserialize)]
struct QueuedEnvelope {
    id: u64,
    #[serde(default)]
    arrived_at: u64,
    #[serde(default = "default_ttl")]
    expires_at: u64,
    envelope: SealedEnvelope,
}

fn default_ttl() -> u64 {
    now() + DEFAULT_TTL_SECONDS
}

/// Token-bucket rate limiter. Buckets are created lazily and evicted on a
/// simple size cap to prevent memory exhaustion.
#[derive(Default, Serialize, Deserialize)]
struct RateLimiter {
    buckets: HashMap<RateKey, Bucket>,
}

#[derive(Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
enum RateKey {
    /// Per-mailbox posting rate limit.
    MailboxId(String),
    /// Per-username directory-read limit so a one-time prekey pool can't be drained
    /// for free by anonymous GETs (red-team M1).
    Directory(String),
    /// Single global bucket bounding the rate of NEW account registrations (H2).
    Registrations,
}

#[derive(Serialize, Deserialize)]
struct Bucket {
    tokens: f64,
    last_update: u64,
}

impl RateLimiter {
    fn check(&mut self, key: RateKey, rate: f64, burst: f64, now: u64) -> bool {
        let bucket = self.buckets.entry(key).or_insert(Bucket {
            tokens: burst,
            last_update: now,
        });
        let elapsed = now.saturating_sub(bucket.last_update) as f64;
        bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
        bucket.last_update = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct Inner {
    directory: HashMap<String, DirEntry>,
    mailboxes: HashMap<String, Vec<QueuedEnvelope>>,
    next_id: u64,
    server_seed: [u8; 32],
    server_vk: [u8; 32],
    rate_limiter: RateLimiter,
    snapshot_path: Option<PathBuf>,
    ttl_seconds: u64,
    /// Set by any state mutation; the snapshot task is the sole writer + clearer.
    dirty: bool,
}

#[derive(Clone)]
pub struct AppState(Arc<Mutex<Inner>>);

fn state_from_seed(seed: [u8; 32], snapshot_path: Option<PathBuf>, ttl_seconds: u64) -> AppState {
    let signing = SigningKey::from_bytes(&seed);
    AppState(Arc::new(Mutex::new(Inner {
        directory: HashMap::new(),
        mailboxes: HashMap::new(),
        next_id: 0,
        server_seed: signing.to_bytes(),
        server_vk: signing.verifying_key().to_bytes(),
        rate_limiter: RateLimiter::default(),
        snapshot_path,
        ttl_seconds,
        dirty: false,
    })))
}

/// In-memory state with an ephemeral signing key (used by tests).
pub fn new_state() -> AppState {
    state_from_seed(
        SigningKey::generate(&mut rand::rngs::OsRng).to_bytes(),
        None,
        DEFAULT_TTL_SECONDS,
    )
}

/// Persist the sealed-sender signing key at `path` so a relay restart keeps the
/// same `server_vk` that clients have pinned (F-13).
///
/// A key is generated and written **only** when the file is genuinely absent. A
/// present-but-invalid file (wrong length, unreadable) is a fatal startup error
/// rather than being silently overwritten — silently rotating the signing key
/// would invalidate every sender certificate clients have pinned and destroy the
/// (possibly recoverable) original key. Generated keys are written `0600`.
pub fn new_state_at(key_path: &str, data_dir: &str) -> std::io::Result<AppState> {
    let seed: [u8; 32] = match std::fs::read(key_path) {
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
        Ok(b) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "server key file {key_path} is present but {} bytes (expected 32) — refusing to \
                     overwrite and rotate the signing key; move it aside to rotate intentionally",
                    b.len()
                ),
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let s = SigningKey::generate(&mut rand::rngs::OsRng).to_bytes();
            write_key_file(key_path, &s)?;
            s
        }
        Err(e) => return Err(e),
    };
    std::fs::create_dir_all(data_dir)?;
    let snapshot = Path::new(data_dir).join("snapshot.json");
    let state = state_from_seed(seed, Some(snapshot.clone()), DEFAULT_TTL_SECONDS);
    if snapshot.exists() {
        if let Err(e) = state.load_snapshot() {
            // A corrupt snapshot must not take the whole relay down (red-team L6).
            // Move it aside for forensics and start with empty state rather than refuse
            // to boot (availability over silently losing the file).
            let aside = snapshot.with_extension("corrupt");
            let _ = std::fs::rename(&snapshot, &aside);
            eprintln!(
                "WARN: snapshot load failed ({e}); moved to {} and started fresh",
                aside.display()
            );
        }
    }
    Ok(state)
}

/// Write a freshly generated signing key, restricting it to owner-only (`0600`)
/// on Unix. The seed can mint sender certificates, so it must not be world-readable.
fn write_key_file(path: &str, seed: &[u8; 32]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(seed)?;
        f.flush()
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, seed)
    }
}

impl AppState {
    fn sweep_expired(&self) {
        let mut inner = self.0.lock().unwrap();
        let now = now();
        for queue in inner.mailboxes.values_mut() {
            queue.retain(|e| e.expires_at > now);
        }
        inner.mailboxes.retain(|_, q| !q.is_empty());
        // Also prune stale rate-limit buckets so a long-lived process does not
        // grow memory unbounded.
        inner
            .rate_limiter
            .buckets
            .retain(|_, b| now.saturating_sub(b.last_update) < 3600);
        // Expirations mutated state — let the snapshot task persist it (no sync write).
        inner.dirty = true;
    }

    /// The SOLE snapshot writer (red-team H1): writes only when `dirty`, so a burst of
    /// requests collapses to at most one full-state write per snapshot interval instead
    /// of one O(N) clone+write per request. fsyncs the data before the atomic rename
    /// (red-team L6).
    fn snapshot_if_dirty(&self) -> std::io::Result<()> {
        let (snap, path) = {
            let mut inner = self.0.lock().unwrap();
            let Some(path) = inner.snapshot_path.clone() else {
                inner.dirty = false;
                return Ok(());
            };
            if !inner.dirty {
                return Ok(());
            }
            let snap = SerializableState {
                next_id: inner.next_id,
                directory: inner
                    .directory
                    .iter()
                    .map(|(k, v)| (k.clone(), SerializableDirEntry::from(v)))
                    .collect(),
                mailboxes: inner.mailboxes.clone(),
            };
            inner.dirty = false; // a mutation racing after this re-sets dirty → next tick
            (snap, path)
        };
        let write = || -> std::io::Result<()> {
            use std::io::Write;
            let bytes = serde_json::to_vec_pretty(&snap).map_err(std::io::Error::other)?;
            let tmp = path.with_extension("tmp");
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &path)?;
            if let Some(dir) = path.parent() {
                if let Ok(d) = std::fs::File::open(dir) {
                    let _ = d.sync_all();
                }
            }
            Ok(())
        };
        if let Err(e) = write() {
            // Re-arm so the next tick retries rather than silently dropping the write.
            self.0.lock().unwrap().dirty = true;
            return Err(e);
        }
        Ok(())
    }

    fn load_snapshot(&self) -> Result<(), Box<dyn std::error::Error>> {
        let inner = self.0.lock().unwrap();
        let path = inner.snapshot_path.as_ref().ok_or("no snapshot path")?;
        let bytes = std::fs::read(path)?;
        drop(inner);
        let snap: SerializableState = serde_json::from_slice(&bytes)?;
        let mut inner = self.0.lock().unwrap();
        inner.next_id = snap.next_id;
        inner.directory = snap
            .directory
            .into_iter()
            .map(|(k, v)| (k, v.into()))
            .collect();
        inner.mailboxes = snap.mailboxes;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct SerializableDirEntry {
    identity: IdentityPublic,
    signed_prekey: SignedPreKeyPublic,
    kem_one_time: Vec<KemPreKeyPublic>,
    last_resort_kem: KemPreKeyPublic,
    one_time: Vec<OneTimePreKeyPublic>,
}

impl From<&DirEntry> for SerializableDirEntry {
    fn from(e: &DirEntry) -> Self {
        Self {
            identity: e.identity,
            signed_prekey: e.signed_prekey.clone(),
            kem_one_time: e.kem_one_time.iter().cloned().collect(),
            last_resort_kem: e.last_resort_kem.clone(),
            one_time: e.one_time.iter().cloned().collect(),
        }
    }
}

impl From<SerializableDirEntry> for DirEntry {
    fn from(e: SerializableDirEntry) -> Self {
        Self {
            identity: e.identity,
            signed_prekey: e.signed_prekey,
            kem_one_time: e.kem_one_time.into_iter().collect(),
            last_resort_kem: e.last_resort_kem,
            one_time: e.one_time.into_iter().collect(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SerializableState {
    next_id: u64,
    directory: HashMap<String, SerializableDirEntry>,
    mailboxes: HashMap<String, Vec<QueuedEnvelope>>,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/register", post(register))
        .route("/v1/directory/{username}", get(directory))
        .route("/v1/cert", post(cert))
        .route("/v1/server-key", get(server_key))
        .route("/v1/mailbox/{id}", post(post_mailbox))
        .route("/v1/fetch", post(fetch))
        .route("/v1/ack", post(ack))
        .route("/v1/replenish", post(replenish))
        .layer(DefaultBodyLimit::max(MAX_RELAY_REQUEST_BODY_BYTES))
        .with_state(state)
}

fn now() -> u64 {
    // Saturate to 0 if the clock is before the epoch rather than panicking — a
    // panic here (also reached across the iOS FFI) would be app-hostile.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

type ApiError = (StatusCode, String);

async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<StatusCode, ApiError> {
    if let Err(reason) = validate_username(&req.username) {
        return Err((StatusCode::BAD_REQUEST, reason.into()));
    }
    let msg = registration_signed_bytes(&req.username, &req.identity);
    verify(&req.identity, &msg, &req.registration_sig).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "bad registration signature".into(),
        )
    })?;

    let mut inner = state.0.lock().unwrap();
    let is_new = !inner.directory.contains_key(&req.username);
    if let Some(existing) = inner.directory.get(&req.username) {
        if existing.identity != req.identity {
            return Err((StatusCode::CONFLICT, "username taken".into()));
        }
    }
    if is_new {
        // Bound NEW-account creation rate + total directory size (red-team H2).
        // Re-registration of an existing username (idempotent prekey refresh) is exempt.
        let now = now();
        if !inner
            .rate_limiter
            .check(RateKey::Registrations, 5.0, 50.0, now)
        {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "registration rate limit".into(),
            ));
        }
        if inner.directory.len() >= MAX_DIRECTORY_ENTRIES {
            return Err((StatusCode::SERVICE_UNAVAILABLE, "relay at capacity".into()));
        }
    }
    inner.directory.insert(
        req.username.clone(),
        DirEntry {
            identity: req.identity,
            signed_prekey: req.signed_prekey,
            kem_one_time: req.kem_prekeys.into_iter().collect(),
            last_resort_kem: req.last_resort_kem_prekey,
            one_time: req.one_time_prekeys.into_iter().collect(),
        },
    );
    inner.dirty = true;
    Ok(StatusCode::OK)
}

async fn directory(
    State(state): State<AppState>,
    AxumPath(username): AxumPath<String>,
) -> Result<Json<DirectoryResponse>, ApiError> {
    let mut inner = state.0.lock().unwrap();
    // Throttle reads per username so a one-time prekey pool can't be drained for free
    // by anonymous GETs (red-team M1).
    let now = now();
    if !inner
        .rate_limiter
        .check(RateKey::Directory(username.clone()), 1.0, 10.0, now)
    {
        return Err((StatusCode::TOO_MANY_REQUESTS, "directory rate limit".into()));
    }
    let entry = inner
        .directory
        .get_mut(&username)
        .ok_or((StatusCode::NOT_FOUND, "unknown user".into()))?;
    let one_time_prekey = entry.one_time.pop_front();
    // Consume a one-time ML-KEM prekey if available, else fall back to last-resort (F-05).
    let kem_one_time = entry.kem_one_time.pop_front();
    let consumed = one_time_prekey.is_some() || kem_one_time.is_some();
    let kem_prekey = kem_one_time.unwrap_or_else(|| entry.last_resort_kem.clone());
    let bundle = PreKeyBundle {
        username: username.clone(),
        identity: entry.identity,
        signed_prekey: entry.signed_prekey.clone(),
        one_time_prekey,
        kem_prekey,
    };
    if consumed {
        inner.dirty = true; // only persist when a prekey was actually popped
    }
    Ok(Json(DirectoryResponse { bundle }))
}

async fn cert(
    State(state): State<AppState>,
    Json(req): Json<CertRequest>,
) -> Result<Json<CertResponse>, ApiError> {
    let msg = cert_signed_bytes(&req.username, &req.identity);
    verify(&req.identity, &msg, &req.sig).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "bad cert request signature".into(),
        )
    })?;

    let inner = state.0.lock().unwrap();
    match inner.directory.get(&req.username) {
        Some(e) if e.identity == req.identity => {}
        _ => return Err((StatusCode::FORBIDDEN, "identity not registered".into())),
    }
    let certificate = issue_certificate(
        &inner.server_seed,
        &req.username,
        &req.identity,
        now() + CERT_TTL_SECS,
    );
    Ok(Json(CertResponse { certificate }))
}

async fn server_key(State(state): State<AppState>) -> Json<ServerKeyResponse> {
    let inner = state.0.lock().unwrap();
    Json(ServerKeyResponse {
        verifying_key: inner.server_vk,
    })
}

async fn post_mailbox(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Json(req): Json<PostEnvelope>,
) -> StatusCode {
    // H1 fix: hold ONE lock across the rate-limit check AND the push, so concurrent
    // bursts can't slip past the token bucket between two separate lock acquisitions.
    {
        let mut inner = state.0.lock().unwrap();
        let now = now();
        if !inner
            .rate_limiter
            .check(RateKey::MailboxId(id.clone()), 20.0, 100.0, now)
        {
            return StatusCode::TOO_MANY_REQUESTS;
        }
        // Cap the total number of mailboxes so an attacker can't create unbounded
        // mailboxes (red-team H2); per-mailbox length is capped separately below.
        if !inner.mailboxes.contains_key(&id) && inner.mailboxes.len() >= MAX_MAILBOXES {
            return StatusCode::INSUFFICIENT_STORAGE;
        }
        let ttl = inner.ttl_seconds;
        let msg_id = inner.next_id;
        let queue = inner.mailboxes.entry(id).or_default();
        if queue.len() >= MAX_MAILBOX_MESSAGES {
            // Mailbox full: refuse rather than grow without bound. The owner drains
            // it via fetch + ACK.
            return StatusCode::INSUFFICIENT_STORAGE;
        }
        queue.push(QueuedEnvelope {
            id: msg_id,
            arrived_at: now,
            expires_at: now + ttl,
            envelope: req.envelope,
        });
        inner.next_id += 1;
        inner.dirty = true;
    }
    StatusCode::OK
}

/// Authenticated read (F-04): the caller proves control of the identity key, and
/// the server derives the mailbox from it — so only the owner can read. Does NOT
/// delete (F-07); the client deletes via /v1/ack after durably processing.
async fn fetch(
    State(state): State<AppState>,
    Json(req): Json<FetchRequest>,
) -> Result<Json<FetchResponse>, ApiError> {
    verify(&req.identity, &fetch_signed_bytes(&req.identity), &req.sig)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "bad fetch signature".into()))?;
    let mb = mailbox_id(&req.identity);
    let inner = state.0.lock().unwrap();
    let envelopes: Vec<StoredEnvelope> = inner
        .mailboxes
        .get(&mb)
        .map(|q| {
            q.iter()
                .map(|e| StoredEnvelope {
                    id: e.id,
                    envelope: e.envelope.clone(),
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Json(FetchResponse { envelopes }))
}

/// Authenticated delete of specific envelope ids (F-07), only after the client
/// has durably processed them.
async fn ack(
    State(state): State<AppState>,
    Json(req): Json<AckRequest>,
) -> Result<StatusCode, ApiError> {
    verify(
        &req.identity,
        &ack_signed_bytes(&req.identity, &req.ids),
        &req.sig,
    )
    .map_err(|_| (StatusCode::UNAUTHORIZED, "bad ack signature".into()))?;
    let mb = mailbox_id(&req.identity);
    let mut inner = state.0.lock().unwrap();
    if let Some(q) = inner.mailboxes.get_mut(&mb) {
        let before = q.len();
        q.retain(|e| !req.ids.contains(&e.id));
        if q.len() != before {
            inner.dirty = true;
        }
    }
    Ok(StatusCode::OK)
}

/// POST /v1/replenish: add fresh one-time prekeys to an existing directory entry.
async fn replenish(
    State(state): State<AppState>,
    Json(req): Json<ReplenishRequest>,
) -> Result<StatusCode, ApiError> {
    let msg = replenish_signed_bytes(&req.username, &req.identity);
    verify(&req.identity, &msg, &req.sig)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "bad replenish signature".into()))?;

    let mut inner = state.0.lock().unwrap();
    let entry = inner
        .directory
        .get_mut(&req.username)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "identity not registered".into()))?;
    if entry.identity != req.identity {
        return Err((StatusCode::FORBIDDEN, "identity mismatch".into()));
    }
    entry.one_time.extend(req.one_time_prekeys);
    entry.kem_one_time.extend(req.kem_prekeys);
    // Cap the pools so replenish can't grow a directory entry without bound (H2):
    // keep the most recently published prekeys.
    while entry.one_time.len() > MAX_PREKEY_POOL {
        entry.one_time.pop_front();
    }
    while entry.kem_one_time.len() > MAX_PREKEY_POOL {
        entry.kem_one_time.pop_front();
    }
    inner.dirty = true;
    Ok(StatusCode::OK)
}

/// Run the relay on `addr` until the process exits, persisting the signing key
/// at `key_path` and server state under `data_dir`.
pub async fn run(
    addr: std::net::SocketAddr,
    key_path: &str,
    data_dir: &str,
) -> std::io::Result<()> {
    let state = new_state_at(key_path, data_dir)?;
    let maintenance_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(MAINTENANCE_INTERVAL_SECONDS));
        loop {
            interval.tick().await;
            maintenance_state.sweep_expired();
        }
    });
    // Sole snapshot writer (red-team H1): coalesces dirty state to one write per
    // interval, off the request path and off the async reactor via spawn_blocking.
    let snapshot_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(SNAPSHOT_INTERVAL_SECONDS));
        loop {
            interval.tick().await;
            let s = snapshot_state.clone();
            let _ = tokio::task::spawn_blocking(move || s.snapshot_if_dirty()).await;
        }
    });
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, build_router(state)).await
}
