//! AUDIT proof-of-concept tests (demonstrate bugs found in security review).
//!
//! These exercise the real client + in-process relay over HTTP and use only
//! public APIs (plus the public `logos-proto` wire types + the plaintext store)
//! to act as a malicious relay / network attacker that re-posts envelopes.
//!
//! Several of these are EXPECTED TO FAIL against the current code — they encode
//! the desired post-fix behavior and prove the vulnerabilities until fixed.

use logos_client::Client;
use logos_identity::{IdentityKeyPair, IdentityPublic};
use logos_proto::{
    ack_signed_bytes, fetch_signed_bytes, mailbox_id, AckRequest, DirectoryResponse, FetchRequest,
    FetchResponse, PostEnvelope, StoredEnvelope,
};
use std::sync::mpsc;

fn start_relay() -> String {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(addr).unwrap();
            axum::serve(
                listener,
                logos_server::build_router(logos_server::new_state()),
            )
            .await
            .unwrap();
        });
    });
    format!("http://{}", rx.recv().unwrap())
}

fn tmp(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("logos-poc-{}-{}", std::process::id(), name))
}

/// Rebuild an identity from a *plaintext* client store (demonstrates the store
/// exposes the long-term secret in the clear, and lets us act as that mailbox's
/// owner to capture envelopes the way a malicious relay can see them).
fn identity_from_store(path: &std::path::Path) -> IdentityKeyPair {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let arr = v["identity_secret"].as_array().unwrap();
    let bytes: Vec<u8> = arr.iter().map(|x| x.as_u64().unwrap() as u8).collect();
    let fixed: [u8; 64] = bytes.try_into().unwrap();
    IdentityKeyPair::from_secret_bytes(&fixed)
}

/// Raw authenticated fetch (does NOT delete) — captures a recipient's mailbox the
/// way the relay sees it.
fn raw_fetch(url: &str, id: &IdentityKeyPair) -> Vec<StoredEnvelope> {
    let http = reqwest::blocking::Client::new();
    let id_pub = id.public();
    let sig = id.sign(&fetch_signed_bytes(&id_pub)).to_vec();
    let resp: FetchResponse = http
        .post(format!("{url}/v1/fetch"))
        .json(&FetchRequest {
            identity: id_pub,
            sig,
        })
        .send()
        .unwrap()
        .json()
        .unwrap();
    resp.envelopes
}

/// Unauthenticated mailbox post (anyone can do this — no auth on /v1/mailbox/:id).
fn raw_post(url: &str, recipient: &IdentityPublic, env: &logos_sealed::SealedEnvelope) {
    let http = reqwest::blocking::Client::new();
    let id = mailbox_id(recipient);
    http.post(format!("{url}/v1/mailbox/{id}"))
        .json(&PostEnvelope {
            envelope: env.clone(),
        })
        .send()
        .unwrap();
}

/// Fetch with a caller-chosen identity, signed by `signer` (signer.ed must equal
/// `identity.ed` for the server's signature check to pass). Lets a test forge a
/// `{attacker_ed, victim_dh}` identity.
fn raw_fetch_as(
    url: &str,
    identity: IdentityPublic,
    signer: &IdentityKeyPair,
) -> Vec<StoredEnvelope> {
    let http = reqwest::blocking::Client::new();
    let sig = signer.sign(&fetch_signed_bytes(&identity)).to_vec();
    let resp: FetchResponse = http
        .post(format!("{url}/v1/fetch"))
        .json(&FetchRequest { identity, sig })
        .send()
        .unwrap()
        .json()
        .unwrap();
    resp.envelopes
}

fn raw_ack_as(url: &str, identity: IdentityPublic, ids: Vec<u64>, signer: &IdentityKeyPair) {
    let http = reqwest::blocking::Client::new();
    let sig = signer.sign(&ack_signed_bytes(&identity, &ids)).to_vec();
    http.post(format!("{url}/v1/ack"))
        .json(&AckRequest { identity, ids, sig })
        .send()
        .unwrap();
}

fn raw_directory(url: &str, who: &str) -> DirectoryResponse {
    reqwest::blocking::Client::new()
        .get(format!("{url}/v1/directory/{who}"))
        .send()
        .unwrap()
        .json()
        .unwrap()
}

/// V3 (characterization of a KNOWN, unfixed limitation): an UNAUTHENTICATED,
/// fetch-only caller drains the one-time prekey pools. This documents current
/// behavior — server-side rate-limiting / prekey replenishment is tracked work.
/// After the V2 fix the worst consequence (session reset via replay) is closed;
/// the residual effect is forcing new sessions onto the reusable last-resort KEM.
#[test]
fn poc_v3_unauthenticated_directory_drains_one_time_prekeys() {
    let url = start_relay();
    let _bob = Client::create(tmp("v3-bob"), &url, "v3bob").unwrap();

    // 20 one-time X25519 + 10 one-time ML-KEM prekeys were registered.
    // Drain them with plain GETs — no auth, no message ever sent.
    let mut last = raw_directory(&url, "v3bob");
    for _ in 0..40 {
        last = raw_directory(&url, "v3bob");
    }
    // After draining: no one-time X25519 prekey, and the KEM prekey has fallen
    // back to the reusable last-resort (id 0).
    assert!(
        last.bundle.one_time_prekey.is_none(),
        "attacker could NOT drain one-time X25519 prekeys"
    );
    assert_eq!(
        last.bundle.kem_prekey.id, 0,
        "attacker could NOT force the reusable last-resort KEM prekey"
    );
}

/// V1: a redelivered, already-consumed Normal message can never be decrypted nor
/// ACKed, so it is stuck on the server forever and bloats every future fetch.
#[test]
fn poc_v1_redelivered_normal_message_is_stuck_forever() {
    let url = start_relay();
    let bob_path = tmp("v1-bob");
    let mut alice = Client::create(tmp("v1-alice"), &url, "v1alice").unwrap();
    let mut bob = Client::create(&bob_path, &url, "v1bob").unwrap();
    let bob_id = identity_from_store(&bob_path);
    let bob_pub = bob_id.public();

    alice.send("v1bob", "hello").unwrap(); // prekey msg
    assert_eq!(bob.recv().unwrap().len(), 1); // establish + consume

    alice.send("v1bob", "second").unwrap(); // Normal msg
    let captured = raw_fetch(&url, &bob_id); // capture before Bob acks
    assert_eq!(captured.len(), 1);
    assert_eq!(bob.recv().unwrap()[0].text, "second"); // consume + ack

    // Malicious relay redelivers the (already-consumed) Normal envelope.
    raw_post(&url, &bob_pub, &captured[0].envelope);

    // Bob can't decrypt it again (chain key advanced), so recv returns nothing...
    assert!(bob.recv().unwrap().is_empty());
    // ...and because an undecryptable envelope is never ACKed, it is STUCK: still
    // present on the server, re-downloaded and re-failed on every future fetch.
    let stuck = raw_fetch(&url, &bob_id);
    assert!(
        stuck.is_empty(),
        "BUG: {} undecryptable envelope(s) stuck in the mailbox forever",
        stuck.len()
    );
}

/// V2: replaying the initial PREKEY envelope resets/clobbers an established
/// session when the handshake used the reusable last-resort KEM prekey (no
/// one-time X25519 prekey). A consumed first message is redelivered as "new",
/// and subsequent real messages then fail — a relay can break any conversation.
#[test]
fn poc_v2_prekey_replay_resets_established_session() {
    let url = start_relay();
    let bob_path = tmp("v2-bob");
    let mut alice = Client::create(tmp("v2-alice"), &url, "v2alice").unwrap();
    let mut bob = Client::create(&bob_path, &url, "v2bob").unwrap();
    let bob_id = identity_from_store(&bob_path);
    let bob_pub = bob_id.public();

    // Drain Bob's one-time prekeys so the session uses last-resort KEM + no OTK.
    for _ in 0..40 {
        raw_directory(&url, "v2bob");
    }

    alice.send("v2bob", "m1").unwrap(); // prekey msg using last-resort path
    let captured = raw_fetch(&url, &bob_id); // capture the prekey envelope
    assert_eq!(captured.len(), 1);
    assert_eq!(bob.recv().unwrap()[0].text, "m1"); // establish + consume + ack

    alice.send("v2bob", "m2").unwrap(); // advance the session
    assert_eq!(bob.recv().unwrap()[0].text, "m2");

    // Replay the original prekey envelope (unauthenticated post).
    raw_post(&url, &bob_pub, &captured[0].envelope);
    let replayed = bob.recv().unwrap();

    // BUG 1: the already-seen first message is redelivered as a brand-new message.
    assert!(
        replayed.is_empty(),
        "BUG: prekey replay redelivered an old message as new: {:?}",
        replayed.iter().map(|m| &m.text).collect::<Vec<_>>()
    );

    // BUG 2: the established session was clobbered, so further real messages on
    // the original session no longer decrypt.
    alice.send("v2bob", "m3").unwrap();
    assert_eq!(
        bob.recv().unwrap().first().map(|m| m.text.as_str()),
        Some("m3"),
        "BUG: session was reset by the replay; subsequent messages are lost"
    );
}

/// V6: a corrupt plaintext store with a wrong-length identity_secret loads fine
/// but PANICS on first use (would crash the iOS app across the FFI boundary).
#[test]
fn poc_v6_corrupt_store_panics_on_use_not_load() {
    let url = start_relay();
    let path = tmp("v6-store");
    let _ = Client::create(&path, &url, "v6user").unwrap();

    // Corrupt identity_secret to the wrong length (simulates disk corruption /
    // tampering) but keep valid JSON.
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    v["identity_secret"] = serde_json::json!([1, 2, 3]); // 3 bytes, not 64
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();

    // A corrupt store must surface a recoverable error (not panic on load or use).
    let loaded =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Client::load(&path, &url)));
    match loaded {
        Ok(Err(_)) => { /* recoverable error — correct */ }
        Ok(Ok(_)) => panic!("corrupt store loaded successfully (should be rejected)"),
        Err(_) => panic!("BUG: corrupt store caused a panic instead of a recoverable error"),
    }
}

/// V8: unsealable garbage posted to a mailbox (sealed-sender posting is open) must
/// be drained (ACK-dropped), not left to accumulate and be re-fetched every poll.
#[test]
fn poc_v8_garbage_envelopes_are_drained_not_stuck() {
    let url = start_relay();
    let bob_path = tmp("v8-bob");
    let mut bob = Client::create(&bob_path, &url, "v8bob").unwrap();
    let bob_pub = identity_from_store(&bob_path).public();
    let bob_id = identity_from_store(&bob_path);

    // An attacker floods Bob's mailbox with junk it cannot unseal.
    for i in 0..5u8 {
        let junk = logos_sealed::SealedEnvelope {
            ephemeral_pub: [i; 32],
            ciphertext: vec![i; 48],
        };
        raw_post(&url, &bob_pub, &junk);
    }
    assert_eq!(raw_fetch(&url, &bob_id).len(), 5);

    // recv surfaces nothing and drains the garbage.
    assert!(bob.recv().unwrap().is_empty());
    assert!(
        raw_fetch(&url, &bob_id).is_empty(),
        "BUG: undecryptable garbage was not drained and will be re-fetched forever"
    );
}

/// V-CRIT: fetch/ack authenticate the Ed25519 key but the mailbox must be bound to
/// it. An attacker presenting {their own ed, the victim's public dh} (signing with
/// their own ed, so the signature verifies) must NOT be able to read or delete the
/// victim's mailbox.
#[test]
fn poc_vcrit_mailbox_not_readable_or_drainable_with_foreign_ed() {
    let url = start_relay();
    let bob_path = tmp("vc-bob");
    let mut alice = Client::create(tmp("vc-alice"), &url, "vcalice").unwrap();
    let mut bob = Client::create(&bob_path, &url, "vcbob").unwrap();
    let victim = identity_from_store(&bob_path).public();

    alice.send("vcbob", "top secret").unwrap();

    // Attacker forges {attacker_ed, victim_dh} and signs with their own ed.
    let attacker = IdentityKeyPair::generate();
    let forged = IdentityPublic {
        ed: attacker.public().ed,
        dh: victim.dh,
    };

    // Read attempt: must not return the victim's envelopes.
    let stolen = raw_fetch_as(&url, forged, &attacker);
    assert!(
        stolen.is_empty(),
        "BUG: attacker read {} envelope(s) from the victim's mailbox",
        stolen.len()
    );

    // Delete attempt: acking a wide id range must not wipe the victim's mailbox.
    raw_ack_as(&url, forged, (0..16).collect(), &attacker);

    // The victim still receives the message intact.
    let got = bob.recv().unwrap();
    assert_eq!(
        got.first().map(|m| m.text.as_str()),
        Some("top secret"),
        "BUG: attacker drained the victim's mailbox via Ed/DH key confusion"
    );
}
