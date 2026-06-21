//! End-to-end: two clients exchange E2EE messages through a live relay.
//! Exercises register → PQXDH session setup → Double Ratchet → sealed sender,
//! over real HTTP against an in-process axum relay.

use logos_client::Client;
use std::sync::mpsc;

/// Start the relay on an ephemeral port (own runtime/thread) and return its URL.
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
    let addr = rx.recv().unwrap();
    format!("http://{addr}")
}

fn tmp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("logos-it-{}-{}", std::process::id(), name));
    dir
}

#[test]
fn two_clients_exchange_messages_through_relay() {
    let url = start_relay();

    let mut alice = Client::create(tmp("alice"), &url, "alice", Some("test-password")).unwrap();
    let mut bob = Client::create(tmp("bob"), &url, "bob", Some("test-password")).unwrap();

    // Alice -> Bob (first message establishes the session via PQXDH prekey message).
    alice.send("bob", "hello bob").unwrap();
    let got = bob.recv().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].from, "alice");
    assert_eq!(got[0].text, "hello bob");

    // Bob -> Alice (reply on the established session).
    bob.send("alice", "hi alice").unwrap();
    let got = alice.recv().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].from, "bob");
    assert_eq!(got[0].text, "hi alice");

    // Alice -> Bob again (Normal message, not a prekey message).
    alice.send("bob", "second message").unwrap();
    let got = bob.recv().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].text, "second message");

    // Empty mailbox after delivery (delete-on-deliver).
    assert!(bob.recv().unwrap().is_empty());

    // Persistence: reload Bob from disk and keep decrypting on the same session.
    let mut bob2 = Client::load(tmp("bob"), &url, Some("test-password")).unwrap();
    alice.send("bob", "after reload").unwrap();
    let got = bob2.recv().unwrap();
    assert_eq!(got[0].text, "after reload");
}

#[test]
fn prekey_pool_refills_after_inbound_prekeys_drain_it() {
    // M1: prekeys are minted only at registration; inbound handshakes consume them.
    // Once our local pool crosses the low watermark, recv() must republish fresh
    // prekeys so the relay keeps handing out one-time prekeys (forward secrecy for
    // initial messages) instead of falling back to the reusable last-resort KEM.
    let url = start_relay();
    let mut alice = Client::create(tmp("m1-alice"), &url, "alice_m1", Some("pw")).unwrap();

    // 15 distinct peers each open a session to alice — every directory fetch pops one
    // of her published one-time prekeys — then send a prekey message. recv() then
    // consumes 15 of alice's local one-time prekeys (20 -> 5), tripping replenish.
    for i in 0..15 {
        let name = format!("peer_m1_{i}");
        let mut p = Client::create(tmp(&format!("m1-{name}")), &url, &name, Some("pw")).unwrap();
        p.send("alice_m1", "hi").unwrap();
    }
    let got = alice.recv().unwrap();
    assert_eq!(got.len(), 15, "alice should receive all 15 prekey messages");

    // Deterministic core check: the inbound handshakes consumed 15 one-time X25519
    // prekeys (20 -> 5, tripping the watermark) and 10 one-time ML-KEM prekeys
    // (10 -> 0). recv() must have refilled both pools back to their full counts.
    assert_eq!(
        alice.local_prekey_counts(),
        (20, 10),
        "client should refill its local prekey pools after the watermark trips"
    );

    // End-to-end check: the fresh prekeys must have been *published* to the relay, so
    // the relay can keep handing out one-time prekeys past the 5 that remained
    // pre-replenish. Six fetches all returning Some proves republication (without M1
    // the relay's residual pool of 5 would yield a None by the 6th). The directory is
    // rate-limited (burst 10, 1/s refill), so let the bucket recover before the burst.
    let http = reqwest::blocking::Client::new();
    std::thread::sleep(std::time::Duration::from_secs(8));
    let mut some_count = 0;
    for _ in 0..6 {
        let resp = http
            .get(format!("{url}/v1/directory/alice_m1"))
            .send()
            .unwrap();
        assert!(
            resp.status().is_success(),
            "directory fetch was rate-limited"
        );
        let dir: logos_proto::DirectoryResponse = resp.json().unwrap();
        if dir.bundle.one_time_prekey.is_some() {
            some_count += 1;
        }
    }
    assert_eq!(
        some_count, 6,
        "relay should serve one-time prekeys past the pre-replenish residual (got {some_count}/6)"
    );
}

#[test]
fn other_identity_cannot_read_or_drain_mailbox() {
    let url = start_relay();
    let mut alice = Client::create(tmp("a2"), &url, "alice2", Some("test-password")).unwrap();
    let mut bob = Client::create(tmp("b2"), &url, "bob2", Some("test-password")).unwrap();
    let mut eve = Client::create(tmp("e2"), &url, "eve2", Some("test-password")).unwrap();

    alice.send("bob2", "for bob only").unwrap();

    // F-04: fetch is bound to the caller's identity key — Eve only ever reads her
    // own (empty) mailbox and cannot drain Bob's.
    assert!(eve.recv().unwrap().is_empty());

    // F-07: Bob's message survived (ACK-based deletion) and is delivered to Bob.
    let got = bob.recv().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].text, "for bob only");
}
