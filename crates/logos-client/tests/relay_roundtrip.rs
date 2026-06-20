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

    let mut alice = Client::create(tmp("alice"), &url, "alice").unwrap();
    let mut bob = Client::create(tmp("bob"), &url, "bob").unwrap();

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
    let mut bob2 = Client::load(tmp("bob"), &url).unwrap();
    alice.send("bob", "after reload").unwrap();
    let got = bob2.recv().unwrap();
    assert_eq!(got[0].text, "after reload");
}
