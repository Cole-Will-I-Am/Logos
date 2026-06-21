//! Drives the FFI-wrapped `LogosClient` end-to-end against an in-process relay —
//! the part of the iOS surface we can fully verify on Linux (the Swift bindings
//! call exactly these methods).

use logos_ffi::LogosClient;
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

fn tmp(name: &str) -> String {
    std::env::temp_dir()
        .join(format!("logos-ffi-{}-{}", std::process::id(), name))
        .to_string_lossy()
        .into_owned()
}

#[test]
fn ffi_client_round_trip() {
    let url = start_relay();

    let alice = LogosClient::create(
        tmp("alice"),
        url.clone(),
        "alice".into(),
        Some("test-password".into()),
    )
    .unwrap();
    let bob = LogosClient::create(
        tmp("bob"),
        url.clone(),
        "bob".into(),
        Some("test-password".into()),
    )
    .unwrap();
    assert_eq!(alice.username(), "alice");

    alice.send("bob".into(), "hello from ffi".into()).unwrap();
    let got = bob.recv().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].from, "alice");
    assert_eq!(got[0].text, "hello from ffi");

    bob.send("alice".into(), "reply via ffi".into()).unwrap();
    let got = alice.recv().unwrap();
    assert_eq!(got[0].text, "reply via ffi");
}
