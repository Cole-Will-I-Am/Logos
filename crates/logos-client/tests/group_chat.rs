//! End-to-end: three clients form an E2EE sender-key group through a live relay and
//! exchange group messages. Exercises group creation, the invite + sender-key
//! distribution bootstrap (including the canonical-initiator rule for member pairs
//! and the out-of-order pending-key buffer), per-member fan-out, and sender-key
//! decryption + per-message signature verification.

use logos_client::Client;
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
    let addr = rx.recv().unwrap();
    format!("http://{addr}")
}

fn tmp(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("logos-grp-{}-{}", std::process::id(), name))
}

/// Run `recv` on every client a few times so the multi-round bootstrap (invites →
/// sender-key distribution → replies) fully settles. Order-independent.
fn settle(clients: &mut [&mut Client], rounds: usize) {
    for _ in 0..rounds {
        for c in clients.iter_mut() {
            let _ = c.recv().unwrap();
        }
    }
}

#[test]
fn three_party_group_exchange() {
    let url = start_relay();
    let mut alice = Client::create(tmp("alice"), &url, "alice_grp", Some("pw")).unwrap();
    let mut bob = Client::create(tmp("bob"), &url, "bob_grp", Some("pw")).unwrap();
    let mut carol = Client::create(tmp("carol"), &url, "carol_grp", Some("pw")).unwrap();

    // Alice creates a group and invites bob + carol.
    let gid = alice
        .create_group("team", &["bob_grp", "carol_grp"])
        .unwrap();
    assert_eq!(gid.len(), 32, "group id is 16 bytes hex-encoded");

    // Bootstrap settles over a few recv rounds (no fixed ordering required).
    settle(&mut [&mut alice, &mut bob, &mut carol], 3);

    // All three now know the group with the same 3-member roster.
    for (who, c) in [("alice", &alice), ("bob", &bob), ("carol", &carol)] {
        let mut members = c
            .group_members(&gid)
            .unwrap_or_else(|| panic!("{who} should know the group"));
        members.sort();
        assert_eq!(
            members,
            vec![
                "alice_grp".to_string(),
                "bob_grp".to_string(),
                "carol_grp".to_string()
            ],
            "{who} should see the full roster"
        );
    }

    // Alice sends to the group; bob and carol both decrypt it.
    alice.send_group(&gid, "hello team").unwrap();
    let bob_msgs = bob.recv().unwrap();
    let carol_msgs = carol.recv().unwrap();
    assert!(
        bob_msgs.iter().any(|m| m.from == "alice_grp"
            && m.text == "hello team"
            && m.group.as_deref() == Some(gid.as_str())),
        "bob should receive alice's group message, got {:?}",
        bob_msgs
            .iter()
            .map(|m| (&m.from, &m.text))
            .collect::<Vec<_>>()
    );
    assert!(
        carol_msgs
            .iter()
            .any(|m| m.from == "alice_grp" && m.text == "hello team"),
        "carol should receive alice's group message"
    );

    // Bob replies; alice and carol both decrypt it (exercises a different sender key).
    bob.send_group(&gid, "hi from bob").unwrap();
    let alice_msgs = alice.recv().unwrap();
    let carol_msgs2 = carol.recv().unwrap();
    assert!(
        alice_msgs
            .iter()
            .any(|m| m.from == "bob_grp" && m.text == "hi from bob"),
        "alice should receive bob's reply, got {:?}",
        alice_msgs
            .iter()
            .map(|m| (&m.from, &m.text))
            .collect::<Vec<_>>()
    );
    assert!(
        carol_msgs2
            .iter()
            .any(|m| m.from == "bob_grp" && m.text == "hi from bob"),
        "carol should receive bob's reply"
    );

    // A second message from alice advances her sender chain; still decrypts in order.
    alice.send_group(&gid, "second").unwrap();
    let bob_msgs2 = bob.recv().unwrap();
    assert!(
        bob_msgs2
            .iter()
            .any(|m| m.from == "alice_grp" && m.text == "second"),
        "bob should receive alice's second message"
    );

    // Persistence: reload carol from disk and keep decrypting on the same group.
    let mut carol2 = Client::load(tmp("carol"), &url, Some("pw")).unwrap();
    bob.send_group(&gid, "after reload").unwrap();
    let cm = carol2.recv().unwrap();
    assert!(
        cm.iter()
            .any(|m| m.from == "bob_grp" && m.text == "after reload"),
        "reloaded carol should keep receiving group messages"
    );
}

#[test]
fn non_member_cannot_decrypt_group_message() {
    let url = start_relay();
    let mut alice = Client::create(tmp("m-alice"), &url, "alice_x", Some("pw")).unwrap();
    let mut bob = Client::create(tmp("m-bob"), &url, "bob_x", Some("pw")).unwrap();
    let mut mallory = Client::create(tmp("m-mal"), &url, "mallory_x", Some("pw")).unwrap();

    // A two-person group that excludes mallory.
    let gid = alice.create_group("private", &["bob_x"]).unwrap();
    settle(&mut [&mut alice, &mut bob], 2);

    alice.send_group(&gid, "secret").unwrap();
    // Bob (a member) reads it.
    let bm = bob.recv().unwrap();
    assert!(bm.iter().any(|m| m.text == "secret"));
    // Mallory was never sent anything for this group and isn't a member; her mailbox
    // is empty (per-member fan-out only targets members) and she learns nothing.
    let mm = mallory.recv().unwrap();
    assert!(mm.is_empty(), "non-member must not receive group traffic");
    assert!(
        mallory.group_members(&gid).is_none(),
        "non-member must not know the group"
    );
}

#[test]
fn admin_can_add_a_member() {
    let url = start_relay();
    let mut alice = Client::create(tmp("add-alice"), &url, "alice_add", Some("pw")).unwrap();
    let mut bob = Client::create(tmp("add-bob"), &url, "bob_add", Some("pw")).unwrap();
    let mut carol = Client::create(tmp("add-carol"), &url, "carol_add", Some("pw")).unwrap();

    let gid = alice.create_group("team", &["bob_add"]).unwrap();
    settle(&mut [&mut alice, &mut bob], 2);

    // Admin adds carol; bootstrap of the new member settles over a few rounds.
    alice.add_member(&gid, "carol_add").unwrap();
    settle(&mut [&mut alice, &mut bob, &mut carol], 3);

    for (who, c) in [("alice", &alice), ("bob", &bob), ("carol", &carol)] {
        let mut m = c
            .group_members(&gid)
            .unwrap_or_else(|| panic!("{who} should know the group"));
        m.sort();
        assert_eq!(
            m,
            vec![
                "alice_add".to_string(),
                "bob_add".to_string(),
                "carol_add".to_string()
            ],
            "{who} should see carol in the roster"
        );
    }

    // The new member can send (original members receive) and receive.
    carol.send_group(&gid, "carol here").unwrap();
    let am = alice.recv().unwrap();
    let bm = bob.recv().unwrap();
    assert!(
        am.iter()
            .any(|m| m.from == "carol_add" && m.text == "carol here"),
        "alice should receive the new member's message"
    );
    assert!(
        bm.iter()
            .any(|m| m.from == "carol_add" && m.text == "carol here"),
        "bob should receive the new member's message"
    );
    alice.send_group(&gid, "welcome carol").unwrap();
    let cm = carol.recv().unwrap();
    assert!(
        cm.iter()
            .any(|m| m.from == "alice_add" && m.text == "welcome carol"),
        "the new member should receive group messages"
    );
}

#[test]
fn admin_removes_member_and_rekeys() {
    let url = start_relay();
    let mut alice = Client::create(tmp("rm-alice"), &url, "alice_rm", Some("pw")).unwrap();
    let mut bob = Client::create(tmp("rm-bob"), &url, "bob_rm", Some("pw")).unwrap();
    let mut carol = Client::create(tmp("rm-carol"), &url, "carol_rm", Some("pw")).unwrap();

    let gid = alice.create_group("team", &["bob_rm", "carol_rm"]).unwrap();
    settle(&mut [&mut alice, &mut bob, &mut carol], 3);

    // While still a member, carol receives.
    alice.send_group(&gid, "before removal").unwrap();
    let cm = carol.recv().unwrap();
    assert!(
        cm.iter().any(|m| m.text == "before removal"),
        "carol should receive messages while a member"
    );
    let _ = bob.recv().unwrap();

    // Admin removes carol; rekey-on-removal propagates over a few rounds.
    alice.remove_member(&gid, "carol_rm").unwrap();
    settle(&mut [&mut alice, &mut bob], 3);

    let mut am = alice.group_members(&gid).unwrap();
    am.sort();
    assert_eq!(
        am,
        vec!["alice_rm".to_string(), "bob_rm".to_string()],
        "carol should be gone from the roster"
    );

    // A post-removal message reaches the remaining member but NOT the removed one:
    // carol is dropped from the fan-out and the rekey means her old chain is useless.
    alice.send_group(&gid, "after removal").unwrap();
    let bm = bob.recv().unwrap();
    assert!(
        bm.iter().any(|m| m.text == "after removal"),
        "remaining member should receive the post-removal message"
    );
    let cm2 = carol.recv().unwrap();
    assert!(
        !cm2.iter().any(|m| m.text == "after removal"),
        "removed member must NOT receive post-removal messages"
    );
}
