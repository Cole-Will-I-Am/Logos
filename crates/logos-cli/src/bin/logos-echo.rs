//! Logos echo bot — a test buddy. Polls the relay, and replies to every message
//! with "echo: <your text>" so a client (e.g. the iOS app) can verify a full
//! end-to-end round-trip. Dev/test tool only.
//!
//! Env: LOGOS_SERVER (relay URL), LOGOS_STORE (client store path). The store must
//! already be registered (run `logos --store <path> register echo` once first).
//!
//! EXPERIMENTAL — UNAUDITED.

use logos_client::Client;
use std::{thread, time::Duration};

fn main() -> anyhow::Result<()> {
    let server = std::env::var("LOGOS_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8787".into());
    let store = std::env::var("LOGOS_STORE").unwrap_or_else(|_| "echo-store.json".into());
    let mut client = Client::load(&store, &server, None)?;
    eprintln!("echo bot '{}' polling {}", client.username(), server);

    loop {
        match client.recv() {
            Ok(msgs) => {
                for m in msgs {
                    eprintln!("← {}: {}", m.from, m.text);
                    let reply = format!("echo: {}", m.text);
                    match client.send(&m.from, &reply) {
                        Ok(()) => eprintln!("→ {}: {}", m.from, reply),
                        Err(e) => eprintln!("send to {} failed: {e}", m.from),
                    }
                }
            }
            Err(e) => eprintln!("recv error: {e}"),
        }
        thread::sleep(Duration::from_secs(2));
    }
}
