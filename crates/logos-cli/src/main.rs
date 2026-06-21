//! Logos dev CLI — register an identity and exchange end-to-end-encrypted
//! messages through a relay. For testing the protocol; not a finished product.
//!
//! EXPERIMENTAL — UNAUDITED. Do not use for real secrets.

use clap::{Parser, Subcommand};
use logos_client::Client;

#[derive(Parser)]
#[command(
    name = "logos",
    about = "Logos E2EE messenger CLI (EXPERIMENTAL — UNAUDITED)"
)]
struct Cli {
    /// Relay base URL.
    #[arg(long, default_value = "http://127.0.0.1:8787", global = true)]
    server: String,
    /// Path to the local client store file.
    #[arg(long, default_value = "logos-store.json", global = true)]
    store: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create an identity and register it with the relay.
    Register { username: String },
    /// Send an end-to-end-encrypted message.
    Send { to: String, message: Vec<String> },
    /// Fetch and decrypt pending messages.
    Recv,
    /// Print this client's username.
    Whoami,
}

fn main() -> anyhow::Result<()> {
    eprintln!("⚠️  Logos is EXPERIMENTAL and UNAUDITED — do not use for real secrets.");
    let cli = Cli::parse();
    match cli.command {
        Command::Register { username } => {
            let client = Client::create(&cli.store, &cli.server, &username, Some("test-password"))?;
            println!("registered '{}' (store: {})", client.username(), cli.store);
        }
        Command::Send { to, message } => {
            let mut client = Client::load(&cli.store, &cli.server, Some("test-password"))?;
            client.send(&to, &message.join(" "))?;
            println!("sent to {to}");
        }
        Command::Recv => {
            let mut client = Client::load(&cli.store, &cli.server, Some("test-password"))?;
            let msgs = client.recv()?;
            if msgs.is_empty() {
                println!("(no new messages)");
            }
            for m in msgs {
                println!("{}: {}", m.from, m.text);
            }
        }
        Command::Whoami => {
            let client = Client::load(&cli.store, &cli.server, Some("test-password"))?;
            println!("{}", client.username());
        }
    }
    Ok(())
}
