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
    /// Passphrase to encrypt/decrypt the store at rest (Argon2id). May also be set
    /// via the LOGOS_PASSWORD env var. If omitted, the store is written in PLAINTEXT.
    #[arg(long, global = true)]
    password: Option<String>,
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    /// Resolve the store passphrase from `--password` or `$LOGOS_PASSWORD`. Warns
    /// once when neither is set (the store is then unencrypted on disk).
    fn store_password(&self) -> Option<String> {
        let pw = self
            .password
            .clone()
            .or_else(|| std::env::var("LOGOS_PASSWORD").ok())
            .filter(|s| !s.is_empty());
        if pw.is_none() {
            eprintln!("⚠️  No --password / LOGOS_PASSWORD set — the store is UNENCRYPTED at rest.");
        }
        pw
    }
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
    /// Print this identity's 24-word recovery phrase (back this up).
    Phrase,
    /// Restore an identity from its recovery phrase and re-register it.
    Restore {
        username: String,
        phrase: Vec<String>,
    },
    /// Create an E2EE group and invite members (usernames).
    GroupCreate { name: String, members: Vec<String> },
    /// Send an end-to-end-encrypted message to a group (by hex id).
    GroupSend { group: String, message: Vec<String> },
    /// List the groups this client belongs to.
    Groups,
    /// Add a member to a group (admin only).
    GroupAdd { group: String, username: String },
    /// Remove a member from a group (admin only); triggers rekey-on-removal.
    GroupRemove { group: String, username: String },
    /// Rename a group (admin only).
    GroupRename { group: String, name: String },
}

fn main() -> anyhow::Result<()> {
    eprintln!("⚠️  Logos is EXPERIMENTAL and UNAUDITED — do not use for real secrets.");
    let cli = Cli::parse();
    let password = cli.store_password();
    match cli.command {
        Command::Register { username } => {
            let client = Client::create(&cli.store, &cli.server, &username, password.as_deref())?;
            println!("registered '{}' (store: {})", client.username(), cli.store);
        }
        Command::Send { to, message } => {
            let mut client = Client::load(&cli.store, &cli.server, password.as_deref())?;
            client.send(&to, &message.join(" "))?;
            println!("sent to {to}");
        }
        Command::Recv => {
            let mut client = Client::load(&cli.store, &cli.server, password.as_deref())?;
            let msgs = client.recv()?;
            if msgs.is_empty() {
                println!("(no new messages)");
            }
            for m in msgs {
                match &m.group {
                    Some(gid) => {
                        let short = &gid[..gid.len().min(8)];
                        println!("[group {short}] {}: {}", m.from, m.text);
                    }
                    None => println!("{}: {}", m.from, m.text),
                }
            }
        }
        Command::Whoami => {
            let client = Client::load(&cli.store, &cli.server, password.as_deref())?;
            println!("{}", client.username());
        }
        Command::Phrase => {
            let client = Client::load(&cli.store, &cli.server, password.as_deref())?;
            println!("{}", client.export_recovery_phrase()?);
        }
        Command::Restore { username, phrase } => {
            let client = Client::restore(
                &cli.store,
                &cli.server,
                &username,
                &phrase.join(" "),
                password.as_deref(),
            )?;
            println!("restored '{}' (store: {})", client.username(), cli.store);
        }
        Command::GroupCreate { name, members } => {
            let mut client = Client::load(&cli.store, &cli.server, password.as_deref())?;
            let refs: Vec<&str> = members.iter().map(String::as_str).collect();
            let id = client.create_group(&name, &refs)?;
            println!(
                "created group '{name}' ({id}) — invited {} member(s)",
                members.len()
            );
        }
        Command::GroupSend { group, message } => {
            let mut client = Client::load(&cli.store, &cli.server, password.as_deref())?;
            client.send_group(&group, &message.join(" "))?;
            println!("sent to group {group}");
        }
        Command::Groups => {
            let client = Client::load(&cli.store, &cli.server, password.as_deref())?;
            let groups = client.groups();
            if groups.is_empty() {
                println!("(no groups)");
            }
            for g in groups {
                println!("{}  {}  [{}]", g.id, g.name, g.members.join(", "));
            }
        }
        Command::GroupAdd { group, username } => {
            let mut client = Client::load(&cli.store, &cli.server, password.as_deref())?;
            client.add_member(&group, &username)?;
            println!("added {username} to group {group}");
        }
        Command::GroupRemove { group, username } => {
            let mut client = Client::load(&cli.store, &cli.server, password.as_deref())?;
            client.remove_member(&group, &username)?;
            println!("removed {username} from group {group} (rekeyed)");
        }
        Command::GroupRename { group, name } => {
            let mut client = Client::load(&cli.store, &cli.server, password.as_deref())?;
            client.rename_group(&group, &name)?;
            println!("renamed group {group} to '{name}'");
        }
    }
    Ok(())
}
