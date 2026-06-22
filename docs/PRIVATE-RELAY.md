# Private Relay (advanced)

Logos defaults to the public relay (`relay.manticthink.com`). **Private Relay** lets
you point the app at a relay *you* control instead — for example a `logos-server`
running on your own [Tailscale](https://tailscale.com) network. Set it in
**Settings → Network → Private relay**.

This is an advanced/private-network mode, not a different messaging architecture.

## What it is (and isn't)

- **Still a relay, not peer-to-peer.** Messages are store-and-forwarded by the relay
  you choose, so offline delivery still works and the app needs no inbound listener
  (which iOS wouldn't allow in the background anyway).
- **Not "internet-free."** Over Tailscale the traffic is WireGuard-encrypted, but it
  can still traverse the public internet via Tailscale's DERP relays when a direct
  path isn't available. DERP forwards encrypted packets it can't read — but the path
  is not literally off the internet.
- **End-to-end encryption is unchanged.** The relay (public or private) only ever
  sees opaque ciphertext; Private Relay is about *which* untrusted relay carries it.

## The single-relay identity model (important)

Your identity, prekeys, and mailbox are registered to **one relay's directory**. So
switching relays is closer to switching *networks* than switching *transport*:

> **Private Relay connects you only to people registered on that same relay.**

Each relay keeps its own identity and chat history on-device (stores are scoped per
relay), so switching is safe and reversible — but you can't be on the public relay
and message someone who's only on a private one. Being reachable on both at once
would require multi-relay support in the client (a future item).

## Running a relay on Tailscale

1. Run `logos-server` on a tailnet node (`LOGOS_ADDR=127.0.0.1:8787`, or bind to the
   tailnet interface).
2. Give it an HTTPS endpoint on its `…ts.net` name so iOS App Transport Security
   accepts it — e.g. `tailscale cert <name>.<tailnet>.ts.net` and terminate TLS in a
   small reverse proxy (caddy/nginx) in front of `127.0.0.1:8787`.
3. On every participating device: install Tailscale, join the same tailnet, then set
   **Settings → Network → Private relay** to `https://<name>.<tailnet>.ts.net`.

**Privacy caveat (Certificate Transparency):** provisioning a public-CA HTTPS cert
for a `ts.net` name publishes that machine/tailnet DNS name to the public CT logs.
For serious-privacy deployments, prefer a name you're comfortable being public, or a
private CA / self-managed TLS that your devices trust.

## Priority / roadmap

1. **At-rest encryption** of the on-device store — ✅ done (stores are encrypted at rest).
2. **Private Relay** (this feature).
3. **Multi-relay presence** (be reachable on public *and* private at once) — later.
4. **True peer-to-peer** — not a core promise (impractical on iOS for the reasons above).
