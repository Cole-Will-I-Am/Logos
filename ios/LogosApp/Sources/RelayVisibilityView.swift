import SwiftUI

/// "What the relay sees" — radical transparency about the untrusted server.
///
/// Logos's whole premise is that the relay is hostile: it must be able to route
/// and store opaque envelopes without learning who you are or what you said. Most
/// apps never show this because the honest answer is embarrassing. For Logos it's a
/// flex — so we show it, plainly, and we don't hide the parts that are still weak.
///
/// Everything here is derived from the published threat model (docs/THREAT-MODEL.md)
/// and the relay construction (docs/PROTOCOL.md). Nothing here is a security claim
/// beyond what those documents already state; Logos remains EXPERIMENTAL & UNAUDITED.
struct RelayVisibilityView: View {
    @EnvironmentObject var session: Session

    private var relayHost: String { URL(string: session.relayURL)?.host ?? session.relayURL }

    var body: some View {
        ScrollView {
            VStack(spacing: Space.lg) {
                header
                liveCard
                canSeeSection
                cantSeeSection
                limitsSection
                footer
            }
            .padding(Space.lg)
            .frame(maxWidth: 560).frame(maxWidth: .infinity)
        }
        .logosBackground(watermark: true)
        .navigationTitle("What the relay sees")
        .navigationBarTitleDisplayMode(.inline)
    }

    // MARK: - Header

    private var header: some View {
        VStack(spacing: Space.sm) {
            Image(systemName: "server.rack")
                .font(.system(size: 30, weight: .light))
                .foregroundStyle(LColor.goldText)
                .frame(width: 84, height: 84)
                .background(LColor.goldWash, in: Circle())
            Text("Logos treats its own server as untrusted.")
                .font(LFont.title3).foregroundStyle(LColor.ink)
                .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
            Text("Here is exactly what **\(relayHost)** can and cannot observe about you. We'd rather you know than take our word for it.")
                .font(LFont.subhead).foregroundStyle(LColor.inkSecondary)
                .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: - Live "this is the routing identifier" card

    private var liveCard: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            Text("THE ROUTING IDENTIFIER").font(LFont.caption).fontWeight(.semibold)
                .foregroundStyle(LColor.inkTertiary).tracking(0.6)
            Text("To deliver a message the relay needs a mailbox to drop it in. This is yours — the one piece of routing metadata the server genuinely uses. It does not contain your username or your keys, but it is stable (it doesn't rotate yet).")
                .font(LFont.footnote).foregroundStyle(LColor.inkSecondary)
                .fixedSize(horizontal: false, vertical: true)
            if session.mailboxId.isEmpty {
                Text("— set up an identity to see yours —")
                    .font(LFont.footnote).foregroundStyle(LColor.inkTertiary)
            } else {
                Text(session.mailboxId)
                    .font(LFont.mono).foregroundStyle(LColor.ink)
                    .lineLimit(2).truncationMode(.middle)
                    .textSelection(.enabled)
                    .padding(.horizontal, Space.sm).padding(.vertical, 10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(LColor.surfaceAlt)
                    .clipShape(RoundedRectangle(cornerRadius: Radius.control, style: .continuous))
            }
            HStack(spacing: Space.xs) {
                Circle().fill(session.online ? LColor.verified : LColor.danger)
                    .frame(width: 8, height: 8)
                Text(session.online ? "Connected to \(relayHost)" : "Not currently reaching \(relayHost)")
                    .font(LFont.caption).foregroundStyle(LColor.inkSecondary)
            }
        }
        .cardStyle()
    }

    // MARK: - Can see

    private var canSeeSection: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            sectionLabel("WHAT IT CAN SEE", tint: LColor.caution, icon: "eye.fill")
            VStack(spacing: 0) {
                RelayFactRow(tint: .caution, icon: "tray.full.fill",
                             title: "Which mailbox a message is for",
                             detail: "It has to, to deliver it. When you send, it sees the recipient's mailbox; when you fetch, it sees yours.")
                rowDivider
                RelayFactRow(tint: .caution, icon: "clock.fill",
                             title: "When messages move",
                             detail: "Timing of deliveries and fetches. Padding and scheduled cover traffic to blur this are on the roadmap, not on yet.")
                rowDivider
                RelayFactRow(tint: .caution, icon: "ruler.fill",
                             title: "Roughly how big a message is",
                             detail: "The ciphertext length is visible even though the contents aren't. Constant-size padding is future work.")
                rowDivider
                RelayFactRow(tint: .caution, icon: "network",
                             title: "The network address it's talking to",
                             detail: "Like any server, it sees the IP that connects. A private relay or, later, an onion/mixnet transport changes who that is. Logos is relayed, not peer-to-peer.")
            }
            .cardStyle(padding: 0)
        }
    }

    // MARK: - Can't see

    private var cantSeeSection: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            sectionLabel("WHAT IT CANNOT SEE", tint: LColor.verified, icon: "lock.shield.fill")
            VStack(spacing: 0) {
                RelayFactRow(tint: .verified, icon: "text.bubble.fill",
                             title: "What you said",
                             detail: "Message contents are end-to-end encrypted with a post-quantum-hybrid handshake (X25519 + ML-KEM-1024). The relay stores opaque bytes.")
                rowDivider
                RelayFactRow(tint: .verified, icon: "eye.slash.fill",
                             title: "Who sent a delivered message",
                             detail: "Sealed sender hides the author from the relay. (This sender-hiding envelope is classical X25519 today; the contents inside are post-quantum.)")
                rowDivider
                RelayFactRow(tint: .verified, icon: "key.fill",
                             title: "Your identity when you collect mail",
                             detail: "Fetch is authenticated by proving control of your key, and the server derives your mailbox from that proof — it never receives your identity key itself.")
                rowDivider
                RelayFactRow(tint: .verified, icon: "checkmark.shield.fill",
                             title: "Whether you've verified anyone",
                             detail: "Safety numbers are compared on your devices. Verification status, nicknames, and photos never leave this phone.")
            }
            .cardStyle(padding: 0)
            NavigationLink { SealedSenderView() } label: {
                HStack(spacing: 4) {
                    Text("How sealed sender hides who you are").font(LFont.footnote.weight(.medium))
                    Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold))
                }
                .foregroundStyle(LColor.goldText)
                .padding(.leading, Space.xs).padding(.top, 2)
            }
            .buttonStyle(.plain)
        }
    }

    // MARK: - Honest limits

    private var limitsSection: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            sectionLabel("WHAT WE HAVEN'T CLOSED YET", tint: LColor.inkSecondary, icon: "wrench.and.screwdriver.fill")
            VStack(alignment: .leading, spacing: Space.sm) {
                limitRow("The relay currently issues the sealed-sender certificates, so a fully malicious operator holds that authority. Sender identity is TOFU-pinned on your device as a first defense; moving this to key transparency is planned.")
                limitRow("Mailbox identifiers are stable rather than blinded/rotating, so the relay can link a mailbox's activity over time.")
                limitRow("Timing and message size are observable until envelope padding and cover-traffic modes land.")
                limitRow("Anyone can post to a mailbox by design (open delivery), bounded only by a per-mailbox cap — full rate-limiting and TTL are future work.")
            }
            .padding(Space.md)
            .background(LColor.surfaceAlt.opacity(0.6))
            .clipShape(RoundedRectangle(cornerRadius: Radius.card, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.card, style: .continuous)
                .strokeBorder(LColor.hairline, lineWidth: 1))
        }
    }

    private var footer: some View {
        VStack(spacing: Space.xs) {
            Text("Logos never asks you to trust the relay — only the safety number.")
                .font(LFont.footnote.weight(.medium)).foregroundStyle(LColor.goldText)
                .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
            Text("Details: docs/THREAT-MODEL.md \u{00B7} docs/PROTOCOL.md")
                .font(LFont.caption).foregroundStyle(LColor.inkTertiary)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, Space.xs)
    }

    // MARK: - Bits

    private func sectionLabel(_ text: String, tint: Color, icon: String) -> some View {
        HStack(spacing: 6) {
            Image(systemName: icon).font(.system(size: 12, weight: .semibold)).foregroundStyle(tint)
            Text(text).font(LFont.caption).fontWeight(.semibold).foregroundStyle(tint).tracking(0.6)
        }
        .padding(.leading, Space.xs)
    }

    private func limitRow(_ text: String) -> some View {
        HStack(alignment: .top, spacing: Space.xs) {
            Image(systemName: "circle.fill").font(.system(size: 5)).foregroundStyle(LColor.inkTertiary)
                .padding(.top, 6)
            Text(text).font(LFont.footnote).foregroundStyle(LColor.inkSecondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var rowDivider: some View {
        Divider().background(LColor.hairline).padding(.leading, 52)
    }
}

/// One fact about the relay's view, styled by whether it's something it can see
/// (caution) or can't (verified). Icon + title + plain-language explanation.
private struct RelayFactRow: View {
    enum Tint { case caution, verified
        var color: Color { self == .caution ? LColor.caution : LColor.verified }
    }
    let tint: Tint
    let icon: String
    let title: String
    let detail: String

    var body: some View {
        HStack(alignment: .top, spacing: Space.sm) {
            Image(systemName: icon)
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(tint.color)
                .frame(width: 26)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(LFont.body).foregroundStyle(LColor.ink)
                Text(detail).font(LFont.footnote).foregroundStyle(LColor.inkSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(Space.md)
    }
}
