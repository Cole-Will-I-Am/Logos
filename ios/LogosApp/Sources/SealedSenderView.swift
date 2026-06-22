import SwiftUI

/// Deeper explainer for sealed sender, reached from "What the relay sees".
/// Honest about the construction and its current limits (the relay still issues the
/// sender certificates today; the envelope is classical while contents are PQ).
/// Everything here tracks docs/THREAT-MODEL.md and docs/PROTOCOL.md.
struct SealedSenderView: View {
    var body: some View {
        ScrollView {
            VStack(spacing: Space.lg) {
                header
                stepsCard
                certNote
                footer
            }
            .padding(Space.lg)
            .frame(maxWidth: 560).frame(maxWidth: .infinity)
        }
        .logosBackground(watermark: true)
        .navigationTitle("Sealed sender")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var header: some View {
        VStack(spacing: Space.sm) {
            Image(systemName: "eye.slash.fill")
                .font(.system(size: 30, weight: .light))
                .foregroundStyle(LColor.goldText)
                .frame(width: 84, height: 84).background(LColor.goldWash, in: Circle())
            Text("The relay delivers your message without learning who sent it.")
                .font(LFont.title3).foregroundStyle(LColor.ink)
                .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
            Text("Normally a server must know the sender to route a message. Sealed sender removes that: the author is hidden inside the encrypted envelope, not in the routing the server reads.")
                .font(LFont.subhead).foregroundStyle(LColor.inkSecondary)
                .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
        }
    }

    private var stepsCard: some View {
        VStack(alignment: .leading, spacing: Space.md) {
            step(1, "You seal the message for the recipient",
                 "The message is already end-to-end encrypted for your contact (post-quantum hybrid). It's then wrapped a second time in a sealed-sender envelope addressed only to their mailbox.")
            step(2, "The relay sees a mailbox, not a sender",
                 "It can route the outer envelope to the right mailbox, but the author's identity is in the part it can't open. To the server, deliveries to a mailbox aren't attributable to any particular person.")
            step(3, "Only the recipient unwraps who it's from",
                 "Your contact's device opens the envelope, reads the sender certificate inside, and checks it against the identity it pinned for you on first contact (trust-on-first-use). The relay never sees this step.")
        }
        .cardStyle()
    }

    private func step(_ n: Int, _ title: String, _ detail: String) -> some View {
        HStack(alignment: .top, spacing: Space.sm) {
            Text("\(n)").font(LFont.headline).foregroundStyle(LColor.onGold)
                .frame(width: 26, height: 26).background(LColor.gold, in: Circle())
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(LFont.body).foregroundStyle(LColor.ink)
                Text(detail).font(LFont.footnote).foregroundStyle(LColor.inkSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
    }

    private var certNote: some View {
        LBanner(tone: .caution, icon: "exclamationmark.shield.fill",
                title: "The honest limit",
                message: "Today the relay issues the sender certificates, so a fully malicious operator holds that authority — your device's trust-on-first-use pin is the first defense, and a key mismatch is surfaced loudly. The sender-hiding envelope is also classical (X25519) for now, while the message contents inside are post-quantum. Moving certificate authority off the relay (key transparency) is planned.")
    }

    private var footer: some View {
        Text("Details: docs/THREAT-MODEL.md \u{00B7} docs/PROTOCOL.md")
            .font(LFont.caption).foregroundStyle(LColor.inkTertiary)
            .frame(maxWidth: .infinity)
    }
}
