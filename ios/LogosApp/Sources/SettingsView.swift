import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var session: Session
    @State private var copied = false

    var body: some View {
        ScrollView {
            VStack(spacing: Space.lg) {
                identityCard
                privacySection
                aboutSection
            }
            .padding(Space.lg)
            .frame(maxWidth: 560).frame(maxWidth: .infinity)
        }
        .logosBackground(watermark: true)
        .navigationTitle("Settings")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var identityCard: some View {
        VStack(spacing: Space.md) {
            LAvatar(name: session.username ?? "?", size: 72)
            Text(session.username.map { "@\($0)" } ?? "—")
                .font(LFont.title3).foregroundStyle(LColor.ink)
            SecurityChip(level: .encrypted)

            if !session.mailboxId.isEmpty {
                Button {
                    UIPasteboard.general.string = session.mailboxId
                    Haptic.tap()
                    withAnimation(Motion.micro) { copied = true }
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: copied ? "checkmark" : "doc.on.doc")
                        Text(copied ? "Copied" : "Copy your address")
                    }
                    .font(LFont.footnote.weight(.medium)).foregroundStyle(LColor.goldText)
                }
            }
        }
        .frame(maxWidth: .infinity)
        .cardStyle(padding: Space.lg)
    }

    private var privacySection: some View {
        SettingsGroup(title: "Privacy & security") {
            SettingsRow(icon: "lock.fill", title: "End-to-end encryption",
                        detail: "On for every conversation. Always.")
            SettingsRow(icon: "eye.slash.fill", title: "Sealed sender",
                        detail: "Outgoing messages hide who sent them from the relay.")
            SettingsRow(icon: "iphone", title: "Stored on this device",
                        detail: "Your keys never leave it — and we keep the store out of backups.")
        }
    }

    private var aboutSection: some View {
        VStack(spacing: Space.md) {
            LBanner(tone: .caution, icon: "flask.fill",
                    title: "Experimental & unaudited",
                    message: "Logos hasn’t been independently security audited. Don’t use it for anything you genuinely need to keep secret.")

            SettingsGroup(title: "Advanced") {
                SettingsRow(icon: "antenna.radiowaves.left.and.right", title: "Relay",
                            detail: session.relayURL, mono: true)
            }

            Text("Logos · v\(appVersion)")
                .font(LFont.caption).foregroundStyle(LColor.inkTertiary)
        }
    }

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.1.0"
    }
}

// MARK: - Settings building blocks

private struct SettingsGroup<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Text(title.uppercased()).font(LFont.caption).fontWeight(.semibold)
                .foregroundStyle(LColor.inkTertiary).tracking(0.6)
                .padding(.leading, Space.xs)
            VStack(spacing: 0) { content }
                .cardStyle(padding: 0)
        }
    }
}

private struct SettingsRow: View {
    let icon: String
    let title: String
    var detail: String? = nil
    var mono = false
    var body: some View {
        HStack(spacing: Space.sm) {
            Image(systemName: icon).font(.system(size: 15, weight: .medium))
                .foregroundStyle(LColor.goldText).frame(width: 26)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(LFont.body).foregroundStyle(LColor.ink)
                if let detail {
                    Text(detail)
                        .font(mono ? LFont.caption.monospaced() : LFont.footnote)
                        .foregroundStyle(LColor.inkSecondary)
                        .lineLimit(mono ? 1 : nil).truncationMode(.middle)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(Space.md)
    }
}
