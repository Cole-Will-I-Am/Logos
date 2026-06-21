import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var session: Session
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false
    @State private var relayMode = 0       // 0 = public, 1 = private relay
    @State private var privateURL = ""

    var body: some View {
        ScrollView {
            VStack(spacing: Space.lg) {
                identityCard
                networkSection
                privacySection
                aboutSection
            }
            .padding(Space.lg)
            .frame(maxWidth: 560).frame(maxWidth: .infinity)
        }
        .logosBackground(watermark: true)
        .navigationTitle("Settings")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            relayMode = session.relayURL == Session.defaultRelay ? 0 : 1
            privateURL = relayMode == 1 ? session.relayURL : ""
        }
    }

    private var networkSection: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Text("NETWORK").font(LFont.caption).fontWeight(.semibold)
                .foregroundStyle(LColor.inkTertiary).tracking(0.6).padding(.leading, Space.xs)
            VStack(alignment: .leading, spacing: Space.sm) {
                relayStatusRow
                Picker("Relay", selection: $relayMode) {
                    Text("Public").tag(0)
                    Text("Private relay").tag(1)
                }
                .pickerStyle(.segmented)

                if relayMode == 1 {
                    TextField("https://your-relay.ts.net", text: $privateURL)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .keyboardType(.URL)
                        .font(LFont.footnote.monospaced())
                        .padding(.horizontal, Space.sm).padding(.vertical, 10)
                        .background(LColor.surfaceAlt)
                        .clipShape(RoundedRectangle(cornerRadius: Radius.control, style: .continuous))
                    Text("Routes your messages through a relay you choose — e.g. a Logos server on your Tailscale network. You’ll only reach people registered on that same relay. It’s still relayed (not peer-to-peer), and traffic can still cross the internet when no direct path is available.")
                        .font(LFont.caption).foregroundStyle(LColor.inkSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    Text("Default Logos relay — \(hostOf(Session.defaultRelay)).")
                        .font(LFont.caption).foregroundStyle(LColor.inkSecondary)
                }

                Button(action: applyNetwork) { Text("Apply").frame(maxWidth: .infinity) }
                    .buttonStyle(.logosSecondary)
                    .disabled(!networkChanged)

                Label("Switching networks changes which relay your identity lives on — you may need to register on the new one.",
                      systemImage: "info.circle")
                    .font(LFont.caption).foregroundStyle(LColor.inkTertiary)
                    .labelStyle(.titleAndIcon)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .cardStyle()
        }
    }

    private var targetRelay: String {
        relayMode == 0 ? Session.defaultRelay : privateURL.trimmingCharacters(in: .whitespaces)
    }
    private var networkChanged: Bool { !targetRelay.isEmpty && targetRelay != session.relayURL }
    private func applyNetwork() {
        guard networkChanged else { return }
        Haptic.tap()
        session.switchRelay(to: targetRelay)
        dismiss()
    }
    private func hostOf(_ s: String) -> String { URL(string: s)?.host ?? s }

    private var relayStatusRow: some View {
        HStack(spacing: Space.xs) {
            Circle().fill(session.online ? LColor.verified : LColor.danger)
                .frame(width: 8, height: 8)
            Text(session.online ? "Connected" : "Can’t reach relay")
                .font(LFont.footnote.weight(.medium)).foregroundStyle(LColor.ink)
            Spacer()
            if let t = session.lastSynced {
                Text("Synced \(t, style: .time)")
                    .font(LFont.caption).foregroundStyle(LColor.inkTertiary)
            }
            Button { Haptic.tap(); session.syncNow() } label: {
                Image(systemName: "arrow.clockwise")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(LColor.goldText)
            }
            .disabled(session.username == nil || session.syncing)
            .accessibilityLabel("Sync now")
        }
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
