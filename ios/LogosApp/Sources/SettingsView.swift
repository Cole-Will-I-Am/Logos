import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var session: Session
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    @State private var copied = false
    @State private var relayMode = 0       // 0 = public, 1 = private relay
    @State private var privateURL = ""
    @State private var showMyQR = false
    @State private var showPhrase = false
    @State private var showNewIdentityConfirm = false
    @State private var showAI = false

    var body: some View {
        ScrollView {
            VStack(spacing: Space.lg) {
                brandHeader
                identityCard
                networkSection
                aiSection
                privacySection
                safetySection
                relayVisibilityLink
                aboutSection
            }
            .padding(Space.lg)
            .frame(maxWidth: 560).frame(maxWidth: .infinity)
        }
        .logosBackground(watermark: true)
        .navigationTitle("Settings")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(isPresented: $showMyQR) { myQRSheet }
        .sheet(isPresented: $showPhrase) { RecoveryPhraseSheet().environmentObject(session) }
        .sheet(isPresented: $showAI) { AISettingsView() }
        .alert("Start a new identity?", isPresented: $showNewIdentityConfirm) {
            Button("Delete & start new", role: .destructive) { Task { await session.startNewIdentity() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This deletes your current identity and chats on this device and returns you to sign-up, where you can choose a new username. You can’t undo this unless you’ve saved your recovery phrase.")
        }
        .onAppear {
            relayMode = session.relayURL == Session.defaultRelay ? 0 : 1
            privateURL = relayMode == 1 ? session.relayURL : ""
        }
    }

    private var brandHeader: some View {
        Image("Wordmark")
            .resizable()
            .scaledToFit()
            .frame(width: 176)
            .frame(maxWidth: .infinity)
            .padding(.bottom, Space.xs)
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
        let target = targetRelay
        Task { await session.switchRelay(to: target) }
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
            if session.username != nil {
                Button { showMyQR = true } label: {
                    HStack(spacing: 6) {
                        Image(systemName: "qrcode")
                        Text("My QR code")
                    }
                    .font(LFont.footnote.weight(.medium)).foregroundStyle(LColor.goldText)
                }
                Button { showPhrase = true } label: {
                    HStack(spacing: 6) {
                        Image(systemName: "key.horizontal.fill")
                        Text("Back up your identity")
                    }
                    .font(LFont.footnote.weight(.medium)).foregroundStyle(LColor.goldText)
                }
                Button { showNewIdentityConfirm = true } label: {
                    HStack(spacing: 6) {
                        Image(systemName: "person.crop.circle.badge.plus")
                        Text("Start a new identity")
                    }
                    .font(LFont.footnote.weight(.medium)).foregroundStyle(LColor.danger)
                }
            }
        }
        .frame(maxWidth: .infinity)
        .cardStyle(padding: Space.lg)
    }

    private var myQRSheet: some View {
        NavigationStack {
            VStack(spacing: Space.md) {
                Image("Emblem")
                    .resizable().scaledToFit().frame(height: 30)
                LAvatar(name: session.username ?? "?", size: 64)
                Text(session.username.map { "@\($0)" } ?? "")
                    .font(LFont.title3).foregroundStyle(LColor.ink)
                QRCodeView(payload: LogosQR.addPayload(username: session.username ?? "", relay: session.relayURL))
                Text("Have someone scan this from **New chat → Scan** to message you. You both need to be on the same relay.")
                    .font(LFont.subhead).foregroundStyle(LColor.inkSecondary)
                    .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                Spacer()
            }
            .padding(Space.lg)
            .logosBackground()
            .navigationTitle("My code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .topBarTrailing) { Button("Done") { showMyQR = false } } }
        }
    }

    private var aiSection: some View {
        Button { Haptic.tap(); showAI = true } label: {
            HStack(spacing: Space.sm) {
                Image(systemName: "sparkles").font(.system(size: 15, weight: .medium))
                    .foregroundStyle(LColor.goldText).frame(width: 26)
                VStack(alignment: .leading, spacing: 2) {
                    Text("AI (bring your own key)").font(LFont.body).foregroundStyle(LColor.ink)
                    Text(AIConfig.configured
                         ? "\(AIConfig.effectiveProvider.label) · processed on your device or your provider"
                         : "Off — use on-device, or add your own Anthropic / OpenAI / Ollama key")
                        .font(LFont.footnote).foregroundStyle(LColor.inkSecondary)
                        .lineLimit(2)
                }
                Spacer(minLength: 0)
                Image(systemName: "chevron.right").font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(LColor.inkTertiary)
            }
            .padding(Space.md)
        }
        .buttonStyle(.plain)
        .cardStyle(padding: 0)
    }

    private var relayVisibilityLink: some View {
        NavigationLink { RelayVisibilityView() } label: {
            HStack(spacing: Space.sm) {
                Image(systemName: "server.rack").font(.system(size: 15, weight: .medium))
                    .foregroundStyle(LColor.goldText).frame(width: 26)
                VStack(alignment: .leading, spacing: 2) {
                    Text("What the relay sees").font(LFont.body).foregroundStyle(LColor.ink)
                    Text("Exactly what the server can and can't observe \u{2014} in plain language")
                        .font(LFont.footnote).foregroundStyle(LColor.inkSecondary).lineLimit(2)
                }
                Spacer(minLength: 0)
                Image(systemName: "chevron.right").font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(LColor.inkTertiary)
            }
            .padding(Space.md)
        }
        .buttonStyle(.plain)
        .cardStyle(padding: 0)
    }

    private var privacySection: some View {
        SettingsGroup(title: "Privacy & security") {
            SettingsRow(icon: "lock.fill", title: "End-to-end encryption",
                        detail: "On for every conversation. Always.")
            SettingsRow(icon: "eye.slash.fill", title: "Sealed sender",
                        detail: "Hides who sent a message from the relay. Message contents are post-quantum encrypted; this sender-hiding layer itself is classical (X25519).")
            SettingsRow(icon: "iphone", title: "Stored on this device",
                        detail: "Your keys never leave it. The identity store and chat history are encrypted at rest with a device key (Keychain) and kept out of backups.")
        }
    }

    private var safetySection: some View {
        SettingsGroup(title: "Safety") {
            NavigationLink { BlockedUsersView().environmentObject(session) } label: {
                SettingsRow(icon: "hand.raised.fill", title: "Blocked",
                            detail: session.blocked.isEmpty ? "No one blocked" : "\(session.blocked.count) blocked")
            }
            .buttonStyle(.plain)
            Button {
                Haptic.tap()
                let enc: (String) -> String = { $0.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "" }
                if let url = URL(string: "mailto:\(Support.reportEmail)?subject=\(enc("Logos support"))") { openURL(url) }
            } label: {
                SettingsRow(icon: "envelope.fill", title: "Report a problem", detail: Support.reportEmail)
            }
            .buttonStyle(.plain)
        }
    }

    private var aboutSection: some View {
        VStack(spacing: Space.md) {
            Text("Logos · v\(appVersion)")
                .font(LFont.caption).foregroundStyle(LColor.inkTertiary)
        }
    }

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.1.0"
    }
}

// MARK: - Blocked users

private struct BlockedUsersView: View {
    @EnvironmentObject var session: Session
    var body: some View {
        ScrollView {
            VStack(spacing: Space.md) {
                if session.blocked.isEmpty {
                    Text("No one is blocked.")
                        .font(LFont.footnote).foregroundStyle(LColor.inkSecondary)
                        .frame(maxWidth: .infinity).padding(.top, Space.xl)
                } else {
                    SettingsGroup(title: "Blocked") {
                        ForEach(session.blocked.sorted(), id: \.self) { name in
                            HStack(spacing: Space.sm) {
                                Image(systemName: "hand.raised.fill").font(.system(size: 15, weight: .medium))
                                    .foregroundStyle(LColor.goldText).frame(width: 26)
                                Text(name).font(LFont.body).foregroundStyle(LColor.ink)
                                Spacer(minLength: 0)
                                Button("Unblock") { Haptic.tap(); session.unblock(name) }
                                    .font(LFont.footnote).foregroundStyle(LColor.goldText)
                            }
                            .padding(Space.md)
                        }
                    }
                }
            }
            .padding(Space.lg).frame(maxWidth: 560).frame(maxWidth: .infinity)
        }
        .logosBackground(watermark: true)
        .navigationTitle("Blocked")
        .navigationBarTitleDisplayMode(.inline)
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

/// Reveal + back up the 24-word identity recovery phrase. Blurred until tapped.
struct RecoveryPhraseSheet: View {
    @EnvironmentObject var session: Session
    @Environment(\.dismiss) private var dismiss
    @State private var words: [String] = []
    @State private var revealed = false
    @State private var copied = false
    @State private var loadError = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: Space.lg) {
                    LBanner(tone: .caution, icon: "exclamationmark.shield.fill",
                            title: "Anyone with these words is you",
                            message: "They can restore your account and read new messages. Write them on paper and keep them offline — don’t screenshot them or save them to the cloud, and never share them.")

                    if loadError {
                        LBanner(tone: .danger, icon: "xmark.octagon.fill",
                                title: "Couldn’t load your recovery phrase",
                                message: "Something went wrong reading your identity. Try reopening Logos; if it persists, your store may be corrupt.")
                    } else {
                        ZStack {
                            wordGrid.blur(radius: revealed ? 0 : 9)
                            if !revealed {
                                Button { withAnimation(Motion.standard) { revealed = true } } label: {
                                    Label("Tap to reveal", systemImage: "eye.fill")
                                        .font(LFont.subhead.weight(.semibold))
                                        .foregroundStyle(LColor.goldText)
                                        .padding(Space.sm)
                                        .background(LColor.surface, in: Capsule())
                                }
                            }
                        }
                        if revealed {
                            Button {
                                UIPasteboard.general.string = words.joined(separator: " ")
                                Haptic.tap(); withAnimation(Motion.micro) { copied = true }
                            } label: {
                                HStack(spacing: 6) {
                                    Image(systemName: copied ? "checkmark" : "doc.on.doc")
                                    Text(copied ? "Copied — paste somewhere safe, then clear it" : "Copy phrase")
                                }
                                .font(LFont.footnote.weight(.medium)).foregroundStyle(LColor.goldText)
                                .frame(maxWidth: .infinity)
                            }
                        }
                    }

                    Text("To use it: on a new device, choose “Restore from a recovery phrase” and enter your username and these words. (Older identities show 48 words instead of 24.)")
                        .font(LFont.caption).foregroundStyle(LColor.inkSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(Space.lg).frame(maxWidth: 520).frame(maxWidth: .infinity)
            }
            .logosBackground()
            .navigationTitle("Recovery phrase").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .topBarTrailing) { Button("Done") { dismiss() } } }
            .task {
                if let p = await session.recoveryPhrase() {
                    words = p.split(separator: " ").map(String.init)
                } else {
                    loadError = true
                }
            }
        }
    }

    private var wordGrid: some View {
        let cols = [GridItem(.flexible()), GridItem(.flexible())]
        return LazyVGrid(columns: cols, spacing: Space.xs) {
            ForEach(Array(words.enumerated()), id: \.offset) { i, w in
                HStack(spacing: Space.xs) {
                    Text("\(i + 1)").font(LFont.caption.monospaced())
                        .foregroundStyle(LColor.inkTertiary).frame(width: 22, alignment: .trailing)
                    Text(w).font(LFont.body.monospaced()).foregroundStyle(LColor.ink)
                    Spacer(minLength: 0)
                }
                .padding(.horizontal, Space.sm).padding(.vertical, 8)
                .background(LColor.surfaceAlt)
                .clipShape(RoundedRectangle(cornerRadius: Radius.control, style: .continuous))
            }
        }
    }
}
