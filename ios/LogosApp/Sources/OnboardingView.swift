import SwiftUI

struct OnboardingView: View {
    @EnvironmentObject var session: Session
    @State private var username = ""
    @State private var relay = ""
    @State private var showAdvanced = false
    @State private var showHow = false
    @State private var showRestore = false
    @FocusState private var nameFocused: Bool

    private var trimmed: String { username.trimmingCharacters(in: .whitespaces) }

    var body: some View {
        ScrollView {
            VStack(spacing: Space.lg) {
                Spacer(minLength: Space.xl)

                // Brand wordmark (real lockup: emblem + "Logos")
                VStack(spacing: Space.sm) {
                    Image("Wordmark")
                        .resizable()
                        .scaledToFit()
                        .frame(width: 220)
                    Text("End-to-end encrypted messages.\nNo phone number, no email.")
                        .font(LFont.callout).foregroundStyle(LColor.inkSecondary)
                        .multilineTextAlignment(.center)
                }
                .padding(.bottom, Space.sm)

                // Identity field
                VStack(alignment: .leading, spacing: Space.xs) {
                    Text("CHOOSE A USERNAME").font(LFont.caption).fontWeight(.semibold)
                        .foregroundStyle(LColor.inkTertiary).tracking(0.6)
                    HStack(spacing: 4) {
                        Text("@").font(LFont.body).foregroundStyle(LColor.inkTertiary)
                        TextField("yourname", text: $username)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .focused($nameFocused)
                            .submitLabel(.done)
                    }
                    .padding(.horizontal, Space.md).padding(.vertical, 14)
                    .background(LColor.surface)
                    .clipShape(RoundedRectangle(cornerRadius: Radius.control, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: Radius.control, style: .continuous)
                            .strokeBorder(nameFocused ? LColor.gold : LColor.hairline, lineWidth: 1))
                    Text("This is how friends find you. Pick something you’re happy to share.")
                        .font(LFont.footnote).foregroundStyle(LColor.inkSecondary)
                }

                // Primary action
                Button("Create your identity") {
                    Haptic.tap()
                    session.register(username: trimmed, relay: relay)
                }
                .buttonStyle(.logosPrimary)
                .disabled(trimmed.isEmpty)

                Button("Restore from a recovery phrase") {
                    Haptic.tap(); showRestore = true
                }
                .font(LFont.subhead.weight(.medium))
                .foregroundStyle(LColor.goldText)

                if let e = session.lastError {
                    LBanner(tone: .danger, icon: "exclamationmark.triangle.fill",
                            title: "Couldn’t create your identity", message: e)
                }

                // How encryption works — plain language, expandable (no wall of text)
                howItWorks

                // Advanced (relay) — hidden by default
                advanced

                Spacer(minLength: Space.lg)
            }
            .padding(.horizontal, Space.lg)
            .frame(maxWidth: 520)
            .frame(maxWidth: .infinity)
        }
        .scrollDismissesKeyboard(.interactively)
        .logosBackground()
        .onAppear { if relay.isEmpty { relay = session.relayURL } }
        .sheet(isPresented: $showRestore) { RestoreView().environmentObject(session) }
    }

    private var howItWorks: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            Button {
                withAnimation(Motion.standard) { showHow.toggle() }
            } label: {
                HStack {
                    Label("How encryption works", systemImage: "lock.shield")
                        .font(LFont.subhead.weight(.medium)).foregroundStyle(LColor.ink)
                    Spacer()
                    Image(systemName: "chevron.down")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(LColor.inkTertiary)
                        .rotationEffect(.degrees(showHow ? 0 : -90))
                }
            }
            if showHow {
                VStack(alignment: .leading, spacing: Space.sm) {
                    point("lock.fill", "Only you and the person you’re messaging can read what you send. Not us, not the relay.")
                    point("key.fill", "Your keys live on this device. We never see them, so we can’t hand them over.")
                    point("eye.slash.fill", "There’s no phone number to leak. Your relay sees who has a mailbox — not what’s inside.")
                }
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .cardStyle()
    }

    private func point(_ icon: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: Space.sm) {
            Image(systemName: icon).font(.system(size: 13, weight: .semibold))
                .foregroundStyle(LColor.goldText).frame(width: 18)
            Text(text).font(LFont.footnote).foregroundStyle(LColor.inkSecondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var advanced: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            Button {
                withAnimation(Motion.standard) { showAdvanced.toggle() }
            } label: {
                HStack {
                    Text("Advanced").font(LFont.footnote.weight(.medium)).foregroundStyle(LColor.inkSecondary)
                    Image(systemName: "chevron.down")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(LColor.inkTertiary)
                        .rotationEffect(.degrees(showAdvanced ? 0 : -90))
                    Spacer()
                }
            }
            if showAdvanced {
                VStack(alignment: .leading, spacing: 4) {
                    Text("RELAY URL").font(LFont.caption).fontWeight(.semibold)
                        .foregroundStyle(LColor.inkTertiary).tracking(0.6)
                    TextField("https://relay.example", text: $relay)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .keyboardType(.URL)
                        .font(LFont.footnote.monospaced())
                        .padding(.horizontal, Space.sm).padding(.vertical, 10)
                        .background(LColor.surfaceAlt)
                        .clipShape(RoundedRectangle(cornerRadius: Radius.control, style: .continuous))
                    Text("The server that relays your encrypted messages. Leave the default unless you run your own.")
                        .font(LFont.caption).foregroundStyle(LColor.inkTertiary)
                }
                .transition(.opacity)
            }
        }
    }
}

/// Restore an existing identity from its 24-word recovery phrase.
struct RestoreView: View {
    @EnvironmentObject var session: Session
    @Environment(\.dismiss) private var dismiss
    @State private var username = ""
    @State private var phrase = ""
    @State private var relay = ""

    private var trimmedName: String { username.trimmingCharacters(in: .whitespaces) }
    private var wordCount: Int {
        phrase.split(whereSeparator: { $0 == " " || $0 == "\n" || $0 == "\t" })
            .filter { !$0.isEmpty }.count
    }
    // 24 words = a modern (seed-derived) identity; 48 = an older full-key identity.
    private var validWords: Bool { wordCount == 24 || wordCount == 48 }
    private var wordCountHint: String {
        validWords ? "\(wordCount) words ✓"
                   : "\(wordCount) words — need 24 (or 48 for an older identity)"
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: Space.lg) {
                    VStack(alignment: .leading, spacing: Space.xs) {
                        Text("Restore your identity").font(LFont.title).foregroundStyle(LColor.ink)
                        Text("Enter your username and the recovery phrase you saved (24 words, or 48 for an older identity). This reclaims your account on this device.")
                            .font(LFont.callout).foregroundStyle(LColor.inkSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    VStack(alignment: .leading, spacing: Space.xs) {
                        Text("USERNAME").font(LFont.caption).fontWeight(.semibold)
                            .foregroundStyle(LColor.inkTertiary).tracking(0.6)
                        HStack(spacing: 4) {
                            Text("@").font(LFont.body).foregroundStyle(LColor.inkTertiary)
                            TextField("yourname", text: $username)
                                .textInputAutocapitalization(.never).autocorrectionDisabled()
                        }
                        .padding(.horizontal, Space.md).padding(.vertical, 14)
                        .background(LColor.surface)
                        .clipShape(RoundedRectangle(cornerRadius: Radius.control, style: .continuous))
                        .overlay(RoundedRectangle(cornerRadius: Radius.control, style: .continuous)
                            .strokeBorder(LColor.hairline, lineWidth: 1))
                    }

                    VStack(alignment: .leading, spacing: Space.xs) {
                        Text("RECOVERY PHRASE").font(LFont.caption).fontWeight(.semibold)
                            .foregroundStyle(LColor.inkTertiary).tracking(0.6)
                        TextEditor(text: $phrase)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .font(LFont.body.monospaced())
                            .frame(minHeight: 110)
                            .scrollContentBackground(.hidden)
                            .padding(Space.xs)
                            .background(LColor.surface)
                            .clipShape(RoundedRectangle(cornerRadius: Radius.control, style: .continuous))
                            .overlay(RoundedRectangle(cornerRadius: Radius.control, style: .continuous)
                                .strokeBorder(LColor.hairline, lineWidth: 1))
                        Text(wordCountHint)
                            .font(LFont.caption)
                            .foregroundStyle(validWords ? LColor.goldText : LColor.inkTertiary)
                    }

                    Button("Restore") {
                        Haptic.tap()
                        session.restore(username: trimmedName, phrase: phrase, relay: relay)
                    }
                    .buttonStyle(.logosPrimary)
                    .disabled(trimmedName.isEmpty || !validWords)

                    if let e = session.lastError {
                        LBanner(tone: .danger, icon: "exclamationmark.triangle.fill",
                                title: "Couldn’t restore", message: e)
                    }

                    HStack(alignment: .top, spacing: 6) {
                        Image(systemName: "info.circle").font(.system(size: 12))
                        Text("Restores your identity and username only. Message history and contacts stay on your old device; existing contacts may need to start a new chat with you.")
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .font(LFont.caption).foregroundStyle(LColor.inkSecondary)
                }
                .padding(Space.lg)
                .frame(maxWidth: 520).frame(maxWidth: .infinity)
            }
            .scrollDismissesKeyboard(.interactively)
            .logosBackground()
            .navigationTitle("Restore").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
            .onAppear { if relay.isEmpty { relay = session.relayURL } }
        }
    }
}
