import SwiftUI

struct OnboardingView: View {
    @EnvironmentObject var session: Session
    @State private var username = ""
    @State private var relay = ""
    @State private var showAdvanced = false
    @State private var showHow = false
    @FocusState private var nameFocused: Bool

    private var trimmed: String { username.trimmingCharacters(in: .whitespaces) }

    var body: some View {
        ScrollView {
            VStack(spacing: Space.lg) {
                Spacer(minLength: Space.xl)

                // Mark + wordmark (the serif signature)
                VStack(spacing: Space.sm) {
                    Image(systemName: "building.columns.fill")
                        .font(.system(size: 44, weight: .regular))
                        .foregroundStyle(LColor.gold)
                    Text("Logos").font(LFont.display).foregroundStyle(LColor.ink)
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

                if let e = session.lastError {
                    LBanner(tone: .danger, icon: "exclamationmark.triangle.fill",
                            title: "Couldn’t create your identity", message: e)
                }

                // How encryption works — plain language, expandable (no wall of text)
                howItWorks

                // Advanced (relay) — hidden by default
                advanced

                // Honest experimental footer
                HStack(spacing: 6) {
                    Image(systemName: "flask.fill").font(.system(size: 11))
                    Text("Experimental build — not security audited. Don’t use it for anything that must stay secret.")
                }
                .font(LFont.caption).foregroundStyle(LColor.inkSecondary)
                .multilineTextAlignment(.center)
                .padding(.top, Space.xs)

                Spacer(minLength: Space.lg)
            }
            .padding(.horizontal, Space.lg)
            .frame(maxWidth: 520)
            .frame(maxWidth: .infinity)
        }
        .scrollDismissesKeyboard(.interactively)
        .logosBackground()
        .onAppear { if relay.isEmpty { relay = session.relayURL } }
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
