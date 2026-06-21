import SwiftUI

struct ChatView: View {
    @EnvironmentObject var session: Session
    let peer: String
    @State private var draft = ""
    @State private var acknowledgedChange = false
    @FocusState private var composerFocused: Bool

    private var msgs: [ChatMessage] { session.messages[peer] ?? [] }
    private var security: SessionSecurity { session.security(for: peer) }
    private var changedAndUnacknowledged: Bool { security == .identityChanged && !acknowledgedChange }

    var body: some View {
        VStack(spacing: 0) {
            thread
            composer
        }
        .logosBackground(watermark: true)
        .safeAreaInset(edge: .top) {
            if !session.online { OfflineBanner { session.syncNow() } }
        }
        .animation(Motion.standard, value: session.online)
        .navigationTitle(peer)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .principal) {
                NavigationLink { VerifyView(peer: peer) } label: {
                    VStack(spacing: 1) {
                        Text(peer).font(LFont.headline).foregroundStyle(LColor.ink)
                        titleStatus
                    }
                }
            }
            ToolbarItem(placement: .topBarTrailing) {
                NavigationLink { VerifyView(peer: peer) } label: {
                    Image(systemName: "info.circle").foregroundStyle(LColor.goldText)
                }
                .accessibilityLabel("Conversation details")
            }
        }
    }

    // Tiny, quiet status under the title. Loud only when something is wrong.
    @ViewBuilder private var titleStatus: some View {
        switch security {
        case .encrypted:
            Label("End-to-end encrypted", systemImage: "lock.fill")
                .labelStyle(.titleAndIcon)
                .font(.system(size: 11)).foregroundStyle(LColor.inkTertiary)
        case .verified:
            Label("Verified", systemImage: "checkmark.shield.fill")
                .font(.system(size: 11, weight: .medium)).foregroundStyle(LColor.verified)
        case .identityChanged:
            Label("Identity changed", systemImage: "exclamationmark.shield.fill")
                .font(.system(size: 11, weight: .semibold)).foregroundStyle(LColor.caution)
        }
    }

    private var thread: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: Space.xs) {
                    firstSessionChip
                    if security == .identityChanged { identityChangedInterstitial }
                    ForEach(msgs) { msg in
                        MessageBubble(message: msg) { session.retry(msg.id, in: peer) }
                            .id(msg.id)
                    }
                }
                .padding(.horizontal, Space.md)
                .padding(.vertical, Space.sm)
            }
            .scrollDismissesKeyboard(.interactively)
            .onChange(of: msgs.count) { _ in
                guard let last = msgs.last else { return }
                withAnimation(Motion.standard) { proxy.scrollTo(last.id, anchor: .bottom) }
            }
            .onAppear {
                if let last = msgs.last { proxy.scrollTo(last.id, anchor: .bottom) }
            }
        }
    }

    @ViewBuilder private var firstSessionChip: some View {
        if msgs.isEmpty && security != .identityChanged {
            VStack(spacing: Space.xs) {
                Image(systemName: "lock.fill").font(.system(size: 13))
                    .foregroundStyle(LColor.goldText)
                Text("Messages with **\(peer)** are end-to-end encrypted.")
                    .font(LFont.footnote).foregroundStyle(LColor.inkSecondary)
                NavigationLink { VerifyView(peer: peer) } label: {
                    Text("Verify their identity")
                        .font(LFont.footnote.weight(.semibold)).foregroundStyle(LColor.goldText)
                }
            }
            .frame(maxWidth: .infinity)
            .padding(Space.md)
            .background(LColor.goldWash.opacity(0.5))
            .clipShape(RoundedRectangle(cornerRadius: Radius.card, style: .continuous))
            .padding(.bottom, Space.xs)
        }
    }

    // High-friction: unmistakable, and it gates the composer until acknowledged.
    private var identityChangedInterstitial: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            Label("\(peer)’s identity changed", systemImage: "exclamationmark.shield.fill")
                .font(LFont.headline).foregroundStyle(LColor.caution)
            Text("This usually means \(peer) reinstalled Logos or switched devices — but it can also mean someone is intercepting your messages. Verify before you send anything sensitive.")
                .font(LFont.footnote).foregroundStyle(LColor.ink)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: Space.sm) {
                NavigationLink { VerifyView(peer: peer) } label: {
                    Text("Verify identity").frame(maxWidth: .infinity)
                }
                .buttonStyle(.logosPrimary)
                Button("Send anyway") {
                    Haptic.warn(); withAnimation(Motion.standard) { acknowledgedChange = true }
                }
                .buttonStyle(.logosSecondary)
            }
        }
        .padding(Space.md)
        .background(LColor.caution.opacity(0.10))
        .overlay(RoundedRectangle(cornerRadius: Radius.card, style: .continuous)
            .strokeBorder(LColor.caution.opacity(0.4), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: Radius.card, style: .continuous))
        .padding(.bottom, Space.xs)
    }

    private var composer: some View {
        VStack(spacing: 0) {
            Divider().background(LColor.hairline)
            HStack(alignment: .bottom, spacing: Space.xs) {
                Button { Haptic.tap() } label: {
                    Image(systemName: "plus")
                        .font(.system(size: 18, weight: .medium))
                        .foregroundStyle(LColor.inkSecondary)
                        .frame(width: 36, height: 36)
                }
                .accessibilityLabel("Add attachment")

                TextField("Message", text: $draft, axis: .vertical)
                    .focused($composerFocused)
                    .lineLimit(1...6)
                    .font(LFont.body)
                    .padding(.horizontal, Space.sm).padding(.vertical, 9)
                    .background(LColor.surfaceAlt)
                    .clipShape(RoundedRectangle(cornerRadius: Radius.bubble, style: .continuous))

                Button {
                    let t = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !t.isEmpty else { return }
                    draft = ""; Haptic.send()
                    session.send(to: peer, text: t)
                } label: {
                    Image(systemName: "arrow.up")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundStyle(LColor.onGold)
                        .frame(width: 36, height: 36)
                        .background(canSend ? LColor.gold : LColor.gold.opacity(0.35), in: Circle())
                }
                .disabled(!canSend)
                .animation(Motion.micro, value: canSend)
                .accessibilityLabel("Send")
            }
            .padding(.horizontal, Space.sm).padding(.vertical, Space.xs)
            .background(LColor.canvas)
            .opacity(changedAndUnacknowledged ? 0.4 : 1)
            .allowsHitTesting(!changedAndUnacknowledged)
            .overlay(alignment: .top) {
                if changedAndUnacknowledged {
                    Text("Verify \(peer) to continue")
                        .font(LFont.caption).foregroundStyle(LColor.caution)
                        .padding(.top, 2)
                }
            }
        }
    }

    private var canSend: Bool {
        !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !changedAndUnacknowledged
    }
}

// MARK: - Message bubble

struct MessageBubble: View {
    let message: ChatMessage
    let onRetry: () -> Void

    var body: some View {
        HStack {
            if message.mine { Spacer(minLength: 48) }
            VStack(alignment: message.mine ? .trailing : .leading, spacing: 3) {
                Text(message.text)
                    .font(LFont.body)
                    .foregroundStyle(message.mine ? LColor.bubbleMineText : LColor.ink)
                    .padding(.horizontal, 13).padding(.vertical, 9)
                    .background(message.mine ? LColor.bubbleMine : LColor.surfaceAlt)
                    .clipShape(RoundedRectangle(cornerRadius: Radius.bubble, style: .continuous))
                    .textSelection(.enabled)
                if message.mine { statusRow }
            }
            if !message.mine { Spacer(minLength: 48) }
        }
        .frame(maxWidth: .infinity, alignment: message.mine ? .trailing : .leading)
        .transition(.asymmetric(
            insertion: .scale(scale: 0.92, anchor: message.mine ? .bottomTrailing : .bottomLeading)
                .combined(with: .opacity),
            removal: .opacity))
        .animation(Motion.bubble, value: message.status)
    }

    @ViewBuilder private var statusRow: some View {
        switch message.status {
        case .sending:
            label("Sending…", "clock", LColor.inkTertiary)
        case .sent:
            HStack(spacing: 4) {
                Text(message.at, style: .time)
                Image(systemName: "lock.fill")
            }
            .font(.system(size: 10)).foregroundStyle(LColor.inkTertiary)
            .accessibilityLabel("Sent, encrypted")
        case .failed(let why):
            Button(action: { Haptic.tap(); onRetry() }) {
                label("Not delivered · Retry", "exclamationmark.circle.fill", LColor.danger)
            }
            .accessibilityLabel("Not delivered. \(why). Double tap to retry.")
        case .blocked(let why):
            Button(action: { Haptic.warn(); onRetry() }) {
                label("Couldn’t verify identity · Review", "exclamationmark.shield.fill", LColor.caution)
            }
            .accessibilityLabel("Blocked. \(why)")
        }
    }

    private func label(_ text: String, _ icon: String, _ tint: Color) -> some View {
        HStack(spacing: 4) {
            Image(systemName: icon)
            Text(text)
        }
        .font(.system(size: 10, weight: .medium)).foregroundStyle(tint)
    }
}

// MARK: - New chat sheet

struct ComposeSheet: View {
    @EnvironmentObject var session: Session
    @Environment(\.dismiss) private var dismiss
    @State private var peer = ""
    @FocusState private var focused: Bool

    private var trimmed: String { peer.trimmingCharacters(in: .whitespaces) }

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: Space.md) {
                Text("Enter a username to start an encrypted conversation.")
                    .font(LFont.subhead).foregroundStyle(LColor.inkSecondary)
                HStack(spacing: 4) {
                    Text("@").font(LFont.body).foregroundStyle(LColor.inkTertiary)
                    TextField("username", text: $peer)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .focused($focused).submitLabel(.go)
                        .onSubmit(start)
                }
                .padding(.horizontal, Space.md).padding(.vertical, 14)
                .background(LColor.surface)
                .clipShape(RoundedRectangle(cornerRadius: Radius.control, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: Radius.control, style: .continuous)
                    .strokeBorder(focused ? LColor.gold : LColor.hairline, lineWidth: 1))

                Button("Start chat", action: start)
                    .buttonStyle(.logosPrimary)
                    .disabled(trimmed.isEmpty)
                Spacer()
            }
            .padding(Space.lg)
            .logosBackground()
            .navigationTitle("New chat")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Cancel") { dismiss() }.foregroundStyle(LColor.inkSecondary)
                }
            }
            .onAppear { focused = true }
        }
    }

    private func start() {
        guard !trimmed.isEmpty else { return }
        Haptic.tap()
        session.startConversation(with: trimmed)
        dismiss()
    }
}
