import SwiftUI

struct ChatView: View {
    @EnvironmentObject var session: Session
    let peer: String
    @State private var draft = ""
    @State private var acknowledgedChange = false
    @State private var showCatchup = false
    @AppStorage("ai.assistantName") private var assistantName = AIConfig.defaultAssistantName
    @State private var showCloudConsent = false
    @State private var pendingQuestion = ""
    @FocusState private var composerFocused: Bool

    private var msgs: [ChatMessage] { session.messages[peer] ?? [] }
    private var security: SessionSecurity { session.security(for: peer) }
    private var changedAndUnacknowledged: Bool { security == .identityChanged && !acknowledgedChange }
    private var provider: AIProvider { AIConfig.effectiveProvider }
    private var aiName: String {
        let t = assistantName.trimmingCharacters(in: .whitespaces)
        return t.isEmpty ? AIConfig.defaultAssistantName : t
    }

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
        .navigationTitle(session.displayName(for: peer))
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { session.setActive(peer) }
        .onDisappear { session.setActive(nil) }
        .toolbar {
            ToolbarItem(placement: .principal) {
                NavigationLink { VerifyView(peer: peer) } label: {
                    VStack(spacing: 1) {
                        Text(session.displayName(for: peer)).font(LFont.headline).foregroundStyle(LColor.ink)
                        titleStatus
                    }
                }
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button { Haptic.tap(); showCatchup = true } label: {
                    Image(systemName: "sparkles").foregroundStyle(LColor.goldText)
                }
                .accessibilityLabel("Catch me up")
            }
            ToolbarItem(placement: .topBarTrailing) {
                NavigationLink { VerifyView(peer: peer) } label: {
                    Image(systemName: "info.circle").foregroundStyle(LColor.goldText)
                }
                .accessibilityLabel("Conversation details")
            }
        }
        .sheet(isPresented: $showCatchup) { AICatchUpSheet(peer: peer).environmentObject(session) }
        .alert("Use \(aiName) in this chat?", isPresented: $showCloudConsent) {
            Button("Allow once") { session.mentionAI(in: peer, question: pendingQuestion) }
            Button("Allow & don’t ask again") {
                AIConfig.inChatCloudConsented = true
                session.mentionAI(in: peer, question: pendingQuestion)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Your recent messages in this chat will be sent to \(provider.label) to answer, leaving end-to-end encryption (the Logos relay still never sees them). On-device AI keeps everything private.")
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
                    if session.aiMentionPending.contains(peer) { TypingBubble().id("ai-typing") }
                }
                .padding(.horizontal, Space.md)
                .padding(.vertical, Space.sm)
            }
            .scrollDismissesKeyboard(.interactively)
            .onChange(of: msgs.count) { _ in
                guard let last = msgs.last else { return }
                withAnimation(Motion.standard) { proxy.scrollTo(last.id, anchor: .bottom) }
            }
            .onChange(of: session.aiMentionPending) { _ in
                if session.aiMentionPending.contains(peer) {
                    withAnimation(Motion.standard) { proxy.scrollTo("ai-typing", anchor: .bottom) }
                }
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
            mentionSuggestion
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
                    maybeAskAI(t)
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

    // MARK: - In-chat @mention

    /// The text after the last "@" the user is currently typing (nil if none / spans a newline).
    private var mentionFragment: String? {
        guard let at = draft.lastIndex(of: "@") else { return nil }
        let frag = String(draft[draft.index(after: at)...])
        return frag.contains("\n") ? nil : frag
    }
    /// Show the autocomplete chip while "@<fragment>" is still a prefix of the name and
    /// the mention isn't already complete. Hidden when no AI provider is set up.
    private var showMentionSuggestion: Bool {
        guard provider != .none, let frag = mentionFragment else { return false }
        if Session.mentionsAI(draft, name: aiName) { return false }
        return aiName.lowercased().hasPrefix(frag.lowercased())
    }

    @ViewBuilder private var mentionSuggestion: some View {
        if showMentionSuggestion {
            Button(action: insertMention) {
                HStack(spacing: Space.sm) {
                    Image(systemName: "sparkles")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(LColor.onGold)
                        .frame(width: 26, height: 26).background(LColor.gold, in: Circle())
                    VStack(alignment: .leading, spacing: 1) {
                        Text(aiName).font(LFont.subhead.weight(.semibold)).foregroundStyle(LColor.ink)
                        Text("Ask your AI here — both of you see the reply")
                            .font(LFont.caption).foregroundStyle(LColor.inkTertiary)
                    }
                    Spacer(minLength: 0)
                    Image(systemName: "arrow.up.left.circle.fill")
                        .font(.system(size: 18)).foregroundStyle(LColor.goldText)
                }
                .padding(.horizontal, Space.md).padding(.vertical, Space.xs)
                .background(LColor.surface)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .transition(.move(edge: .bottom).combined(with: .opacity))
        }
    }

    private func insertMention() {
        guard let at = draft.lastIndex(of: "@") else { return }
        draft = String(draft[..<at]) + "@\(aiName) "
        Haptic.tap()
    }

    /// If the just-sent message tags the assistant, generate an answer for the thread
    /// (gated by cloud consent). On-device answers immediately; cloud asks once.
    private func maybeAskAI(_ text: String) {
        guard provider != .none, Session.mentionsAI(text, name: aiName) else { return }
        let question = strippedQuestion(text)
        if provider.isCloud && !AIConfig.inChatCloudConsented {
            pendingQuestion = question
            showCloudConsent = true
        } else {
            session.mentionAI(in: peer, question: question)
        }
    }
    /// Drop the "@<name>" token so the model gets just the ask.
    private func strippedQuestion(_ text: String) -> String {
        guard let r = text.range(of: "@" + aiName, options: .caseInsensitive) else { return text }
        var q = text
        q.removeSubrange(r)
        return q.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

// MARK: - Message bubble

struct MessageBubble: View {
    let message: ChatMessage
    /// The 1:1 thread shows a delivery/encryption status under each outbound bubble.
    /// The local AI thread has no relay delivery, so it opts out (`showStatus: false`).
    var showStatus = true
    let onRetry: () -> Void

    private var isAI: Bool { message.aiAuthor != nil }

    var body: some View {
        HStack {
            if message.mine { Spacer(minLength: 48) }
            VStack(alignment: message.mine ? .trailing : .leading, spacing: 3) {
                if let ai = message.aiAuthor {
                    Label(ai, systemImage: "sparkles")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(LColor.goldText)
                        .padding(.horizontal, 4)
                }
                Text(message.text)
                    .font(LFont.body)
                    .foregroundStyle(isAI ? LColor.ink : (message.mine ? LColor.bubbleMineText : LColor.ink))
                    .padding(.horizontal, 13).padding(.vertical, 9)
                    .background(isAI ? LColor.goldWash : (message.mine ? LColor.bubbleMine : LColor.surfaceAlt))
                    .clipShape(RoundedRectangle(cornerRadius: Radius.bubble, style: .continuous))
                    .textSelection(.enabled)
                if message.mine && showStatus { statusRow }
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
    @State private var showScan = false
    @State private var wrongRelay = false
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
                Button { showScan = true } label: {
                    Label("Scan a code", systemImage: "qrcode.viewfinder").frame(maxWidth: .infinity)
                }
                .buttonStyle(.logosSecondary)
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
            .sheet(isPresented: $showScan) {
                QRScanSheet(title: "Scan to add") { handleScan($0) }
            }
            .alert("Different relay", isPresented: $wrongRelay) {
                Button("OK", role: .cancel) {}
            } message: {
                Text("That contact is on a different relay. Switch to their relay in Settings → Network to message them.")
            }
        }
    }

    private func handleScan(_ code: String) {
        guard let (host, q) = LogosQR.parse(code), host == "add", let u = q["u"] else { return }
        if let r = q["r"], r != session.relayURL { wrongRelay = true; return }
        Haptic.tap()
        session.startConversation(with: u)
        dismiss()
    }

    private func start() {
        guard !trimmed.isEmpty else { return }
        Haptic.tap()
        session.startConversation(with: trimmed)
        dismiss()
    }
}
