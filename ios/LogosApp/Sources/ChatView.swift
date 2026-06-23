import SwiftUI
import PhotosUI
import UniformTypeIdentifiers

struct ChatView: View {
    @EnvironmentObject var session: Session
    let peer: String
    @State private var draft = ""
    @State private var acknowledgedChange = false
    @State private var showCatchup = false
    @AppStorage("ai.assistantName") private var assistantName = AIConfig.defaultAssistantName
    @State private var showCloudConsent = false
    @State private var pendingQuestion = ""
    @State private var showAttachMenu = false
    @State private var showPhotoPicker = false
    @State private var photoItem: PhotosPickerItem?
    @State private var showFileImporter = false
    @State private var showAISettings = false
    @State private var showBlockConfirm = false
    @State private var showReportConfirm = false
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
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
        .onAppear { session.setActive(peer); session.aiMentionError = nil }
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
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button(role: .destructive) { showBlockConfirm = true } label: {
                        Label("Block \(session.displayName(for: peer))", systemImage: "hand.raised")
                    }
                    Button(role: .destructive) { showReportConfirm = true } label: {
                        Label("Report \(session.displayName(for: peer))", systemImage: "exclamationmark.bubble")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle").foregroundStyle(LColor.goldText)
                }
                .accessibilityLabel("More options")
            }
        }
        .confirmationDialog("Block \(session.displayName(for: peer))?",
                            isPresented: $showBlockConfirm, titleVisibility: .visible) {
            Button("Block", role: .destructive) { session.block(peer); dismiss() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("You won't receive messages from this person, and this chat will be removed from this device. You can unblock them later in Settings → Blocked.")
        }
        .confirmationDialog("Report \(session.displayName(for: peer))?",
                            isPresented: $showReportConfirm, titleVisibility: .visible) {
            Button("Report & Block", role: .destructive) { reportAndBlock() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Sends a report to the Logos team and blocks this person. Because chats are end-to-end encrypted, only what you choose to write in the report is shared.")
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
        .photosPicker(isPresented: $showPhotoPicker, selection: $photoItem, matching: .images)
        .onChange(of: photoItem) { item in
            guard let item else { return }
            Task {
                let data = try? await item.loadTransferable(type: Data.self)
                if let data { sendImage(data) }
                else { session.lastError = "Couldn’t load that photo — it may still be downloading from iCloud. Try again in a moment." }
                photoItem = nil
            }
        }
        .fileImporter(isPresented: $showFileImporter, allowedContentTypes: [.item], allowsMultipleSelection: false) { result in
            if case .success(let urls) = result, let url = urls.first { sendFile(url) }
        }
        .sheet(isPresented: $showAISettings) { AISettingsView() }
    }

    // MARK: - Report

    private func reportAndBlock() {
        let subject = "Logos report: \(peer)"
        let body = """
        Reporting user: \(peer)
        Reported by: \(session.username ?? "unknown")

        Reason (please describe):

        """
        let enc: (String) -> String = { $0.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "" }
        if let url = URL(string: "mailto:\(Support.reportEmail)?subject=\(enc(subject))&body=\(enc(body))") {
            openURL(url)
        }
        session.block(peer)
        dismiss()
    }

    // MARK: - Attachments

    @MainActor private func sendImage(_ data: Data) {
        guard let img = UIImage(data: data) else { session.lastError = "Couldn’t read that image."; return }
        let resized = img.resizedForSending(maxDimension: 2048)
        guard let jpeg = resized.jpegData(compressionQuality: 0.7) else { return }
        Haptic.send()
        session.sendAttachment(to: peer, data: jpeg, name: "Photo.jpg", mime: "image/jpeg", isImage: true)
    }

    @MainActor private func sendFile(_ url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        // Reject oversized files BEFORE loading them into memory: picking a multi-GB file
        // would otherwise read straight into RAM on the main thread and OOM-crash, since
        // the cap in sendAttachment only checks after the whole file is already read.
        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? 0
        guard size <= Session.attMaxBytes else {
            Haptic.warn()
            session.lastError = "That file is too large to send (max \(Session.attMaxBytes / (1024 * 1024)) MB)."
            return
        }
        guard let data = try? Data(contentsOf: url) else { session.lastError = "Couldn’t read that file."; return }
        let type = UTType(filenameExtension: url.pathExtension)
        let isImage = type?.conforms(to: .image) ?? false
        let mime = type?.preferredMIMEType ?? "application/octet-stream"
        Haptic.send()
        session.sendAttachment(to: peer, data: data, name: url.lastPathComponent, mime: mime, isImage: isImage)
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
                        MessageBubble(message: msg, markdown: msg.aiAuthor != nil) { session.retry(msg.id, in: peer) }
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
            generalErrorBanner
            aiErrorBanner
            mentionSuggestion
            Divider().background(LColor.hairline)
            HStack(alignment: .bottom, spacing: Space.xs) {
                Button { Haptic.tap(); showAttachMenu = true } label: {
                    Image(systemName: "plus")
                        .font(.system(size: 18, weight: .medium))
                        .foregroundStyle(LColor.inkSecondary)
                        .frame(width: 36, height: 36)
                }
                .accessibilityLabel("Add attachment")
                .confirmationDialog("Attach", isPresented: $showAttachMenu, titleVisibility: .hidden) {
                    Button("Photo Library") { showPhotoPicker = true }
                    Button("File") { showFileImporter = true }
                    Button("Cancel", role: .cancel) {}
                }

                TextField("Message", text: $draft, axis: .vertical)
                    .focused($composerFocused)
                    .onChange(of: draft) { _ in collapseDoubledAts() }
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

    /// Surfaces a general failure (attachment too large, couldn’t read a file/photo, a
    /// failed send) that otherwise only set session.lastError with no visible feedback.
    @ViewBuilder private var generalErrorBanner: some View {
        if let e = session.lastError {
            LBanner(tone: .danger, icon: "exclamationmark.triangle.fill",
                    title: "Couldn’t do that", message: e,
                    actionTitle: "Dismiss", action: { session.clearError() })
                .padding(.horizontal, Space.md).padding(.vertical, Space.xs)
                .transition(.move(edge: .bottom).combined(with: .opacity))
        }
    }

    /// Surfaces an in-chat @mention failure (cloud/network/etc.) instead of swallowing it.
    @ViewBuilder private var aiErrorBanner: some View {
        if let e = session.aiMentionError {
            LBanner(tone: .danger, icon: "exclamationmark.triangle.fill",
                    title: "\(aiName) couldn’t answer", message: e,
                    actionTitle: "Dismiss", action: { session.aiMentionError = nil })
                .padding(.horizontal, Space.md).padding(.vertical, Space.xs)
                .transition(.move(edge: .bottom).combined(with: .opacity))
        }
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
        var head = String(draft[..<at])
        while head.last == "@" { head.removeLast() }   // never produce "@@"
        draft = head + "@\(aiName) "
        Haptic.tap()
    }

    /// Collapse an accidental run of "@@" (the autocomplete chip landing on top of a
    /// typed "@") down to a single "@", live as the user types.
    private func collapseDoubledAts() {
        guard draft.contains("@@") else { return }
        var s = draft
        while s.contains("@@") { s = s.replacingOccurrences(of: "@@", with: "@") }
        draft = s
    }

    /// If the just-sent message tags the assistant, generate an answer for the thread
    /// (gated by cloud consent). On-device answers immediately; cloud asks once.
    private func maybeAskAI(_ text: String) {
        guard Session.mentionsAI(text, name: aiName) else { return }
        guard provider != .none else { showAISettings = true; return }   // feedback, not silence
        let question = strippedQuestion(text)
        if provider.isCloud && !AIConfig.inChatCloudConsented {
            pendingQuestion = question
            showCloudConsent = true
        } else {
            session.mentionAI(in: peer, question: question)
        }
    }
    /// Drop the mention token so the model gets just the ask — whichever form was typed
    /// ("@Logos AI", "@LogosAI", or "@Logos"). Longest-first so the full name is removed
    /// whole before the bare first word.
    private func strippedQuestion(_ text: String) -> String {
        let n = aiName.trimmingCharacters(in: .whitespaces)
        let forms = Set([n, n.replacingOccurrences(of: " ", with: ""),
                         n.split(separator: " ").first.map(String.init) ?? n])
            .filter { !$0.isEmpty }.sorted { $0.count > $1.count }
        var q = text
        for f in forms {
            if let r = q.range(of: "@" + f, options: .caseInsensitive) {
                q.removeSubrange(r)
                break
            }
        }
        return q.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

// MARK: - Message bubble

struct MessageBubble: View {
    let message: ChatMessage
    /// The 1:1 thread shows a delivery/encryption status under each outbound bubble.
    /// The local AI thread has no relay delivery, so it opts out (`showStatus: false`).
    var showStatus = true
    /// Render the body as markdown — AI replies only; user/peer text stays literal.
    var markdown = false
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
                if let s = message.sender, !message.mine {
                    Text(s)
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(LColor.goldText)
                        .padding(.horizontal, 4)
                }
                if let att = message.attachment {
                    AttachmentBubble(attachment: att, mine: message.mine, messageId: message.id)
                } else {
                    (markdown ? Text(Markdown.render(message.text)) : Text(message.text))
                        .font(LFont.body)
                        .foregroundStyle(isAI ? LColor.ink : (message.mine ? LColor.bubbleMineText : LColor.ink))
                        .padding(.horizontal, 13).padding(.vertical, 9)
                        .background(isAI ? LColor.goldWash : (message.mine ? LColor.bubbleMine : LColor.surfaceAlt))
                        .clipShape(RoundedRectangle(cornerRadius: Radius.bubble, style: .continuous))
                        .textSelection(.enabled)
                }
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

// MARK: - Attachment bubble

/// Renders a photo (tappable → full screen) or a file chip (name + size + share) for a
/// message that carries an `Attachment`. Bytes are read from the on-disk store.
private struct AttachmentBubble: View {
    @EnvironmentObject var session: Session
    let attachment: Attachment
    let mine: Bool
    let messageId: UUID
    @State private var showImage = false

    private var url: URL { session.attachmentURL(attachment.id) }
    private var exists: Bool { FileManager.default.fileExists(atPath: url.path) }

    var body: some View {
        content.overlay {
            if let p = session.attProgress[messageId] {
                ZStack {
                    RoundedRectangle(cornerRadius: Radius.bubble, style: .continuous).fill(.black.opacity(0.3))
                    Text("\(Int(p * 100))%")
                        .font(.system(size: 13, weight: .bold)).foregroundStyle(.white)
                        .padding(.horizontal, 10).padding(.vertical, 6)
                        .background(.black.opacity(0.45), in: Capsule())
                }
            }
        }
    }

    @ViewBuilder private var content: some View {
        if attachment.isImage, exists, let ui = UIImage(contentsOfFile: url.path) {
            Image(uiImage: ui)
                .resizable().scaledToFill()
                .frame(maxWidth: 230, maxHeight: 300)
                .clipShape(RoundedRectangle(cornerRadius: Radius.bubble, style: .continuous))
                .contentShape(Rectangle())
                .onTapGesture { showImage = true }
                .fullScreenCover(isPresented: $showImage) { ImageViewer(url: url) }
                .accessibilityLabel("Photo")
        } else {
            HStack(spacing: Space.sm) {
                Image(systemName: "doc.fill")
                    .font(.system(size: 18, weight: .medium)).foregroundStyle(LColor.goldText)
                    .frame(width: 36, height: 36)
                    .background(LColor.goldWash, in: RoundedRectangle(cornerRadius: 9, style: .continuous))
                VStack(alignment: .leading, spacing: 2) {
                    Text(attachment.name)
                        .font(LFont.subhead.weight(.medium))
                        .foregroundStyle(mine ? LColor.bubbleMineText : LColor.ink).lineLimit(1)
                    Text(ByteCountFormatter.string(fromByteCount: Int64(attachment.size), countStyle: .file))
                        .font(LFont.caption).foregroundStyle(LColor.inkTertiary)
                }
                if exists {
                    ShareLink(item: url) {
                        Image(systemName: "square.and.arrow.up").font(.system(size: 15)).foregroundStyle(LColor.goldText)
                    }
                }
            }
            .padding(.horizontal, 12).padding(.vertical, 10)
            .frame(maxWidth: 260)
            .background(mine ? LColor.bubbleMine : LColor.surfaceAlt)
            .clipShape(RoundedRectangle(cornerRadius: Radius.bubble, style: .continuous))
            .accessibilityLabel("File, \(attachment.name)")
        }
    }
}

/// Full-screen photo viewer with close + share.
private struct ImageViewer: View {
    @Environment(\.dismiss) private var dismiss
    let url: URL

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            if let ui = UIImage(contentsOfFile: url.path) {
                Image(uiImage: ui).resizable().scaledToFit().ignoresSafeArea()
            }
            VStack {
                HStack {
                    Button { dismiss() } label: {
                        Image(systemName: "xmark.circle.fill").font(.system(size: 28))
                            .foregroundStyle(.white.opacity(0.9)).padding()
                    }
                    Spacer()
                    ShareLink(item: url) {
                        Image(systemName: "square.and.arrow.up").font(.system(size: 22))
                            .foregroundStyle(.white.opacity(0.9)).padding()
                    }
                }
                Spacer()
            }
        }
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
        guard let (host, q) = LogosQR.parse(code), host == "add", let raw = q["u"] else { return }
        // Usernames are lowercase-only in the core; normalize so a mixed-case QR doesn't
        // create a thread whose every send fails with a cryptic validation error.
        let u = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !u.isEmpty else { return }
        if let r = q["r"], r != session.relayURL { wrongRelay = true; return }
        Haptic.tap()
        session.startConversation(with: u)
        dismiss()
    }

    private func start() {
        let name = trimmed.lowercased()
        guard !name.isEmpty else { return }
        Haptic.tap()
        session.startConversation(with: name)
        dismiss()
    }
}
