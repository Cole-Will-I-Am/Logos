import SwiftUI

struct ConversationsView: View {
    @EnvironmentObject var session: Session
    @AppStorage("ai.assistantName") private var assistantName = AIConfig.defaultAssistantName
    @State private var showCompose = false
    @State private var showContacts = false
    @State private var showExperimental = true
    @State private var showArchived = false
    @State private var query = ""

    var body: some View {
        NavigationStack {
            ZStack {
                LColor.canvas.ignoresSafeArea()
                LogosWatermark(yFraction: 0.30)   // up high so it clears the centered empty-state
                content
            }
            .navigationTitle(session.username.map { "@\($0)" } ?? "Logos")
            .navigationBarTitleDisplayMode(.inline)
            .searchable(text: $query, prompt: "Search chats")
            .safeAreaInset(edge: .top) {
                if !session.online && session.username != nil {
                    OfflineBanner { session.syncNow() }
                }
            }
            .animation(Motion.standard, value: session.online)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    NavigationLink { SettingsView() } label: {
                        Image(systemName: "gearshape").foregroundStyle(LColor.ink)
                    }
                    .accessibilityLabel("Settings")
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button { Haptic.tap(); showContacts = true } label: {
                        Image(systemName: "person.2").foregroundStyle(LColor.ink)
                    }
                    .accessibilityLabel("Contacts")
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button { Haptic.tap(); showCompose = true } label: {
                        Image(systemName: "square.and.pencil").foregroundStyle(LColor.goldText)
                    }
                    .accessibilityLabel("New chat")
                }
            }
            .sheet(isPresented: $showCompose) { ComposeSheet() }
            .sheet(isPresented: $showContacts) { ContactsView() }
        }
    }

    // Pinned first, then most-recent activity.
    private func ordered(_ peers: [String]) -> [String] {
        peers.sorted { a, b in
            let pa = session.pinned.contains(a), pb = session.pinned.contains(b)
            if pa != pb { return pa }
            return session.lastActivity(a) > session.lastActivity(b)
        }
    }
    private func matches(_ peer: String) -> Bool {
        guard !query.isEmpty else { return true }
        if peer.localizedCaseInsensitiveContains(query) { return true }
        if let t = session.messages[peer]?.last?.text, t.localizedCaseInsensitiveContains(query) { return true }
        return false
    }
    private var aiName: String {
        let t = assistantName.trimmingCharacters(in: .whitespaces)
        return t.isEmpty ? AIConfig.defaultAssistantName : t
    }
    private var matchesAIRow: Bool {
        guard !query.isEmpty else { return true }
        if aiName.localizedCaseInsensitiveContains(query) { return true }
        if "ai".localizedCaseInsensitiveContains(query) || "assistant".localizedCaseInsensitiveContains(query) { return true }
        if let t = session.aiMessages.last?.text, t.localizedCaseInsensitiveContains(query) { return true }
        return false
    }
    private var visible: [String] {
        ordered(session.conversations.filter { !session.archived.contains($0) && matches($0) })
    }
    private var archivedList: [String] {
        ordered(session.conversations.filter { session.archived.contains($0) && matches($0) })
    }

    @ViewBuilder private var content: some View {
        ScrollView {
            LazyVStack(spacing: 0) {
                if showExperimental && query.isEmpty { experimentalBanner }
                if matchesAIRow { aiRow }
                ForEach(visible, id: \.self) { row($0) }
                emptyOrNoMatches
                if !archivedList.isEmpty { archivedSection }
            }
            .padding(.vertical, Space.xs)
        }
    }

    // The AI row is always available, so the centered empty state is replaced by a
    // lighter hint that sits below it.
    @ViewBuilder private var emptyOrNoMatches: some View {
        if session.conversations.isEmpty && query.isEmpty {
            LEmptyState(
                title: "No conversations yet",
                message: "Start one with a username — your messages are end-to-end encrypted from the very first hello.")
                .padding(.top, Space.md)
        } else if visible.isEmpty && !matchesAIRow {
            Text(query.isEmpty ? "No active conversations" : "No matches")
                .font(LFont.subhead).foregroundStyle(LColor.inkTertiary)
                .frame(maxWidth: .infinity).padding(Space.xl)
        }
    }

    @ViewBuilder private var aiRow: some View {
        NavigationLink { AIChatView() } label: { AIInboxRow() }
            .buttonStyle(.plain)
        Divider().background(LColor.hairline).padding(.leading, 78)
    }

    private var experimentalBanner: some View {
        LBanner(tone: .neutral, icon: "flask.fill",
                title: "Experimental build",
                message: "Not security audited. Fine to explore — don’t trust it with real secrets yet.",
                actionTitle: "Dismiss",
                action: { withAnimation(Motion.standard) { showExperimental = false } })
        .padding(.horizontal, Space.md).padding(.top, Space.sm)
    }

    @ViewBuilder private func row(_ peer: String) -> some View {
        NavigationLink { ChatView(peer: peer) } label: { ConversationRow(peer: peer) }
            .buttonStyle(.plain)
            .contextMenu { rowMenu(peer) }
        Divider().background(LColor.hairline).padding(.leading, 78)
    }

    @ViewBuilder private func rowMenu(_ peer: String) -> some View {
        Button { session.togglePin(peer) } label: {
            Label(session.pinned.contains(peer) ? "Unpin" : "Pin",
                  systemImage: session.pinned.contains(peer) ? "pin.slash" : "pin")
        }
        Button { session.toggleArchive(peer) } label: {
            Label(session.archived.contains(peer) ? "Unarchive" : "Archive", systemImage: "archivebox")
        }
        if (session.unread[peer] ?? 0) > 0 {
            Button { session.markRead(peer) } label: { Label("Mark as read", systemImage: "checkmark.circle") }
        }
        Button { UIPasteboard.general.string = peer; Haptic.tap() } label: {
            Label("Copy username", systemImage: "doc.on.doc")
        }
        Divider()
        Button(role: .destructive) { session.deleteConversation(peer) } label: {
            Label("Delete chat", systemImage: "trash")
        }
    }

    @ViewBuilder private var archivedSection: some View {
        Button { withAnimation(Motion.standard) { showArchived.toggle() } } label: {
            HStack(spacing: 6) {
                Image(systemName: "archivebox").font(.system(size: 13))
                Text("Archived (\(archivedList.count))").font(LFont.subhead.weight(.medium))
                Spacer()
                Image(systemName: showArchived ? "chevron.up" : "chevron.down")
                    .font(.system(size: 11, weight: .semibold))
            }
            .foregroundStyle(LColor.inkSecondary)
            .padding(.horizontal, Space.md).padding(.vertical, Space.sm)
        }
        if showArchived {
            ForEach(archivedList, id: \.self) { row($0) }
        }
    }
}

private struct ConversationRow: View {
    @EnvironmentObject var session: Session
    let peer: String

    private var last: ChatMessage? { session.messages[peer]?.last }
    private var security: SessionSecurity { session.security(for: peer) }
    private var unread: Int { session.unread[peer] ?? 0 }
    private var pinned: Bool { session.pinned.contains(peer) }

    var body: some View {
        HStack(spacing: Space.sm) {
            LAvatar(name: peer, image: session.avatars[peer])
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    if pinned {
                        Image(systemName: "pin.fill").font(.system(size: 10)).foregroundStyle(LColor.inkTertiary)
                    }
                    Text(session.displayName(for: peer)).font(LFont.headline).fontWeight(unread > 0 ? .bold : .semibold)
                        .foregroundStyle(LColor.ink).lineLimit(1)
                    securityGlyph
                    Spacer(minLength: 0)
                    if let at = last?.at {
                        Text(at, style: .time).font(LFont.caption).foregroundStyle(LColor.inkTertiary)
                    }
                }
                Text(preview)
                    .font(LFont.subhead).fontWeight(unread > 0 ? .medium : .regular)
                    .foregroundStyle(unread > 0 ? LColor.ink : LColor.inkSecondary)
                    .lineLimit(1)
            }
            if unread > 0 {
                Text("\(min(unread, 99))")
                    .font(.system(size: 12, weight: .bold)).foregroundStyle(LColor.onGold)
                    .padding(.horizontal, 7).padding(.vertical, 2)
                    .background(LColor.gold, in: Capsule())
            }
        }
        .padding(.horizontal, Space.md).padding(.vertical, Space.sm)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(peer)\(unread > 0 ? ", \(unread) unread" : "")\(security == .identityChanged ? ", identity changed" : ""), \(preview)")
    }

    // Quiet by default — only show a glyph when it carries information.
    @ViewBuilder private var securityGlyph: some View {
        switch security {
        case .verified:        SecurityChip(level: .verified, compact: true)
        case .identityChanged: SecurityChip(level: .changed,  compact: true)
        case .encrypted:       EmptyView()
        }
    }

    private var preview: String {
        guard let last else { return "Tap to start the conversation" }
        switch last.status {
        case .blocked: return "⚠︎ Identity could not be verified"
        case .failed:  return "Not delivered"
        default:
            let prefix = last.mine ? "You: " : ""
            if let att = last.attachment {
                return prefix + (att.isImage ? "📷 Photo" : "📎 " + att.name)
            }
            return prefix + last.text
        }
    }
}

/// The pinned "AI assistant" entry at the top of the inbox. Distinct from a person
/// (gold sparkle avatar, "AI" chip, user-chosen name); opens `AIChatView`.
private struct AIInboxRow: View {
    @EnvironmentObject var session: Session
    @AppStorage("ai.assistantName") private var assistantName = AIConfig.defaultAssistantName

    private var name: String {
        let t = assistantName.trimmingCharacters(in: .whitespaces)
        return t.isEmpty ? AIConfig.defaultAssistantName : t
    }
    private var last: ChatMessage? { session.aiMessages.last }
    private var preview: String {
        if session.aiPending { return "Thinking…" }
        guard let last else { return "Ask me anything — private by default" }
        return (last.mine ? "You: " : "") + last.text
    }

    var body: some View {
        HStack(spacing: Space.sm) {
            ZStack {
                Circle().fill(LColor.gold)
                Image(systemName: "sparkles")
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundStyle(LColor.onGold)
            }
            .frame(width: 46, height: 46)
            .overlay(Circle().strokeBorder(LColor.gold.opacity(0.5), lineWidth: 1))

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(name).font(LFont.headline).fontWeight(.semibold)
                        .foregroundStyle(LColor.ink).lineLimit(1)
                    Text("AI").font(.system(size: 10, weight: .bold))
                        .foregroundStyle(LColor.goldText)
                        .padding(.horizontal, 5).padding(.vertical, 1)
                        .background(LColor.goldWash, in: Capsule())
                    Spacer(minLength: 0)
                    if let at = last?.at {
                        Text(at, style: .time).font(LFont.caption).foregroundStyle(LColor.inkTertiary)
                    }
                }
                Text(preview)
                    .font(LFont.subhead).foregroundStyle(LColor.inkSecondary)
                    .lineLimit(1)
            }
        }
        .padding(.horizontal, Space.md).padding(.vertical, Space.sm)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(name), AI assistant. \(preview)")
    }
}
