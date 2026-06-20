import SwiftUI

struct ConversationsView: View {
    @EnvironmentObject var session: Session
    @State private var showCompose = false
    @State private var showExperimental = true

    var body: some View {
        NavigationStack {
            ZStack {
                LColor.canvas.ignoresSafeArea()
                content
            }
            .navigationTitle(session.username.map { "@\($0)" } ?? "Logos")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    NavigationLink { SettingsView() } label: {
                        Image(systemName: "gearshape").foregroundStyle(LColor.ink)
                    }
                    .accessibilityLabel("Settings")
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button { Haptic.tap(); showCompose = true } label: {
                        Image(systemName: "square.and.pencil").foregroundStyle(LColor.goldText)
                    }
                    .accessibilityLabel("New chat")
                }
            }
            .sheet(isPresented: $showCompose) { ComposeSheet() }
        }
    }

    @ViewBuilder private var content: some View {
        if session.conversations.isEmpty {
            LEmptyState(
                icon: "bubble.left.and.text.bubble.right",
                title: "No conversations yet",
                message: "Start one with a username — your messages are end-to-end encrypted from the very first hello.",
                actionTitle: "New chat",
                action: { showCompose = true }
            )
        } else {
            ScrollView {
                LazyVStack(spacing: 0) {
                    if showExperimental {
                        LBanner(tone: .neutral, icon: "flask.fill",
                                title: "Experimental build",
                                message: "Not security audited. Fine to explore — don’t trust it with real secrets yet.",
                                actionTitle: "Dismiss",
                                action: { withAnimation(Motion.standard) { showExperimental = false } })
                        .padding(.horizontal, Space.md).padding(.top, Space.sm)
                    }
                    ForEach(session.conversations, id: \.self) { peer in
                        NavigationLink { ChatView(peer: peer) } label: {
                            ConversationRow(peer: peer)
                        }
                        .buttonStyle(.plain)
                        if peer != session.conversations.last {
                            Divider().background(LColor.hairline).padding(.leading, 78)
                        }
                    }
                }
                .padding(.vertical, Space.xs)
            }
        }
    }
}

private struct ConversationRow: View {
    @EnvironmentObject var session: Session
    let peer: String

    private var last: ChatMessage? { session.messages[peer]?.last }
    private var security: SessionSecurity { session.security(for: peer) }

    var body: some View {
        HStack(spacing: Space.sm) {
            LAvatar(name: peer)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(peer).font(LFont.headline).foregroundStyle(LColor.ink).lineLimit(1)
                    securityGlyph
                    Spacer(minLength: 0)
                    if let at = last?.at {
                        Text(at, style: .time)
                            .font(LFont.caption).foregroundStyle(LColor.inkTertiary)
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
        .accessibilityLabel("\(peer), \(security == .identityChanged ? "identity changed, " : "")\(preview)")
    }

    // (timestamps shown via Text(date, style: .time))

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
        default:       return (last.mine ? "You: " : "") + last.text
        }
    }
}
