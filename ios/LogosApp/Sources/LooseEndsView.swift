import SwiftUI

// Loose Ends — a private, on-device pass over your conversations that surfaces the
// things still waiting on you: questions someone asked that you haven't answered,
// promises you made, and time-sensitive deadlines. It runs through the user's
// configured provider (on-device by default) and, like everything AI in Logos, never
// touches the relay. This first cut is intentionally EPHEMERAL: results are computed
// on demand and held only in memory, so nothing message-derived is written to disk.
// Follow-up (see docs/NEXT_LEVEL.md): persist with resolve-memory, encrypted at rest.

// MARK: - Model

enum LooseEndKind: String, Codable {
    case question, promise, deadline

    var label: String {
        switch self {
        case .question: return "They asked you"
        case .promise:  return "You said you'd"
        case .deadline: return "Time-sensitive"
        }
    }
    var icon: String {
        switch self {
        case .question: return "questionmark.bubble.fill"
        case .promise:  return "hand.raised.fill"
        case .deadline: return "alarm.fill"
        }
    }
    var tint: Color {
        switch self {
        case .question: return LColor.goldText
        case .promise:  return LColor.verified
        case .deadline: return LColor.caution
        }
    }
}

struct LooseEnd: Identifiable, Equatable, Codable {
    let id = UUID()
    let peer: String
    let kind: LooseEndKind
    let text: String
    /// Stable content key for resolve-memory — matches the same item across rescans
    /// even though `id` is fresh each time. (Computed, so it's not persisted.)
    var key: String { "\(peer.lowercased())|\(kind.rawValue)|\(text.lowercased())" }
}

// MARK: - Engine

enum LooseEnds {
    /// Build a compact transcript across the most-recent active 1:1 conversations and
    /// ask the configured model to extract loose ends. Returns [] when nothing is
    /// configured or nothing is found.
    @MainActor
    static func scan(_ session: Session,
                     maxConversations: Int = 8,
                     perConversation: Int = 16) async throws -> [LooseEnd] {
        // Only conversations that have at least one inbound message can hold a loose end.
        let peers = Array(
            session.conversations
                .filter { (session.messages[$0] ?? []).contains(where: { !$0.mine }) }
                .sorted { session.lastActivity($0) > session.lastActivity($1) }
                .prefix(maxConversations)
        )
        guard !peers.isEmpty else { return [] }

        var blocks: [String] = []
        for peer in peers {
            let recent = (session.messages[peer] ?? []).suffix(perConversation)
            guard !recent.isEmpty else { continue }
            let lines = recent
                .map { ($0.mine ? "Me" : "@\(peer)") + ": " + $0.text }
                .joined(separator: "\n")
            blocks.append("## Conversation with @\(peer)\n\(lines)")
        }
        guard !blocks.isEmpty else { return [] }
        let transcript = blocks.joined(separator: "\n\n")

        let system = """
        You scan a user's private 1:1 chats and surface "loose ends" — things still \
        waiting on the user. Find only these three kinds:
        - "question": a question someone (@username) asked the user that the user has NOT answered yet.
        - "promise": something the user ("Me") said they would do but hasn't confirmed finishing.
        - "deadline": anything time-sensitive with a date or time the user may still need to act on.
        Ignore small talk and anything resolved later in the same conversation. Never invent items.
        Respond with ONLY a JSON array — no prose, no markdown code fences. Each element is:
        {"who":"<the @username from the conversation header it came from>","kind":"question|promise|deadline","text":"<description, 12 words or fewer>"}
        If there are no loose ends, respond with exactly: []
        """
        let raw = try await AIClient.complete(system: system, user: transcript)
        return parse(raw, knownPeers: peers)
    }

    /// Defensive parse: tolerate stray prose or code fences around the JSON array, and
    /// map the model's "who" back onto a real conversation peer.
    static func parse(_ raw: String, knownPeers: [String]) -> [LooseEnd] {
        guard let data = jsonArrayData(raw),
              let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        else { return [] }

        var lookup: [String: String] = [:]
        for p in knownPeers { lookup[p.lowercased()] = p }

        var out: [LooseEnd] = []
        for o in arr {
            let text = (o["text"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !text.isEmpty else { continue }
            let kind = LooseEndKind(rawValue: (o["kind"] as? String ?? "").lowercased()) ?? .question
            let whoRaw = (o["who"] as? String ?? "")
                .lowercased()
                .trimmingCharacters(in: CharacterSet(charactersIn: "@ "))
            let peer = lookup[whoRaw] ?? knownPeers.first ?? whoRaw
            out.append(LooseEnd(peer: peer, kind: kind, text: text))
        }
        return out
    }

    /// The outermost `[...]` slice of a model response, as UTF-8 data.
    private static func jsonArrayData(_ s: String) -> Data? {
        guard let start = s.firstIndex(of: "["),
              let end = s.lastIndex(of: "]"),
              start < end
        else { return nil }
        return String(s[start...end]).data(using: .utf8)
    }
}

// MARK: - Screen

struct LooseEndsView: View {
    @EnvironmentObject var session: Session

    private enum Phase { case idle, running, done }
    @State private var phase: Phase = .idle
    @State private var errorText: String?

    private var provider: AIProvider { AIConfig.effectiveProvider }
    private var visible: [LooseEnd] { session.looseEnds }

    var body: some View {
        ScrollView {
            VStack(spacing: Space.lg) {
                switch phase {
                case .idle:    idle
                case .running: running
                case .done:    results
                }
            }
            .padding(Space.lg)
            .frame(maxWidth: 560).frame(maxWidth: .infinity)
        }
        .logosBackground(watermark: true)
        .navigationTitle("Loose ends")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { if phase == .idle && !session.looseEnds.isEmpty { phase = .done } }
    }

    // MARK: Idle

    @ViewBuilder private var idle: some View {
        if provider == .none {
            LEmptyState(icon: "checklist",
                        title: "Set up AI first",
                        message: "Loose ends are found by your AI. Turn on free on-device AI, or add your own key, in Settings → AI. Your messages never reach the Logos relay.")
        } else {
            VStack(spacing: Space.md) {
                Image(systemName: "checklist")
                    .font(.system(size: 30, weight: .light))
                    .foregroundStyle(LColor.goldText)
                    .frame(width: 84, height: 84)
                    .background(LColor.goldWash, in: Circle())
                Text("What's still waiting on you")
                    .font(LFont.title3).foregroundStyle(LColor.ink)
                Text("Logos reads your recent conversations and pulls out unanswered questions, promises you made, and anything time-sensitive — so nothing slips.")
                    .font(LFont.subhead).foregroundStyle(LColor.inkSecondary)
                    .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)

                if provider.isCloud {
                    LBanner(tone: .caution, icon: "exclamationmark.shield.fill",
                            title: "This leaves your device",
                            message: "Recent messages from your active chats are sent to \(provider.label), which can read them — that content leaves end-to-end encryption. On-device AI keeps it all private. The Logos relay is never involved either way.")
                } else {
                    LBanner(tone: .neutral, icon: "lock.shield",
                            title: "Stays on your device",
                            message: "Runs on \(provider.label). Your messages never leave this phone and never touch the relay.")
                }

                Button { Task { await run() } } label: {
                    Label("Find loose ends", systemImage: "sparkles").frame(maxWidth: .infinity)
                }
                .buttonStyle(.logosPrimary)
            }
        }
    }

    // MARK: Running

    private var running: some View {
        VStack(spacing: Space.md) {
            ProgressView()
            Text(provider.isCloud ? "Asking \(provider.label)…" : "Reading your conversations on-device…")
                .font(LFont.subhead).foregroundStyle(LColor.inkSecondary)
        }
        .frame(maxWidth: .infinity).padding(.top, Space.xxl)
    }

    // MARK: Results

    @ViewBuilder private var results: some View {
        if let e = errorText {
            VStack(spacing: Space.md) {
                LBanner(tone: .danger, icon: "exclamationmark.triangle.fill",
                        title: "Couldn't read your conversations", message: e)
                rescanButton
            }
        } else if visible.isEmpty {
            VStack(spacing: Space.lg) {
                LEmptyState(icon: "checkmark.seal.fill",
                            title: "You're all caught up",
                            message: "No unanswered questions, open promises, or looming deadlines in your recent chats.")
                rescanButton
            }
        } else {
            VStack(spacing: Space.sm) {
                HStack {
                    Text(visible.count == 1 ? "1 loose end" : "\(visible.count) loose ends")
                        .font(LFont.subhead.weight(.medium)).foregroundStyle(LColor.inkSecondary)
                    Spacer()
                    if let at = session.looseEndsScannedAt {
                        Text(at, style: .relative).font(LFont.caption).foregroundStyle(LColor.inkTertiary)
                    }
                }
                .padding(.horizontal, Space.xxs)

                ForEach(visible) { item in
                    LooseEndCard(item: item) {
                        Haptic.tap()
                        withAnimation(Motion.standard) { session.resolveLooseEnd(item) }
                    }
                }

                rescanButton.padding(.top, Space.xs)

                Text("AI can miss things or misread them — this is a nudge, not a substitute for the chat.")
                    .font(LFont.caption).foregroundStyle(LColor.inkTertiary)
                    .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity).padding(.top, Space.xxs)
            }
        }
    }

    private var rescanButton: some View {
        Button { Task { await run() } } label: {
            Label("Scan again", systemImage: "arrow.clockwise").frame(maxWidth: .infinity)
        }
        .buttonStyle(.logosSecondary)
    }

    // MARK: Run

    private func run() async {
        phase = .running
        errorText = nil
        do {
            let found = try await LooseEnds.scan(session)
            session.recordLooseEnds(found)          // persisted, sealed at rest
        } catch {
            errorText = (error as? AIError)?.errorDescription ?? error.localizedDescription
        }
        phase = .done
    }
}

/// One loose-end row: a tappable area that opens the conversation, plus a check to
/// dismiss it from the list (this session only).
private struct LooseEndCard: View {
    @EnvironmentObject var session: Session
    let item: LooseEnd
    let onDone: () -> Void

    var body: some View {
        HStack(spacing: Space.sm) {
            NavigationLink { ChatView(peer: item.peer) } label: {
                HStack(spacing: Space.sm) {
                    Image(systemName: item.kind.icon)
                        .font(.system(size: 15, weight: .medium))
                        .foregroundStyle(item.kind.tint)
                        .frame(width: 30, height: 30)
                        .background(item.kind.tint.opacity(0.12), in: Circle())
                    VStack(alignment: .leading, spacing: 2) {
                        Text(item.text).font(LFont.body).foregroundStyle(LColor.ink)
                            .fixedSize(horizontal: false, vertical: true)
                            .multilineTextAlignment(.leading)
                        Text("\(item.kind.label) · \(session.displayName(for: item.peer))")
                            .font(LFont.caption).foregroundStyle(LColor.inkTertiary)
                    }
                    Spacer(minLength: 0)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            Button(action: onDone) {
                Image(systemName: "checkmark.circle")
                    .font(.system(size: 20))
                    .foregroundStyle(LColor.goldText)
            }
            .accessibilityLabel("Mark done")
        }
        .padding(Space.md)
        .background(LColor.surface)
        .clipShape(RoundedRectangle(cornerRadius: Radius.card, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.card, style: .continuous)
            .strokeBorder(LColor.hairline, lineWidth: 1))
        .transition(.opacity.combined(with: .move(edge: .trailing)))
    }
}

/// Inbox entry point for Loose Ends. Pushed from the conversation list so tapping a
/// result can open the relevant chat in the same navigation stack.
struct LooseEndsInboxRow: View {
    var body: some View {
        HStack(spacing: Space.sm) {
            ZStack {
                Circle().fill(LColor.goldWash)
                Image(systemName: "checklist")
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(LColor.goldText)
            }
            .frame(width: 46, height: 46)
            .overlay(Circle().strokeBorder(LColor.gold.opacity(0.4), lineWidth: 1))

            VStack(alignment: .leading, spacing: 3) {
                Text("Loose ends").font(LFont.headline).fontWeight(.semibold)
                    .foregroundStyle(LColor.ink)
                Text("Unanswered questions & promises — found on-device")
                    .font(LFont.subhead).foregroundStyle(LColor.inkSecondary).lineLimit(1)
            }
            Spacer(minLength: 0)
            Image(systemName: "chevron.right").font(.system(size: 13, weight: .semibold))
                .foregroundStyle(LColor.inkTertiary)
        }
        .padding(.horizontal, Space.md).padding(.vertical, Space.sm)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Loose ends. Unanswered questions and promises, found on-device.")
    }
}
