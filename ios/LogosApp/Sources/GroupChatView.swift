import SwiftUI
import LogosKit

/// An E2EE group conversation. Mirrors `ChatView` but for the group sender-key thread:
/// messages are attributed to their sender, sent via `Session.sendToGroup`, and the
/// header opens member management. The relay never sees group content.
struct GroupChatView: View {
    @EnvironmentObject var session: Session
    let groupId: String
    @State private var draft = ""
    @State private var showInfo = false
    @AppStorage("ai.assistantName") private var assistantName = AIConfig.defaultAssistantName
    @State private var showCloudConsent = false
    @State private var pendingQuestion = ""
    @State private var showAISettings = false
    @FocusState private var composerFocused: Bool

    private var key: String { Session.groupKey(groupId) }
    private var msgs: [ChatMessage] { session.groupMessages(groupId) }
    private var info: GroupInfo? { session.group(groupId) }
    private var title: String { info?.name ?? "Group" }
    private var memberCount: Int { info?.members.count ?? 0 }
    private var provider: AIProvider { AIConfig.effectiveProvider }
    private var aiName: String {
        let t = assistantName.trimmingCharacters(in: .whitespaces)
        return t.isEmpty ? AIConfig.defaultAssistantName : t
    }

    var body: some View {
        VStack(spacing: 0) { thread; composer }
            .logosBackground(watermark: true)
            .safeAreaInset(edge: .top) { if !session.online { OfflineBanner { session.syncNow() } } }
            .animation(Motion.standard, value: session.online)
            .navigationBarTitleDisplayMode(.inline)
            .onAppear { session.setActive(key); session.aiMentionError = nil }
            .onDisappear { session.setActive(nil) }
            .toolbar {
                ToolbarItem(placement: .principal) {
                    Button { showInfo = true } label: {
                        VStack(spacing: 1) {
                            Text(title).font(LFont.headline).foregroundStyle(LColor.ink)
                            Text("\(memberCount) member\(memberCount == 1 ? "" : "s") · end-to-end encrypted")
                                .font(.system(size: 11)).foregroundStyle(LColor.inkTertiary)
                        }
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showInfo = true } label: {
                        Image(systemName: "person.2.circle").foregroundStyle(LColor.goldText)
                    }
                    .accessibilityLabel("Group info")
                }
            }
            .sheet(isPresented: $showInfo) { GroupInfoView(groupId: groupId).environmentObject(session) }
            .sheet(isPresented: $showAISettings) { AISettingsView() }
            .alert("Use \(aiName) in this group?", isPresented: $showCloudConsent) {
                Button("Allow once") { session.mentionAIInGroup(in: groupId, question: pendingQuestion) }
                Button("Allow & don’t ask again") {
                    AIConfig.inChatCloudConsented = true
                    session.mentionAIInGroup(in: groupId, question: pendingQuestion)
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("The group’s recent messages will be sent to \(provider.label) to answer, leaving end-to-end encryption (the Logos relay still never sees them). On-device AI keeps everything private.")
            }
    }

    private var thread: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: Space.xs) {
                    intro
                    ForEach(msgs) { msg in
                        MessageBubble(message: msg, markdown: msg.aiAuthor != nil) { session.retryGroup(msg.id, in: groupId) }
                            .id(msg.id)
                    }
                    if session.aiMentionPending.contains(key) { TypingBubble().id("ai-typing") }
                }
                .padding(.horizontal, Space.md).padding(.vertical, Space.sm)
            }
            .scrollDismissesKeyboard(.interactively)
            .onChange(of: msgs.count) { _ in
                if let last = msgs.last { withAnimation(Motion.standard) { proxy.scrollTo(last.id, anchor: .bottom) } }
            }
            .onChange(of: session.aiMentionPending) { _ in
                if session.aiMentionPending.contains(key) {
                    withAnimation(Motion.standard) { proxy.scrollTo("ai-typing", anchor: .bottom) }
                }
            }
            .onAppear { if let last = msgs.last { proxy.scrollTo(last.id, anchor: .bottom) } }
        }
    }

    @ViewBuilder private var intro: some View {
        if msgs.isEmpty {
            VStack(spacing: Space.xs) {
                Image(systemName: "person.3.fill").font(.system(size: 15)).foregroundStyle(LColor.goldText)
                Text("**\(title)** is end-to-end encrypted.")
                    .font(LFont.footnote).foregroundStyle(LColor.inkSecondary)
                Text("Messages are encrypted for each member — the Logos relay can’t read them.")
                    .font(LFont.caption).foregroundStyle(LColor.inkTertiary)
                    .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity).padding(Space.md)
            .background(LColor.goldWash.opacity(0.5))
            .clipShape(RoundedRectangle(cornerRadius: Radius.card, style: .continuous))
            .padding(.bottom, Space.xs)
        }
    }

    private var composer: some View {
        VStack(spacing: 0) {
            aiErrorBanner
            mentionSuggestion
            Divider().background(LColor.hairline)
            HStack(alignment: .bottom, spacing: Space.xs) {
                TextField("Message", text: $draft, axis: .vertical)
                    .focused($composerFocused).lineLimit(1...6).font(LFont.body)
                    .onChange(of: draft) { _ in collapseDoubledAts() }
                    .padding(.horizontal, Space.sm).padding(.vertical, 9)
                    .background(LColor.surfaceAlt)
                    .clipShape(RoundedRectangle(cornerRadius: Radius.bubble, style: .continuous))
                Button {
                    let t = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !t.isEmpty else { return }
                    draft = ""; Haptic.send(); session.sendToGroup(groupId, text: t)
                    maybeAskAI(t)
                } label: {
                    Image(systemName: "arrow.up").font(.system(size: 16, weight: .bold))
                        .foregroundStyle(LColor.onGold).frame(width: 36, height: 36)
                        .background(canSend ? LColor.gold : LColor.gold.opacity(0.35), in: Circle())
                }
                .disabled(!canSend).animation(Motion.micro, value: canSend).accessibilityLabel("Send")
            }
            .padding(.horizontal, Space.sm).padding(.vertical, Space.xs).background(LColor.canvas)
        }
    }
    private var canSend: Bool { !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

    // MARK: - In-chat @mention (group)

    /// The text after the last "@" the user is currently typing (nil if none / spans a newline).
    private var mentionFragment: String? {
        guard let at = draft.lastIndex(of: "@") else { return nil }
        let frag = String(draft[draft.index(after: at)...])
        return frag.contains("\n") ? nil : frag
    }
    private var showMentionSuggestion: Bool {
        guard provider != .none, let frag = mentionFragment else { return false }
        if Session.mentionsAI(draft, name: aiName) { return false }
        return aiName.lowercased().hasPrefix(frag.lowercased())
    }

    /// Surfaces an in-group @mention failure (provider/network/etc.) instead of swallowing it.
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
                        Text("Ask your AI here — everyone in the group sees the reply")
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
    /// Collapse an accidental run of "@@" down to a single "@", live as the user types.
    private func collapseDoubledAts() {
        guard draft.contains("@@") else { return }
        var s = draft
        while s.contains("@@") { s = s.replacingOccurrences(of: "@@", with: "@") }
        draft = s
    }

    /// If the just-sent message tags the assistant, generate a group answer (gated by cloud
    /// consent). On-device/Ollama answer immediately; cloud asks once. An empty question is
    /// allowed — it means "weigh in on the conversation".
    private func maybeAskAI(_ text: String) {
        guard Session.mentionsAI(text, name: aiName) else { return }
        guard provider != .none else { showAISettings = true; return }
        let question = strippedQuestion(text)
        if provider.isCloud && !AIConfig.inChatCloudConsented {
            pendingQuestion = question
            showCloudConsent = true
        } else {
            session.mentionAIInGroup(in: groupId, question: question)
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

// MARK: - Group info / member management

struct GroupInfoView: View {
    @EnvironmentObject var session: Session
    @Environment(\.dismiss) private var dismiss
    let groupId: String
    @State private var showAdd = false
    @State private var addName = ""
    @State private var showRename = false
    @State private var renameDraft = ""

    private var info: GroupInfo? { session.group(groupId) }
    private var isAdmin: Bool { session.isGroupAdmin(groupId) }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: Space.lg) {
                    if let info {
                        LBanner(tone: .neutral, icon: "lock.fill", title: info.name,
                                message: "End-to-end encrypted group · \(info.members.count) members. The relay can’t read messages.")
                        VStack(alignment: .leading, spacing: Space.xs) {
                            Text("MEMBERS").font(LFont.caption).fontWeight(.semibold)
                                .foregroundStyle(LColor.inkTertiary).tracking(0.6)
                            ForEach(info.members, id: \.self) { m in
                                HStack(spacing: Space.sm) {
                                    LAvatar(name: m, size: 34)
                                    Text(m == session.username ? "\(m) (you)" : m)
                                        .font(LFont.body).foregroundStyle(LColor.ink).lineLimit(1)
                                    if info.admins.contains(m) {
                                        Text("admin").font(LFont.caption).foregroundStyle(LColor.goldText)
                                    }
                                    Spacer(minLength: 0)
                                    if isAdmin, m != session.username {
                                        Button(role: .destructive) { session.removeFromGroup(groupId, m) } label: {
                                            Image(systemName: "minus.circle.fill").foregroundStyle(LColor.danger)
                                        }
                                        .accessibilityLabel("Remove \(m)")
                                    }
                                }
                                .padding(.vertical, 3)
                            }
                        }
                        if isAdmin {
                            Button { addName = ""; showAdd = true } label: {
                                Label("Add member", systemImage: "person.badge.plus").frame(maxWidth: .infinity)
                            }.buttonStyle(.logosSecondary)
                            Button { renameDraft = info.name; showRename = true } label: {
                                Label("Rename group", systemImage: "pencil").frame(maxWidth: .infinity)
                            }.buttonStyle(.logosSecondary)
                        } else {
                            Text("Only group admins can add or remove members.")
                                .font(LFont.caption).foregroundStyle(LColor.inkTertiary)
                        }
                    } else {
                        LEmptyState(icon: "person.3", title: "Group unavailable",
                                    message: "This group is no longer available on this device.")
                    }
                }
                .padding(Space.lg).frame(maxWidth: 560).frame(maxWidth: .infinity)
            }
            .logosBackground()
            .navigationTitle("Group info").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .topBarTrailing) { Button("Done") { dismiss() } } }
            .alert("Add member", isPresented: $showAdd) {
                TextField("username", text: $addName)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                Button("Cancel", role: .cancel) {}
                Button("Add") {
                    let u = addName.trimmingCharacters(in: .whitespaces).lowercased()
                    if !u.isEmpty { session.addToGroup(groupId, u) }
                }
            } message: {
                Text("Add someone by their Logos username. They’ll receive the group and messages from now on.")
            }
            .alert("Rename group", isPresented: $showRename) {
                TextField("Group name", text: $renameDraft)
                Button("Cancel", role: .cancel) {}
                Button("Save") {
                    let n = renameDraft.trimmingCharacters(in: .whitespaces)
                    if !n.isEmpty { session.renameGroupChat(groupId, n) }
                }
            }
        }
    }
}

// MARK: - New group

struct NewGroupSheet: View {
    @EnvironmentObject var session: Session
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var selected: Set<String> = []

    private var canCreate: Bool {
        !name.trimmingCharacters(in: .whitespaces).isEmpty && !selected.isEmpty
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: Space.md) {
                    field("GROUP NAME") {
                        TextField("e.g. Weekend trip", text: $name).textFieldStyle(.roundedBorder)
                    }
                    field("MEMBERS") {
                        if session.contacts.isEmpty {
                            Text("Add contacts first — you invite people to a group by their username.")
                                .font(LFont.subhead).foregroundStyle(LColor.inkSecondary)
                                .fixedSize(horizontal: false, vertical: true)
                        } else {
                            ForEach(session.contacts, id: \.self) { c in
                                Button {
                                    if selected.contains(c) { selected.remove(c) } else { selected.insert(c) }
                                } label: {
                                    HStack(spacing: Space.sm) {
                                        LAvatar(name: c, image: session.avatars[c], size: 34)
                                        Text(session.displayName(for: c)).font(LFont.body).foregroundStyle(LColor.ink)
                                        Spacer(minLength: 0)
                                        Image(systemName: selected.contains(c) ? "checkmark.circle.fill" : "circle")
                                            .foregroundStyle(selected.contains(c) ? LColor.gold : LColor.inkTertiary)
                                    }
                                    .padding(.vertical, 4).contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                    Button("Create group") {
                        Haptic.tap()
                        session.createGroup(name: name.trimmingCharacters(in: .whitespaces),
                                            members: Array(selected))
                        dismiss()
                    }
                    .buttonStyle(.logosPrimary).disabled(!canCreate)
                }
                .padding(Space.lg).frame(maxWidth: 560).frame(maxWidth: .infinity)
            }
            .logosBackground()
            .navigationTitle("New group").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .topBarTrailing) { Button("Cancel") { dismiss() } } }
        }
    }

    @ViewBuilder private func field<C: View>(_ label: String, @ViewBuilder _ content: () -> C) -> some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Text(label).font(LFont.caption).fontWeight(.semibold)
                .foregroundStyle(LColor.inkTertiary).tracking(0.6)
            content()
        }
    }
}
