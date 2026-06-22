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
    @FocusState private var composerFocused: Bool

    private var key: String { Session.groupKey(groupId) }
    private var msgs: [ChatMessage] { session.groupMessages(groupId) }
    private var info: GroupInfo? { session.group(groupId) }
    private var title: String { info?.name ?? "Group" }
    private var memberCount: Int { info?.members.count ?? 0 }

    var body: some View {
        VStack(spacing: 0) { thread; composer }
            .logosBackground(watermark: true)
            .safeAreaInset(edge: .top) { if !session.online { OfflineBanner { session.syncNow() } } }
            .animation(Motion.standard, value: session.online)
            .navigationBarTitleDisplayMode(.inline)
            .onAppear { session.setActive(key) }
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
    }

    private var thread: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: Space.xs) {
                    intro
                    ForEach(msgs) { msg in
                        MessageBubble(message: msg) { session.retryGroup(msg.id, in: groupId) }
                            .id(msg.id)
                    }
                }
                .padding(.horizontal, Space.md).padding(.vertical, Space.sm)
            }
            .scrollDismissesKeyboard(.interactively)
            .onChange(of: msgs.count) { _ in
                if let last = msgs.last { withAnimation(Motion.standard) { proxy.scrollTo(last.id, anchor: .bottom) } }
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
            Divider().background(LColor.hairline)
            HStack(alignment: .bottom, spacing: Space.xs) {
                TextField("Message", text: $draft, axis: .vertical)
                    .focused($composerFocused).lineLimit(1...6).font(LFont.body)
                    .padding(.horizontal, Space.sm).padding(.vertical, 9)
                    .background(LColor.surfaceAlt)
                    .clipShape(RoundedRectangle(cornerRadius: Radius.bubble, style: .continuous))
                Button {
                    let t = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !t.isEmpty else { return }
                    draft = ""; Haptic.send(); session.sendToGroup(groupId, text: t)
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
