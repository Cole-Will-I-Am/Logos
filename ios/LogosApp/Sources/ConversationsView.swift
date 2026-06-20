import SwiftUI

struct ConversationsView: View {
    @EnvironmentObject var session: Session
    @State private var newPeer = ""

    var body: some View {
        NavigationStack {
            List {
                Section("New chat") {
                    HStack {
                        TextField("username", text: $newPeer)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        Button("Start") {
                            let p = newPeer.trimmingCharacters(in: .whitespaces)
                            guard !p.isEmpty else { return }
                            session.startConversation(with: p)
                            newPeer = ""
                        }
                        .disabled(newPeer.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                }
                Section("Chats") {
                    if session.conversations.isEmpty {
                        Text("No conversations yet.").foregroundStyle(.secondary)
                    }
                    ForEach(session.conversations, id: \.self) { peer in
                        NavigationLink(peer) { ChatView(peer: peer) }
                    }
                }
            }
            .navigationTitle(session.username ?? "Logos")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    NavigationLink { SettingsView() } label: { Image(systemName: "gearshape") }
                }
            }
        }
    }
}
