import SwiftUI

struct ChatView: View {
    @EnvironmentObject var session: Session
    let peer: String
    @State private var draft = ""

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 8) {
                    ForEach(session.messages[peer] ?? []) { msg in
                        HStack {
                            if msg.mine { Spacer(minLength: 40) }
                            Text(msg.text)
                                .padding(10)
                                .background(msg.mine ? Color.accentColor.opacity(0.2) : Color.gray.opacity(0.15))
                                .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                            if !msg.mine { Spacer(minLength: 40) }
                        }
                        .frame(maxWidth: .infinity, alignment: msg.mine ? .trailing : .leading)
                    }
                }
                .padding()
            }
            Divider()
            HStack {
                TextField("Message", text: $draft, axis: .vertical)
                    .textFieldStyle(.roundedBorder)
                Button {
                    let t = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                    draft = ""
                    guard !t.isEmpty else { return }
                    session.send(to: peer, text: t)
                } label: {
                    Image(systemName: "arrow.up.circle.fill").font(.title2)
                }
                .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .padding()
        }
        .navigationTitle(peer)
        .navigationBarTitleDisplayMode(.inline)
    }
}
