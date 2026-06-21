import SwiftUI

/// Local, manually-managed address book. Tapping a contact starts (or reopens) a
/// chat. Nothing here is ever synced or uploaded — contacts live only on this
/// device, added by username or QR (no phone numbers, no server-side discovery).
struct ContactsView: View {
    @EnvironmentObject var session: Session
    @Environment(\.dismiss) private var dismiss
    @State private var showAdd = false

    var body: some View {
        NavigationStack {
            Group {
                if session.contacts.isEmpty {
                    LEmptyState(
                        title: "No contacts yet",
                        message: "Add people by username or QR. Your contacts live only on this device — never uploaded.")
                } else {
                    List {
                        ForEach(session.contacts, id: \.self) { c in
                            Button { message(c) } label: { row(c) }
                                .listRowBackground(LColor.surface)
                                .swipeActions(edge: .trailing) {
                                    Button(role: .destructive) { session.removeContact(c) } label: {
                                        Label("Remove", systemImage: "trash")
                                    }
                                }
                        }
                    }
                    .listStyle(.plain)
                    .scrollContentBackground(.hidden)
                }
            }
            .logosBackground()
            .navigationTitle("Contacts")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Done") { dismiss() }.foregroundStyle(LColor.inkSecondary)
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button { Haptic.tap(); showAdd = true } label: {
                        Image(systemName: "plus").foregroundStyle(LColor.goldText)
                    }
                    .accessibilityLabel("Add contact")
                }
            }
            .sheet(isPresented: $showAdd) { AddContactSheet() }
        }
    }

    private func message(_ c: String) {
        Haptic.tap()
        session.startConversation(with: c)
        dismiss() // the chat appears at the top of the conversations list
    }

    private func row(_ c: String) -> some View {
        HStack(spacing: Space.sm) {
            LAvatar(name: c, image: session.avatars[c], size: 44)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 5) {
                    Text(session.displayName(for: c)).font(LFont.headline).foregroundStyle(LColor.ink)
                    if session.security(for: c) == .verified {
                        Image(systemName: "checkmark.shield.fill")
                            .font(.system(size: 11)).foregroundStyle(LColor.verified)
                    }
                }
                if session.displayName(for: c) != c {
                    Text("@\(c)").font(LFont.caption).foregroundStyle(LColor.inkTertiary)
                }
            }
            Spacer(minLength: 0)
            Image(systemName: "bubble.left.fill")
                .font(.system(size: 13)).foregroundStyle(LColor.goldText)
        }
        .padding(.vertical, 4)
    }
}

/// Add a contact by username or by scanning their QR code.
private struct AddContactSheet: View {
    @EnvironmentObject var session: Session
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var showScan = false
    @State private var wrongRelay = false

    private var trimmed: String { name.trimmingCharacters(in: .whitespaces) }

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: Space.md) {
                Text("Add a contact by username, or scan their QR code. Stored only on this device — never uploaded.")
                    .font(LFont.subhead).foregroundStyle(LColor.inkSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 4) {
                    Text("@").font(LFont.body).foregroundStyle(LColor.inkTertiary)
                    TextField("username", text: $name)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .submitLabel(.done).onSubmit(add)
                }
                .padding(.horizontal, Space.md).padding(.vertical, 14)
                .background(LColor.surface)
                .clipShape(RoundedRectangle(cornerRadius: Radius.control, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: Radius.control, style: .continuous)
                    .strokeBorder(LColor.hairline, lineWidth: 1))

                Button("Add contact", action: add)
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
            .navigationTitle("Add contact")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Cancel") { dismiss() }.foregroundStyle(LColor.inkSecondary)
                }
            }
            .sheet(isPresented: $showScan) {
                QRScanSheet(title: "Scan to add") { handleScan($0) }
            }
            .alert("Different relay", isPresented: $wrongRelay) {
                Button("OK", role: .cancel) {}
            } message: {
                Text("That contact is on a different relay. Switch to their relay in Settings → Network to add them here.")
            }
        }
    }

    private func add() {
        guard !trimmed.isEmpty else { return }
        Haptic.tap()
        session.addContact(trimmed)
        dismiss()
    }

    private func handleScan(_ code: String) {
        guard let (host, q) = LogosQR.parse(code), host == "add", let u = q["u"] else { return }
        if let r = q["r"], r != session.relayURL { wrongRelay = true; return }
        Haptic.tap()
        session.addContact(u)
        dismiss()
    }
}
