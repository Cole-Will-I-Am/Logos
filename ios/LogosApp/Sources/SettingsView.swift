import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var session: Session

    var body: some View {
        List {
            Section("Account") {
                LabeledContent("Username", value: session.username ?? "—")
                LabeledContent("Relay", value: session.relayURL)
            }
            Section {
                Text("Logos is EXPERIMENTAL and UNAUDITED. The protocol has not been "
                   + "independently audited — do not use it for anything you actually need to keep secret.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Settings")
        .navigationBarTitleDisplayMode(.inline)
    }
}
