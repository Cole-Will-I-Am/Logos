import SwiftUI

struct OnboardingView: View {
    @EnvironmentObject var session: Session
    @State private var username = ""
    @State private var relay = "http://127.0.0.1:8787"

    var body: some View {
        VStack(spacing: 18) {
            Spacer()
            Text("Logos").font(.system(size: 40, weight: .heavy))
            Text("EXPERIMENTAL — UNAUDITED.\nDo not use for real secrets.")
                .font(.footnote).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            TextField("Username", text: $username)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .textFieldStyle(.roundedBorder)
            TextField("Relay URL", text: $relay)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .textFieldStyle(.roundedBorder)

            Button("Create account") {
                session.register(username: username.trimmingCharacters(in: .whitespaces), relay: relay)
            }
            .buttonStyle(.borderedProminent)
            .disabled(username.trimmingCharacters(in: .whitespaces).isEmpty)

            Text("No phone number. By default nothing is kept on our servers — we cannot recover your messages for you.")
                .font(.caption2).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            if let e = session.lastError {
                Text(e).font(.caption).foregroundStyle(.red).multilineTextAlignment(.center)
            }
            Spacer()
        }
        .padding()
    }
}
