import SwiftUI

/// Bring-your-own-key setup. Keys are stored in the Keychain (device-only) and used to
/// call the provider directly from the phone — the Logos relay is never involved.
struct AISettingsView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var provider: AIProvider = AIConfig.provider
    @State private var newKey = ""           // entered/replacement key for the active provider
    @State private var ollamaEndpoint = AIConfig.ollamaEndpoint
    @State private var ollamaKey = ""        // optional (Ollama Cloud)
    @State private var model = ""
    @State private var testing = false
    @State private var testResult: String?
    @State private var testOK = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: Space.lg) {
                    LBanner(tone: .neutral, icon: "lock.shield",
                            title: "Your keys, your data",
                            message: "Keys are stored only on this device and are never sent to the Logos relay — calls go straight from your phone to the provider. Cloud providers (Anthropic, OpenAI) can read what you send them. Ollama on your own server (or on-device) keeps it private.")

                    field(label: "PROVIDER") {
                        Picker("Provider", selection: $provider) {
                            ForEach(AIProvider.allCases) { Text($0.label).tag($0) }
                        }
                        .pickerStyle(.menu)
                        .onChange(of: provider) { _ in model = AIConfig.model(for: provider); testResult = nil }
                    }

                    if provider.isCloud {
                        cloudKeyField
                        Text("Sending chat content here means it leaves end-to-end encryption and is read by \(provider.label). It's never sent silently — you preview and approve each time.")
                            .font(LFont.caption).foregroundStyle(LColor.caution)
                            .fixedSize(horizontal: false, vertical: true)
                    } else if provider == .ollama {
                        ollamaFields
                    }

                    if provider != .none {
                        field(label: "MODEL") {
                            TextField(provider.defaultModel, text: $model)
                                .textInputAutocapitalization(.never).autocorrectionDisabled()
                                .textFieldStyle(.roundedBorder)
                        }
                        Button { Task { await runTest() } } label: {
                            HStack { if testing { ProgressView().padding(.trailing, 4) }
                                Text(testing ? "Testing…" : "Test connection") }
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.logosSecondary)
                        .disabled(testing)
                        if let r = testResult {
                            Label(r, systemImage: testOK ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                                .font(LFont.footnote)
                                .foregroundStyle(testOK ? LColor.verified : LColor.danger)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    Button("Save", action: save).buttonStyle(.logosPrimary)
                }
                .padding(Space.lg).frame(maxWidth: 560).frame(maxWidth: .infinity)
            }
            .logosBackground()
            .navigationTitle("AI").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .topBarLeading) { Button("Done") { dismiss() } } }
            .onAppear { model = AIConfig.model(for: provider); ollamaKey = "" }
        }
    }

    @ViewBuilder private func field<C: View>(label: String, @ViewBuilder _ content: () -> C) -> some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Text(label).font(LFont.caption).fontWeight(.semibold)
                .foregroundStyle(LColor.inkTertiary).tracking(0.6)
            content()
        }
    }

    private var cloudKeyField: some View {
        field(label: "API KEY") {
            if ModelKeys.hasKey(provider) {
                Label("Key saved on this device", systemImage: "checkmark.shield.fill")
                    .font(LFont.footnote).foregroundStyle(LColor.verified)
            }
            SecureField(ModelKeys.hasKey(provider) ? "Enter a new key to replace" : "API key", text: $newKey)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                .textFieldStyle(.roundedBorder)
            if ModelKeys.hasKey(provider) {
                Button(role: .destructive) {
                    ModelKeys.setKey(nil, for: provider); newKey = ""; testResult = nil
                } label: { Text("Remove key").font(LFont.footnote) }
            }
        }
    }

    private var ollamaFields: some View {
        VStack(alignment: .leading, spacing: Space.md) {
            field(label: "ENDPOINT") {
                TextField("https://your-ollama.ts.net", text: $ollamaEndpoint)
                    .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                    .textFieldStyle(.roundedBorder)
                Text("Your own Ollama server (e.g. a Mac or VPS). Content stays between your phone and your server.")
                    .font(LFont.caption).foregroundStyle(LColor.inkTertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            field(label: "API KEY (optional, for Ollama Cloud)") {
                SecureField(ModelKeys.hasKey(.ollama) ? "Key saved — enter to replace" : "leave blank for local", text: $ollamaKey)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .textFieldStyle(.roundedBorder)
            }
        }
    }

    private func save() {
        Haptic.tap()
        AIConfig.provider = provider
        AIConfig.setModel(model, for: provider)
        if provider.isCloud, !newKey.trimmingCharacters(in: .whitespaces).isEmpty {
            ModelKeys.setKey(newKey, for: provider)
        }
        if provider == .ollama {
            AIConfig.ollamaEndpoint = ollamaEndpoint
            if !ollamaKey.trimmingCharacters(in: .whitespaces).isEmpty {
                ModelKeys.setKey(ollamaKey, for: .ollama)
            }
        }
        dismiss()
    }

    private func runTest() async {
        // Persist current entries first so AIClient sees them.
        AIConfig.provider = provider
        AIConfig.setModel(model, for: provider)
        if provider.isCloud, !newKey.trimmingCharacters(in: .whitespaces).isEmpty {
            ModelKeys.setKey(newKey, for: provider)
        }
        if provider == .ollama {
            AIConfig.ollamaEndpoint = ollamaEndpoint
            if !ollamaKey.trimmingCharacters(in: .whitespaces).isEmpty { ModelKeys.setKey(ollamaKey, for: .ollama) }
        }
        testing = true; testResult = nil
        do {
            let reply = try await AIClient.test()
            testOK = true; testResult = "Connected. Replied: \(reply.prefix(40))"
        } catch {
            testOK = false; testResult = (error as? AIError)?.errorDescription ?? error.localizedDescription
        }
        testing = false
    }
}
