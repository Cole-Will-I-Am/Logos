import SwiftUI

/// "Catch me up" — summarize a 1:1 chat with the user's configured provider, with an
/// explicit preview + consent step (and a clear "this leaves your device" warning for
/// cloud providers) before any content is sent. The relay is never involved.
struct AICatchUpSheet: View {
    @EnvironmentObject var session: Session
    @Environment(\.dismiss) private var dismiss
    let peer: String

    private enum Phase { case notConfigured, consent, running, done }
    @State private var phase: Phase = .consent
    @State private var summary = ""
    @State private var errorText: String?

    private var recent: [ChatMessage] { Array((session.messages[peer] ?? []).suffix(60)) }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: Space.lg) {
                    switch phase {
                    case .notConfigured: notConfigured
                    case .consent: consent
                    case .running: ProgressView("Summarizing…").frame(maxWidth: .infinity).padding(.top, Space.xl)
                    case .done: result
                    }
                }
                .padding(Space.lg).frame(maxWidth: 560).frame(maxWidth: .infinity)
            }
            .logosBackground()
            .navigationTitle("Catch me up").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .topBarTrailing) { Button("Done") { dismiss() } } }
            .onAppear { if !AIConfig.configured { phase = .notConfigured } }
        }
    }

    private var consent: some View {
        let p = AIConfig.effectiveProvider
        return VStack(alignment: .leading, spacing: Space.md) {
            if p.isCloud {
                LBanner(tone: .caution, icon: "exclamationmark.shield.fill",
                        title: "This leaves your device",
                        message: "Summarizing sends the last \(recent.count) messages — including \(session.displayName(for: peer))'s — to \(p.label), which can read them. That content leaves end-to-end encryption. The Logos relay is never involved.")
            } else {
                LBanner(tone: .neutral, icon: "lock.shield",
                        title: "Stays private",
                        message: "Summarizing runs on \(p.label) — content stays between your device and your own server; it never reaches the Logos relay or a third party.")
            }
            Text("\(recent.count) messages will be summarized.")
                .font(LFont.subhead).foregroundStyle(LColor.inkSecondary)
            Button("Summarize") { Task { await run() } }
                .buttonStyle(.logosPrimary).disabled(recent.isEmpty)
        }
    }

    private var result: some View {
        VStack(alignment: .leading, spacing: Space.md) {
            if let e = errorText {
                LBanner(tone: .danger, icon: "exclamationmark.triangle.fill",
                        title: "Couldn't summarize", message: e)
            } else {
                Text(Markdown.render(summary)).font(LFont.body).foregroundStyle(LColor.ink)
                    .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                Text("AI summaries can be wrong — check the chat for anything important.")
                    .font(LFont.caption).foregroundStyle(LColor.inkTertiary)
            }
        }
    }

    private var notConfigured: some View {
        LEmptyState(icon: "sparkles", title: "Set up AI first",
                    message: "Add your own Anthropic, OpenAI, or Ollama key in Settings → AI to use catch-up summaries. Your key stays on this device.")
    }

    private func run() async {
        phase = .running
        let convo = recent
            .map { ($0.mine ? "Me" : session.displayName(for: peer)) + ": " + $0.text }
            .joined(separator: "\n")
        let system = """
        You summarize a private 1:1 chat for someone catching up. Be concise. Surface, as \
        short bullets: open questions directed at the user, decisions, action items / \
        commitments, and anything time-sensitive. Do not invent anything not in the messages.
        """
        do {
            summary = try await AIClient.complete(system: system, user: convo)
            errorText = nil
        } catch {
            errorText = (error as? AIError)?.errorDescription ?? error.localizedDescription
        }
        phase = .done
    }
}
