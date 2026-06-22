import SwiftUI

/// The user's private AI assistant as a normal-feeling chat thread. Replies come from
/// the provider chosen in Settings → AI (on-device by default), called directly from
/// the device — the Logos relay is never in the path. Reuses `MessageBubble` so it
/// reads like a 1:1 chat, but carries none of the identity/TOFU machinery (an assistant
/// has no safety number to verify), which is why it's a separate view from `ChatView`.
struct AIChatView: View {
    @EnvironmentObject var session: Session
    @AppStorage("ai.assistantName") private var assistantName = AIConfig.defaultAssistantName
    @State private var draft = ""
    @State private var showSettings = false
    @State private var showRename = false
    @State private var nameDraft = ""
    @FocusState private var composerFocused: Bool

    private var msgs: [ChatMessage] { session.aiMessages }
    private var provider: AIProvider { AIConfig.effectiveProvider }
    private var name: String {
        let t = assistantName.trimmingCharacters(in: .whitespaces)
        return t.isEmpty ? AIConfig.defaultAssistantName : t
    }

    var body: some View {
        VStack(spacing: 0) {
            thread
            composer
        }
        .logosBackground(watermark: true)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .principal) {
                VStack(spacing: 1) {
                    Text(name).font(LFont.headline).foregroundStyle(LColor.ink)
                    titleStatus
                }
            }
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button { nameDraft = name; showRename = true } label: {
                        Label("Rename assistant", systemImage: "pencil")
                    }
                    Button { showSettings = true } label: {
                        Label("AI settings", systemImage: "slider.horizontal.3")
                    }
                    if !msgs.isEmpty {
                        Divider()
                        Button(role: .destructive) { Haptic.warn(); session.clearAIConversation() } label: {
                            Label("Clear conversation", systemImage: "trash")
                        }
                    }
                } label: {
                    Image(systemName: "ellipsis.circle").foregroundStyle(LColor.goldText)
                }
                .accessibilityLabel("Assistant options")
            }
        }
        .sheet(isPresented: $showSettings) { AISettingsView() }
        .alert("Name your assistant", isPresented: $showRename) {
            TextField(AIConfig.defaultAssistantName, text: $nameDraft)
            Button("Cancel", role: .cancel) {}
            Button("Save") {
                let t = nameDraft.trimmingCharacters(in: .whitespaces)
                assistantName = t.isEmpty ? AIConfig.defaultAssistantName : t
            }
        } message: {
            Text("Give your AI a name. It’s shown here and in your chat list — on this device only.")
        }
    }

    // Tiny, quiet status under the title: who answers, and whether it stays on-device.
    @ViewBuilder private var titleStatus: some View {
        if provider.isCloud {
            Label("via \(provider.label)", systemImage: "cloud")
                .labelStyle(.titleAndIcon)
                .font(.system(size: 11)).foregroundStyle(LColor.inkTertiary)
        } else {
            Label("Private · on your device", systemImage: "lock.fill")
                .labelStyle(.titleAndIcon)
                .font(.system(size: 11)).foregroundStyle(LColor.inkTertiary)
        }
    }

    private var thread: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: Space.xs) {
                    intro
                    ForEach(msgs) { msg in
                        MessageBubble(message: msg, showStatus: false, markdown: !msg.mine) {}
                            .id(msg.id)
                    }
                    if session.aiPending { TypingBubble().id("typing") }
                    if let e = session.aiError {
                        LBanner(tone: .danger, icon: "exclamationmark.triangle.fill",
                                title: "Couldn’t get a reply", message: e,
                                actionTitle: needsSetup ? "Set up AI" : nil,
                                action: needsSetup ? { showSettings = true } : nil)
                            .padding(.top, Space.xs)
                    }
                }
                .padding(.horizontal, Space.md)
                .padding(.vertical, Space.sm)
            }
            .scrollDismissesKeyboard(.interactively)
            .onChange(of: msgs.count) { _ in scrollToEnd(proxy) }
            .onChange(of: session.aiPending) { _ in scrollToEnd(proxy) }
            .onAppear { scrollToEnd(proxy) }
        }
    }

    private func scrollToEnd(_ proxy: ScrollViewProxy) {
        withAnimation(Motion.standard) {
            if session.aiPending {
                proxy.scrollTo("typing", anchor: .bottom)
            } else if let last = msgs.last {
                proxy.scrollTo(last.id, anchor: .bottom)
            }
        }
    }

    @ViewBuilder private var intro: some View {
        if msgs.isEmpty {
            VStack(spacing: Space.xs) {
                Image(systemName: "sparkles").font(.system(size: 15))
                    .foregroundStyle(LColor.goldText)
                Text("Chat privately with **\(name)**.")
                    .font(LFont.footnote).foregroundStyle(LColor.inkSecondary)
                Text(introDetail)
                    .font(LFont.caption).foregroundStyle(LColor.inkTertiary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                if needsSetup {
                    Button("Set up AI") { showSettings = true }
                        .font(LFont.footnote.weight(.semibold)).foregroundStyle(LColor.goldText)
                }
            }
            .frame(maxWidth: .infinity)
            .padding(Space.md)
            .background(LColor.goldWash.opacity(0.5))
            .clipShape(RoundedRectangle(cornerRadius: Radius.card, style: .continuous))
            .padding(.bottom, Space.xs)
        }
    }

    private var introDetail: String {
        if needsSetup {
            return "Set up an AI provider to get started — your messages never touch the Logos relay."
        }
        return provider.isCloud
            ? "Replies come from \(provider.label). What you send here goes to them — never to the Logos relay."
            : "Runs on your device. Nothing you type here leaves your phone or touches the Logos relay."
    }

    private var composer: some View {
        VStack(spacing: 0) {
            Divider().background(LColor.hairline)
            HStack(alignment: .bottom, spacing: Space.xs) {
                TextField("Message \(name)", text: $draft, axis: .vertical)
                    .focused($composerFocused)
                    .lineLimit(1...6)
                    .font(LFont.body)
                    .padding(.horizontal, Space.sm).padding(.vertical, 9)
                    .background(LColor.surfaceAlt)
                    .clipShape(RoundedRectangle(cornerRadius: Radius.bubble, style: .continuous))

                Button {
                    let t = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !t.isEmpty else { return }
                    draft = ""; Haptic.send()
                    session.sendToAI(t)
                } label: {
                    Image(systemName: "arrow.up")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundStyle(LColor.onGold)
                        .frame(width: 36, height: 36)
                        .background(canSend ? LColor.gold : LColor.gold.opacity(0.35), in: Circle())
                }
                .disabled(!canSend)
                .animation(Motion.micro, value: canSend)
                .accessibilityLabel("Send")
            }
            .padding(.horizontal, Space.sm).padding(.vertical, Space.xs)
            .background(LColor.canvas)
        }
    }

    private var needsSetup: Bool { provider == .none }
    private var canSend: Bool {
        !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !session.aiPending
    }
}

/// Three-dot "assistant is thinking" indicator, styled like an inbound bubble.
/// Shared by the dedicated AI chat and the in-chat @mention flow.
struct TypingBubble: View {
    @State private var lit = 0

    var body: some View {
        HStack {
            HStack(spacing: 4) {
                ForEach(0..<3) { i in
                    Circle().fill(LColor.inkTertiary)
                        .frame(width: 6, height: 6)
                        .opacity(lit == i ? 1 : 0.3)
                }
            }
            .padding(.horizontal, 14).padding(.vertical, 11)
            .background(LColor.surfaceAlt)
            .clipShape(RoundedRectangle(cornerRadius: Radius.bubble, style: .continuous))
            Spacer(minLength: 48)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 350_000_000)
                withAnimation(Motion.micro) { lit = (lit + 1) % 3 }
            }
        }
        .accessibilityLabel("\(AIConfig.assistantName) is thinking")
    }
}
