import Foundation
import LogosKit

/// Delivery state of an outbound message. Drives the bubble status row.
/// NOTE: `.blocked` is currently inferred from the error text (heuristic) because
/// the FFI only returns `LogosError.Client(msg:)`. The robust fix is a typed FFI
/// error (e.g. `LogosError.IdentityChanged`) — see docs/DESIGN.md → "FFI additions".
enum MessageStatus: Equatable {
    case sending
    case sent
    case failed(String)   // network/unknown — safe to retry
    case blocked(String)  // security refusal (identity/TOFU) — needs the user's attention
}

/// Per-conversation security posture surfaced to the UI.
enum SessionSecurity { case encrypted, verified, identityChanged }

/// One displayed chat message (UI-side; the cryptographic session state lives in
/// the Rust store). History is in-memory for this MVP — persisting it is a follow-up.
struct ChatMessage: Identifiable, Equatable {
    let id = UUID()
    let text: String
    let mine: Bool
    var status: MessageStatus
    let at: Date           // send/receipt time (UI-side; IncomingMessage carries no timestamp yet)
}

/// Owns the Rust `LogosClient` and drives the UI. `LogosClient` calls are blocking
/// (network), so they run off the main actor via `runBlocking`; published state is
/// mutated back on the main actor.
@MainActor
final class Session: ObservableObject {
    @Published var username: String?
    @Published var mailboxId: String = ""
    @Published var conversations: [String] = []
    @Published var messages: [String: [ChatMessage]] = [:]
    @Published var security: [String: SessionSecurity] = [:]
    @Published var relayURL: String
    @Published var lastError: String?

    private var client: LogosClient?
    private let storePath: String
    private var pollTask: Task<Void, Never>?

    init() {
        let dir = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        // Create Application Support up front — `create()/save()` ENOENTs on first run otherwise.
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        storePath = dir.appendingPathComponent("logos-store.json").path
        relayURL = UserDefaults.standard.string(forKey: "relayURL") ?? "https://relay.manticthink.com"
        loadIfExists()
    }

    func security(for peer: String) -> SessionSecurity { security[peer] ?? .encrypted }

    private func loadIfExists() {
        guard FileManager.default.fileExists(atPath: storePath) else { return }
        do {
            let c = try LogosClient.load(path: storePath, serverUrl: relayURL)
            client = c
            username = c.username()
            mailboxId = c.mailbox()
            hardenStore()
            startPolling()
        } catch {
            lastError = friendly(error)
        }
    }

    func register(username name: String, relay: String) {
        relayURL = relay
        UserDefaults.standard.set(relay, forKey: "relayURL")
        let path = storePath
        Task {
            do {
                let c = try await runBlocking { try LogosClient.create(path: path, serverUrl: relay, username: name) }
                client = c
                username = c.username()
                mailboxId = c.mailbox()
                hardenStore()
                startPolling()
            } catch {
                lastError = friendly(error)
            }
        }
    }

    func startConversation(with peer: String) {
        if !conversations.contains(peer) { conversations.append(peer) }
        if messages[peer] == nil { messages[peer] = [] }
    }

    func send(to peer: String, text: String) {
        guard client != nil else { lastError = "No identity loaded."; return }
        startConversation(with: peer)
        let msg = ChatMessage(text: text, mine: true, status: .sending, at: Date())
        messages[peer, default: []].append(msg)
        deliver(msg.id, to: peer, text: text)
    }

    /// Retry a previously failed/blocked message in place (keeps order; no duplicate bubble).
    func retry(_ id: UUID, in peer: String) {
        guard let text = messages[peer]?.first(where: { $0.id == id })?.text else { return }
        deliver(id, to: peer, text: text)
    }

    /// Single source of truth for an outbound attempt. The bubble is only marked
    /// `.sent` AFTER the Rust client confirms; failures/refusals are shown honestly.
    private func deliver(_ id: UUID, to peer: String, text: String) {
        guard let client else { return }
        setStatus(id, in: peer, .sending)
        Task {
            do {
                try await runBlocking { try client.send(to: peer, message: text) }
                setStatus(id, in: peer, .sent)
                if security[peer] == nil { security[peer] = .encrypted }
            } catch {
                switch classify(error) {
                case .identityChanged:
                    setStatus(id, in: peer, .blocked(
                        "We couldn’t confirm \(peer)’s identity. Don’t send anything sensitive until you verify them."))
                    security[peer] = .identityChanged
                    Haptic.warn()
                case .network(let message):
                    setStatus(id, in: peer, .failed(message))
                }
                lastError = friendly(error)
            }
        }
    }

    private func setStatus(_ id: UUID, in peer: String, _ status: MessageStatus) {
        guard var arr = messages[peer], let i = arr.firstIndex(where: { $0.id == id }) else { return }
        arr[i].status = status
        messages[peer] = arr
    }

    func clearError() { lastError = nil }

    // MARK: - Error classification (typed — driven by the FFI's LogosError)

    private enum Failure {
        case identityChanged(peer: String)
        case network(String)   // retryable bucket: transport, unknown user, or other
    }

    /// Map a thrown error to a UI outcome. `IdentityChanged` is authoritative — it
    /// comes from the core's TOFU pin check, not a string guess — so the identity
    /// interstitial only ever fires on a real key change.
    private func classify(_ error: Error) -> Failure {
        guard let e = error as? LogosError else {
            return .network("Couldn’t send. Check your connection and try again.")
        }
        switch e {
        case .IdentityChanged(let peer):
            return .identityChanged(peer: peer)
        case .NotRegistered(let peer):
            return .network("@\(peer) isn’t on Logos yet — double-check the username.")
        case .Network:
            return .network("Couldn’t reach the relay. We’ll keep this message ready to retry.")
        case .Client:
            return .network("Couldn’t send. Try again in a moment.")
        }
    }

    private func friendly(_ error: Error) -> String {
        switch classify(error) {
        case .identityChanged(let peer): return "\(peer)’s identity changed. Verify them before continuing."
        case .network(let message):      return message
        }
    }

    // MARK: - At-rest hygiene (Swift-side; not a substitute for store encryption)

    /// Keep the identity store out of iCloud/iTunes backups and protected at rest.
    /// `completeUnlessOpen` lets background polling keep working once opened while unlocked.
    private func hardenStore() {
        try? FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.completeUnlessOpen],
            ofItemAtPath: storePath)
        var url = URL(fileURLWithPath: storePath)
        var rv = URLResourceValues(); rv.isExcludedFromBackup = true
        try? url.setResourceValues(rv)
    }

    // MARK: - Receive loop

    private func startPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.pollOnce()
                try? await Task.sleep(nanoseconds: 3_000_000_000)
            }
        }
    }

    private func pollOnce() async {
        guard let client else { return }
        do {
            let incoming = try await runBlocking { try client.recv() }
            for m in incoming {
                startConversation(with: m.from)
                messages[m.from, default: []].append(
                    ChatMessage(text: m.text, mine: false, status: .sent, at: Date()))
                if security[m.from] == nil { security[m.from] = .encrypted }
            }
        } catch {
            lastError = friendly(error)
        }
    }
}

/// Run a blocking Rust call off the main thread and await the result.
func runBlocking<T>(_ work: @escaping () throws -> T) async throws -> T {
    try await withCheckedThrowingContinuation { cont in
        DispatchQueue.global(qos: .userInitiated).async {
            do { cont.resume(returning: try work()) }
            catch { cont.resume(throwing: error) }
        }
    }
}
