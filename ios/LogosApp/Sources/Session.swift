import Foundation
import CryptoKit
import LogosKit

/// Delivery state of an outbound message. Drives the bubble status row.
/// NOTE: `.blocked` is currently inferred from the error text (heuristic) because
/// the FFI only returns `LogosError.Client(msg:)`. The robust fix is a typed FFI
/// error (e.g. `LogosError.IdentityChanged`) — see docs/DESIGN.md → "FFI additions".
enum MessageStatus: Equatable, Codable {
    case sending
    case sent
    case failed(String)   // network/unknown — safe to retry
    case blocked(String)  // security refusal (identity/TOFU) — needs the user's attention
}

/// Per-conversation security posture surfaced to the UI.
enum SessionSecurity: String, Codable { case encrypted, verified, identityChanged }

/// One displayed chat message (UI-side; the cryptographic session state lives in
/// the Rust store). Persisted to disk via `HistorySnapshot` so history survives
/// app suspension/relaunch.
struct ChatMessage: Identifiable, Equatable, Codable {
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

    // Connectivity: reflects whether the last relay poll/sync succeeded.
    @Published var online = true
    @Published var lastSynced: Date?
    @Published var syncing = false

    /// The default public relay. Identities/history on this relay keep the original
    /// unsuffixed filenames so existing installs aren't orphaned by per-relay stores.
    static let defaultRelay = "https://relay.manticthink.com"

    private var client: LogosClient?
    private let dir: URL
    private var pollTask: Task<Void, Never>?

    // Store + history are scoped to the active relay: each relay (network) keeps its
    // own identity and chats, so switching networks is safe and reversible.
    private var storePath: String { path(prefix: "logos-store") }
    private var historyPath: String { path(prefix: "logos-history") }

    private func path(prefix: String) -> String {
        let name = relayURL == Self.defaultRelay ? "\(prefix).json"
                                                 : "\(prefix)-\(Self.slug(relayURL)).json"
        return dir.appendingPathComponent(name).path
    }

    private static func slug(_ s: String) -> String {
        SHA256.hash(data: Data(s.utf8)).prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    init() {
        dir = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        // Create Application Support up front — `create()/save()` ENOENTs on first run otherwise.
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        relayURL = UserDefaults.standard.string(forKey: "relayURL") ?? Self.defaultRelay
        loadHistory()
        loadIfExists()
    }

    /// Switch the active relay (network). Each relay scopes its own identity + chats,
    /// so this loads the identity registered on `newURL` if one exists, or drops to
    /// onboarding to register on that network. No-op if unchanged.
    func switchRelay(to newURL: String) {
        let trimmed = newURL.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, trimmed != relayURL else { return }
        pollTask?.cancel(); pollTask = nil
        client = nil
        username = nil; mailboxId = ""
        conversations = []; messages = [:]; security = [:]; lastError = nil
        online = true; lastSynced = nil; syncing = false
        relayURL = trimmed
        UserDefaults.standard.set(trimmed, forKey: "relayURL")
        loadHistory()
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
        persist()
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
        persist()
    }

    func clearError() { lastError = nil }

    // MARK: - Contact verification

    /// Verification state for `peer` from the Rust core (safety number, verified,
    /// change count). Run off-main so it never blocks the UI on the client mutex.
    func contactSecurity(_ peer: String) async -> ContactSecurity? {
        guard let client else { return nil }
        return try? await runBlocking { client.contactSecurity(peer: peer) }
    }

    /// Mark `peer` verified after the user compared safety numbers out-of-band.
    func markVerified(_ peer: String) async {
        guard let client else { return }
        do {
            try await runBlocking { try client.markVerified(peer: peer) }
            security[peer] = .verified
            persist()
        } catch { lastError = friendly(error) }
    }

    /// Recovery: accept that `peer` legitimately changed identity (e.g. reinstalled).
    func resetPeerIdentity(_ peer: String) async {
        guard let client else { return }
        do {
            try await runBlocking { try client.resetPeerIdentity(peer: peer) }
            security[peer] = .encrypted
            persist()
        } catch { lastError = friendly(error) }
    }

    // MARK: - Local chat history persistence

    /// On-disk snapshot of the UI-side chat history (the Rust store holds only the
    /// cryptographic session state, not displayed messages). Written atomically with
    /// iOS file protection so it isn't lost when the app is suspended/terminated.
    /// NOTE: message text is stored in cleartext here, matching the current store
    /// posture — full at-rest encryption (Argon2id) is a tracked follow-up.
    private struct HistorySnapshot: Codable {
        var conversations: [String]
        var messages: [String: [ChatMessage]]
        var security: [String: SessionSecurity]
    }

    private func loadHistory() {
        guard FileManager.default.fileExists(atPath: historyPath),
              let data = try? Data(contentsOf: URL(fileURLWithPath: historyPath)),
              let snap = try? JSONDecoder().decode(HistorySnapshot.self, from: data)
        else { return }
        conversations = snap.conversations
        security = snap.security
        // A message still `.sending` at last save never confirmed delivery — surface
        // it as failed-but-retryable rather than a spinner that never resolves.
        messages = snap.messages.mapValues { arr in
            arr.map { m in
                guard case .sending = m.status else { return m }
                var fixed = m; fixed.status = .failed("Interrupted — tap to retry"); return fixed
            }
        }
    }

    private func persist() {
        let snap = HistorySnapshot(conversations: conversations, messages: messages, security: security)
        do {
            let data = try JSONEncoder().encode(snap)
            var url = URL(fileURLWithPath: historyPath)
            try data.write(to: url, options: [.atomic, .completeFileProtectionUnlessOpen])
            var rv = URLResourceValues(); rv.isExcludedFromBackup = true
            try? url.setResourceValues(rv)
        } catch {
            // Best-effort: never crash the app over history persistence.
        }
    }

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

    /// Force an immediate relay check (manual "Sync now").
    func syncNow() { Task { await pollOnce() } }

    private func pollOnce() async {
        guard let client, !syncing else { return }
        syncing = true
        defer { syncing = false }
        do {
            let incoming = try await runBlocking { try client.recv() }
            for m in incoming {
                startConversation(with: m.from)
                messages[m.from, default: []].append(
                    ChatMessage(text: m.text, mine: false, status: .sent, at: Date()))
                if security[m.from] == nil { security[m.from] = .encrypted }
            }
            if !incoming.isEmpty { persist() }
            online = true
            lastSynced = Date()
        } catch {
            online = false
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
