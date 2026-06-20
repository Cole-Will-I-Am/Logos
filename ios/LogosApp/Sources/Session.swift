import Foundation
import LogosKit

/// One displayed chat message (UI-side; the cryptographic session state lives in
/// the Rust store). History is in-memory for this MVP — persisting it is a follow-up.
struct ChatMessage: Identifiable {
    let id = UUID()
    let text: String
    let mine: Bool
}

/// Owns the Rust `LogosClient` and drives the UI. `LogosClient` calls are blocking
/// (network), so they run off the main actor via `runBlocking`; published state is
/// mutated back on the main actor.
@MainActor
final class Session: ObservableObject {
    @Published var username: String?
    @Published var conversations: [String] = []
    @Published var messages: [String: [ChatMessage]] = [:]
    @Published var relayURL: String
    @Published var lastError: String?

    private var client: LogosClient?
    private let storePath: String
    private var pollTask: Task<Void, Never>?

    init() {
        let dir = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        storePath = dir.appendingPathComponent("logos-store.json").path
        relayURL = UserDefaults.standard.string(forKey: "relayURL") ?? "http://127.0.0.1:8787"
        loadIfExists()
    }

    private func loadIfExists() {
        guard FileManager.default.fileExists(atPath: storePath) else { return }
        do {
            let c = try LogosClient.load(path: storePath, serverUrl: relayURL)
            client = c
            username = c.username()
            startPolling()
        } catch {
            lastError = "\(error)"
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
                startPolling()
            } catch {
                lastError = "\(error)"
            }
        }
    }

    func startConversation(with peer: String) {
        if !conversations.contains(peer) { conversations.append(peer) }
        if messages[peer] == nil { messages[peer] = [] }
    }

    func send(to peer: String, text: String) {
        guard let client else { return }
        startConversation(with: peer)
        messages[peer, default: []].append(ChatMessage(text: text, mine: true))
        Task {
            do { try await runBlocking { try client.send(to: peer, message: text) } }
            catch { lastError = "\(error)" }
        }
    }

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
                messages[m.from, default: []].append(ChatMessage(text: m.text, mine: false))
            }
        } catch {
            lastError = "\(error)"
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
