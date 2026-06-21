import Foundation
import CryptoKit
import UIKit
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
    /// Set when this bubble is an in-chat AI answer the user summoned with @mention —
    /// holds the assistant's display name so it renders as the assistant, not "you".
    /// Local-only (the wire carries the attribution in the message text); optional so
    /// existing persisted history decodes with `nil`.
    var aiAuthor: String? = nil
}

/// Owns the Rust `LogosClient` and drives the UI. `LogosClient` calls are blocking
/// (network), so they run off the main actor via `runBlocking`; published state is
/// mutated back on the main actor.
@MainActor
final class Session: ObservableObject {
    @Published var username: String?
    @Published var mailboxId: String = ""
    @Published var conversations: [String] = []
    /// Saved, local, manually-managed address book (usernames on the active relay).
    /// Persists independently of conversations: deleting a chat keeps the contact;
    /// `removeContact` forgets them entirely. Never synced/uploaded.
    @Published var contacts: [String] = []
    @Published var messages: [String: [ChatMessage]] = [:]
    @Published var security: [String: SessionSecurity] = [:]
    // Inbox state (persisted with history).
    @Published var pinned: Set<String> = []
    @Published var archived: Set<String> = []
    @Published var unread: [String: Int] = [:]
    // Local, device-only contact customization (never shared / never leaves the device).
    @Published var nicknames: [String: String] = [:]
    @Published private(set) var avatars: [String: UIImage] = [:]
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
    private var activePeer: String?   // the open chat, so its incoming msgs don't count as unread
    /// Bumped on every identity transition (register/restore/switch/new). A poll
    /// whose `recv()` was in flight across a transition checks this and discards its
    /// results, so a torn-down identity's data can't be resurrected (red-team M2).
    private var identityGeneration = 0

    // Store + history are scoped to the active relay: each relay (network) keeps its
    // own identity and chats, so switching networks is safe and reversible.
    private var storePath: String { path(prefix: "logos-store") }
    private var historyPath: String { path(prefix: "logos-history") }

    private func path(prefix: String) -> String {
        let name = relayURL == Self.defaultRelay ? "\(prefix).json"
                                                 : "\(prefix)-\(Self.slug(relayURL)).json"
        return dir.appendingPathComponent(name).path
    }

    private var avatarDir: URL { dir.appendingPathComponent("logos-avatars", isDirectory: true) }
    private func avatarURL(_ peer: String) -> URL {
        avatarDir.appendingPathComponent("\(Self.slug(peer)).jpg")
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
    func switchRelay(to newURL: String) async {
        let trimmed = newURL.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, trimmed != relayURL else { return }
        identityGeneration &+= 1
        // Await the in-flight poll so a recv()+save() can't write the old relay's
        // data into the new relay's store after we switch (red-team M2).
        pollTask?.cancel(); await pollTask?.value; pollTask = nil
        client = nil
        username = nil; mailboxId = ""
        conversations = []; contacts = []; messages = [:]; security = [:]; lastError = nil
        online = true; lastSynced = nil; syncing = false
        pinned = []; archived = []; unread = [:]; nicknames = [:]; avatars = [:]
        relayURL = trimmed
        UserDefaults.standard.set(trimmed, forKey: "relayURL")
        loadHistory()
        loadIfExists()
    }

    /// Abandon the current on-device identity and return to onboarding to create a
    /// fresh one (on the same relay). Deletes the local store, history, and avatars
    /// for the active relay. Destructive and irreversible unless the user saved a
    /// recovery phrase first — the UI must confirm before calling this.
    func startNewIdentity() async {
        identityGeneration &+= 1
        // Wait for any in-flight recv()+save() to finish BEFORE deleting, so a racing
        // save can't re-create the store with the old identity's seed/history (M2).
        pollTask?.cancel(); await pollTask?.value; pollTask = nil
        client = nil
        try? FileManager.default.removeItem(atPath: storePath)
        try? FileManager.default.removeItem(atPath: historyPath)
        try? FileManager.default.removeItem(at: avatarDir)
        StoreKey.rotate() // re-mint the device key so any resurrected ciphertext is undecryptable
        username = nil; mailboxId = ""
        conversations = []; contacts = []; messages = [:]; security = [:]; lastError = nil
        online = true; lastSynced = nil; syncing = false
        pinned = []; archived = []; unread = [:]; nicknames = [:]; avatars = [:]
        activePeer = nil
    }

    func security(for peer: String) -> SessionSecurity { security[peer] ?? .encrypted }

    private func loadIfExists() {
        guard FileManager.default.fileExists(atPath: storePath) else { return }
        do {
            // Encrypted at rest with a device-only Keychain key (Argon2id in the core).
            // load() format-detects, so a legacy plaintext store still loads and migrates
            // to encrypted on the next save.
            let c = try LogosClient.load(path: storePath, serverUrl: relayURL, password: StoreKey.password())
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
        identityGeneration &+= 1
        relayURL = relay
        UserDefaults.standard.set(relay, forKey: "relayURL")
        let path = storePath
        Task {
            do {
                let c = try await runBlocking { try LogosClient.create(path: path, serverUrl: relay, username: name, password: StoreKey.password()) }
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

    /// Restore an existing identity on this device from its 24-word recovery phrase.
    /// Re-derives the same keys and re-registers under `name` (reclaiming the
    /// username). Recovers identity + username only — not history or contacts.
    func restore(username name: String, phrase: String, relay: String) {
        identityGeneration &+= 1
        relayURL = relay
        UserDefaults.standard.set(relay, forKey: "relayURL")
        let path = storePath
        let cleaned = phrase
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .components(separatedBy: .whitespacesAndNewlines)
            .filter { !$0.isEmpty }
            .joined(separator: " ")
            .lowercased()
        Task {
            do {
                let c = try await runBlocking {
                    try LogosClient.restore(path: path, serverUrl: relay, username: name,
                                            recoveryPhrase: cleaned, password: StoreKey.password())
                }
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
        if !contacts.contains(peer) { contacts.append(peer); contacts.sort() }
        persist()
    }

    // MARK: - Contacts (local address book)

    /// Save a person as a contact without (yet) starting a chat. Local-only; manual.
    func addContact(_ username: String) {
        let u = username.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !u.isEmpty, !contacts.contains(u) else { return }
        contacts.append(u)
        contacts.sort()
        persist()
    }

    func isContact(_ peer: String) -> Bool { contacts.contains(peer) }

    /// Forget a person entirely on this device: their chat, history, nickname, photo,
    /// and the saved contact. (Deleting a *chat* keeps the contact; this removes it.)
    func removeContact(_ peer: String) {
        deleteConversation(peer)
        contacts.removeAll { $0 == peer }
        nicknames[peer] = nil
        avatars[peer] = nil
        try? FileManager.default.removeItem(at: avatarURL(peer))
        persist()
    }

    // MARK: - Inbox

    /// The currently-open chat. Incoming messages for it aren't counted as unread.
    func setActive(_ peer: String?) {
        activePeer = peer
        if let peer { markRead(peer) }
    }
    func markRead(_ peer: String) {
        guard (unread[peer] ?? 0) != 0 else { return }
        unread[peer] = 0
        persist()
    }
    func togglePin(_ peer: String) {
        if pinned.contains(peer) { pinned.remove(peer) } else { pinned.insert(peer) }
        persist()
    }
    func toggleArchive(_ peer: String) {
        if archived.contains(peer) { archived.remove(peer) } else { archived.insert(peer) }
        persist()
    }
    /// Delete a conversation and its local history on THIS device only — the relay
    /// and the other person are unaffected.
    func deleteConversation(_ peer: String) {
        conversations.removeAll { $0 == peer }
        messages[peer] = nil
        security[peer] = nil
        unread[peer] = nil
        pinned.remove(peer)
        archived.remove(peer)
        // Keep the saved contact + its nickname/photo so the person can be re-messaged;
        // `removeContact(_:)` forgets them entirely.
        persist()
    }
    /// Most recent activity, for sorting the inbox.
    func lastActivity(_ peer: String) -> Date {
        messages[peer]?.last?.at ?? .distantPast
    }

    // MARK: - Contact customization (local, device-only)

    /// Custom name if set, otherwise the username.
    func displayName(for peer: String) -> String {
        let n = nicknames[peer]?.trimmingCharacters(in: .whitespaces)
        return (n?.isEmpty == false) ? n! : peer
    }
    func setNickname(_ name: String?, for peer: String) {
        let t = name?.trimmingCharacters(in: .whitespaces)
        nicknames[peer] = (t?.isEmpty == false) ? t : nil
        persist()
    }
    /// Set a local photo for a contact — stored only on this device (never shared).
    func setAvatar(_ image: UIImage, for peer: String) {
        let square = image.squareThumbnail(256)
        guard let data = square.jpegData(compressionQuality: 0.8) else { return }
        try? FileManager.default.createDirectory(at: avatarDir, withIntermediateDirectories: true)
        var url = avatarURL(peer)
        try? data.write(to: url, options: [.atomic, .completeFileProtectionUnlessOpen])
        var rv = URLResourceValues(); rv.isExcludedFromBackup = true
        try? url.setResourceValues(rv)
        avatars[peer] = square
    }
    func removeAvatar(for peer: String) {
        try? FileManager.default.removeItem(at: avatarURL(peer))
        avatars[peer] = nil
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

    // MARK: - AI assistant (local; on-device by default, never via the relay)

    /// Reserved local thread id for the user's private AI assistant. Contains a colon,
    /// so it can never collide with a real relay username/mailbox. Kept OUT of
    /// `conversations` and `contacts` so none of the people-facing logic ever touches
    /// it — the inbox surfaces it through a dedicated pinned row instead.
    static let aiPeer = "ai:assistant"

    /// True while a reply is in flight (drives the typing indicator).
    @Published var aiPending = false
    /// Last AI failure, surfaced inline in the AI chat. Cleared on the next send.
    @Published var aiError: String?
    /// Peers with an in-chat @mention answer currently being generated (typing dots).
    @Published var aiMentionPending: Set<String> = []

    var aiMessages: [ChatMessage] { messages[Self.aiPeer] ?? [] }

    /// Send a message to the on-device / BYOK assistant. Unlike `send(to:)`, this never
    /// touches the Rust client or the relay — it calls the chosen provider directly
    /// (see `AIClient`) and appends the reply locally. The whole thread is the context.
    func sendToAI(_ text: String) {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty, !aiPending else { return }
        aiError = nil
        messages[Self.aiPeer, default: []].append(
            ChatMessage(text: t, mine: true, status: .sent, at: Date()))
        persist()
        aiPending = true
        let history = messages[Self.aiPeer] ?? []
        let name = AIConfig.assistantName
        Task {
            do {
                let reply = try await AIClient.reply(assistantName: name, history: history)
                messages[Self.aiPeer, default: []].append(
                    ChatMessage(text: reply, mine: false, status: .sent, at: Date()))
            } catch {
                aiError = (error as? AIError)?.errorDescription ?? error.localizedDescription
                Haptic.warn()
            }
            aiPending = false
            persist()
        }
    }

    /// Wipe the local AI conversation (this device only).
    func clearAIConversation() {
        messages[Self.aiPeer] = nil
        aiError = nil
        persist()
    }

    // MARK: - In-chat @mention ("@<assistant> …" inside a 1:1 thread)

    /// Does `text` tag the assistant by name? Matches "@<assistant name>"
    /// case-insensitively (the name may contain spaces).
    static func mentionsAI(_ text: String, name: String) -> Bool {
        let n = name.trimmingCharacters(in: .whitespaces)
        guard !n.isEmpty else { return false }
        return text.lowercased().contains("@" + n.lowercased())
    }

    /// The user tagged the assistant inside their chat with `peer`. Generate an answer
    /// from the recent thread and post it into the conversation for BOTH people to see.
    /// The answer rides the normal E2EE wire (labeled with the assistant name); the
    /// relay only ever sees ciphertext. Caller handles cloud consent before calling.
    func mentionAI(in peer: String, question: String) {
        let q = question.trimmingCharacters(in: .whitespacesAndNewlines)
        guard client != nil, !q.isEmpty, !aiMentionPending.contains(peer) else { return }
        aiMentionPending.insert(peer)
        let name = AIConfig.assistantName
        let me = username ?? "Me"
        let peerName = displayName(for: peer)
        let recent = Array((messages[peer] ?? []).suffix(40))
        Task {
            do {
                let answer = try await AIClient.answerInChat(
                    assistantName: name, meName: me, peerName: peerName, recent: recent, question: q)
                aiMentionPending.remove(peer)
                sendAIAnswer(to: peer, name: name, answer: answer)
            } catch {
                aiMentionPending.remove(peer)
                lastError = (error as? AIError)?.errorDescription ?? error.localizedDescription
                Haptic.warn()
            }
        }
    }

    /// Post an AI answer into a real peer thread. Locally it's an assistant-attributed
    /// bubble; on the wire it's a normal E2EE message labeled with the assistant name
    /// (the AI has no network identity, so the label travels in the text).
    private func sendAIAnswer(to peer: String, name: String, answer: String) {
        guard client != nil else { return }
        let wire = "✦ \(name): \(answer)"
        let msg = ChatMessage(text: answer, mine: true, status: .sending, at: Date(), aiAuthor: name)
        messages[peer, default: []].append(msg)
        deliver(msg.id, to: peer, text: wire)
    }

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

    /// Re-establish a chat after the other person restored from a recovery phrase
    /// (or reinstalled with the SAME identity). Clears the stale local session so
    /// their next message re-handshakes. The pin + verification are kept (the
    /// identity key is unchanged), so this is not an identity reset.
    func resetSession(_ peer: String) async {
        guard let client else { return }
        do {
            try await runBlocking { try client.resetSession(peer: peer) }
        } catch { lastError = friendly(error) }
    }

    /// This identity's 24-word recovery phrase, for the backup screen. `nil` if the
    /// identity predates recovery support (legacy store) or no client is loaded.
    func recoveryPhrase() async -> String? {
        guard let client else { return nil }
        do { return try await runBlocking { try client.exportRecoveryPhrase() } }
        catch { lastError = friendly(error); return nil }
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
        var pinned: [String]?
        var archived: [String]?
        var unread: [String: Int]?
        var nicknames: [String: String]?
        var contacts: [String]?
    }

    private func loadHistory() {
        guard FileManager.default.fileExists(atPath: historyPath),
              let raw = try? Data(contentsOf: URL(fileURLWithPath: historyPath))
        else { return }
        // Decrypt the sealed snapshot; fall back to legacy plaintext JSON (which then
        // migrates to sealed on the next persist()).
        var legacyPlaintext = false
        let data: Data
        if let box = try? ChaChaPoly.SealedBox(combined: raw),
           let opened = try? ChaChaPoly.open(box, using: StoreKey.symmetric()) {
            data = opened
        } else {
            data = raw
            legacyPlaintext = true
        }
        guard let snap = try? JSONDecoder().decode(HistorySnapshot.self, from: data) else { return }
        conversations = snap.conversations
        // Migration: pre-contacts stores seed the address book from past chat partners.
        contacts = (snap.contacts ?? conversations).sorted()
        security = snap.security
        pinned = Set(snap.pinned ?? [])
        archived = Set(snap.archived ?? [])
        unread = snap.unread ?? [:]
        nicknames = snap.nicknames ?? [:]
        for peer in conversations {
            if let data = try? Data(contentsOf: avatarURL(peer)), let img = UIImage(data: data) {
                avatars[peer] = img
            }
        }
        // A message still `.sending` at last save never confirmed delivery — surface
        // it as failed-but-retryable rather than a spinner that never resolves.
        messages = snap.messages.mapValues { arr in
            arr.map { m in
                guard case .sending = m.status else { return m }
                var fixed = m; fixed.status = .failed("Interrupted — tap to retry"); return fixed
            }
        }
        // Upgrade a legacy plaintext history file to the sealed format immediately.
        if legacyPlaintext { persist() }
    }

    private func persist() {
        let snap = HistorySnapshot(conversations: conversations, messages: messages, security: security,
                                   pinned: Array(pinned), archived: Array(archived), unread: unread,
                                   nicknames: nicknames, contacts: contacts)
        do {
            let data = try JSONEncoder().encode(snap)
            // Seal at rest with the device Keychain key (defence in depth alongside
            // iOS FileProtection); message text is no longer cleartext on disk.
            let sealed = try ChaChaPoly.seal(data, using: StoreKey.symmetric()).combined
            var url = URL(fileURLWithPath: historyPath)
            try sealed.write(to: url, options: [.atomic, .completeFileProtectionUnlessOpen])
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
        case .UsernameTaken(let username):
            return .network("“\(username)” is already taken on this relay. Try a different username.")
        case .InvalidRecoveryPhrase:
            return .network("That recovery phrase isn’t valid — check the words and try again.")
        case .InvalidUsername(let reason):
            return .network(reason.prefix(1).uppercased() + reason.dropFirst() + ".")
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
        let gen = identityGeneration
        syncing = true
        defer { syncing = false }
        do {
            let incoming = try await runBlocking { try client.recv() }
            // The identity was switched/torn down while recv() was in flight — discard
            // its results so we don't resurrect a deleted identity's history (M2).
            guard gen == identityGeneration, self.client != nil else { return }
            for m in incoming {
                startConversation(with: m.from)
                messages[m.from, default: []].append(
                    ChatMessage(text: m.text, mine: false, status: .sent, at: Date()))
                if m.from != activePeer { unread[m.from, default: 0] += 1 }
                if security[m.from] == nil { security[m.from] = .encrypted }
            }
            if !incoming.isEmpty { persist() }
            online = true
            lastSynced = Date()
        } catch {
            guard gen == identityGeneration else { return }
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

extension UIImage {
    /// Aspect-fill crop to a square of `side` points (for a compact avatar thumbnail).
    func squareThumbnail(_ side: CGFloat) -> UIImage {
        let renderer = UIGraphicsImageRenderer(size: CGSize(width: side, height: side))
        return renderer.image { _ in
            let scale = max(side / size.width, side / size.height)
            let w = size.width * scale, h = size.height * scale
            draw(in: CGRect(x: (side - w) / 2, y: (side - h) / 2, width: w, height: h))
        }
    }
}
