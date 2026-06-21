import Foundation

enum AIError: LocalizedError {
    case notConfigured
    case onDeviceUnavailable
    case http(Int, String)
    case badResponse
    case network(String)

    var errorDescription: String? {
        switch self {
        case .notConfigured: return "No AI provider is set up. Add a key in Settings → AI."
        case .onDeviceUnavailable: return "On-device AI isn't available here. Add your own key in Settings → AI, or try on an Apple-Intelligence device running iOS 26."
        case .http(let code, let msg): return "Provider error \(code): \(msg)"
        case .badResponse: return "Couldn't read the provider's response."
        case .network(let m): return m
        }
    }
}

/// Calls the user's chosen model provider **directly from the device** — the Logos
/// relay is never in the path and never sees the content or the key. Cloud providers
/// (Anthropic/OpenAI) do see whatever is sent; Ollama (your own server / on-device)
/// keeps it private. Callers must get explicit user consent before sending content to
/// a cloud provider (see `AIProvider.isCloud`).
enum AIClient {
    static func complete(system: String, user: String) async throws -> String {
        switch AIConfig.effectiveProvider {
        case .none: throw AIError.notConfigured
        case .onDevice: return try await AppleOnDevice.complete(system: system, user: user)
        case .anthropic: return try await anthropic(system: system, user: user)
        case .openai: return try await openai(system: system, user: user)
        case .ollama: return try await ollama(system: system, user: user)
        }
    }

    /// A tiny round-trip used by the "Test" button to validate a key/endpoint.
    static func test() async throws -> String {
        try await complete(system: "You are a connectivity test. Reply with exactly: ok.",
                           user: "ping")
    }

    // MARK: - Providers

    private static func post(_ url: URL, headers: [String: String], body: [String: Any]) async throws -> Data {
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = 60
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        headers.forEach { req.setValue($0.value, forHTTPHeaderField: $0.key) }
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, resp): (Data, URLResponse)
        do { (data, resp) = try await URLSession.shared.data(for: req) }
        catch { throw AIError.network(error.localizedDescription) }
        guard let http = resp as? HTTPURLResponse else { throw AIError.badResponse }
        guard (200..<300).contains(http.statusCode) else {
            let msg = String(data: data, encoding: .utf8).map { String($0.prefix(300)) } ?? ""
            throw AIError.http(http.statusCode, msg)
        }
        return data
    }

    private static func json(_ data: Data) throws -> [String: Any] {
        guard let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AIError.badResponse
        }
        return o
    }

    private static func anthropic(system: String, user: String) async throws -> String {
        guard let key = ModelKeys.key(.anthropic) else { throw AIError.notConfigured }
        let url = URL(string: "https://api.anthropic.com/v1/messages")!
        let body: [String: Any] = [
            "model": AIConfig.model(for: .anthropic),
            "max_tokens": 1024,
            "system": system,
            "messages": [["role": "user", "content": user]],
        ]
        let data = try await post(url, headers: [
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        ], body: body)
        // { "content": [ { "type": "text", "text": "..." } ] }
        let o = try json(data)
        guard let content = o["content"] as? [[String: Any]],
              let text = content.first(where: { ($0["type"] as? String) == "text" })?["text"] as? String
        else { throw AIError.badResponse }
        return text
    }

    private static func openai(system: String, user: String) async throws -> String {
        guard let key = ModelKeys.key(.openai) else { throw AIError.notConfigured }
        let url = URL(string: "https://api.openai.com/v1/chat/completions")!
        let body: [String: Any] = [
            "model": AIConfig.model(for: .openai),
            "messages": [
                ["role": "system", "content": system],
                ["role": "user", "content": user],
            ],
        ]
        let data = try await post(url, headers: ["Authorization": "Bearer \(key)"], body: body)
        // { "choices": [ { "message": { "content": "..." } } ] }
        let o = try json(data)
        guard let choices = o["choices"] as? [[String: Any]],
              let message = choices.first?["message"] as? [String: Any],
              let text = message["content"] as? String
        else { throw AIError.badResponse }
        return text
    }

    private static func ollama(system: String, user: String) async throws -> String {
        let base = AIConfig.ollamaEndpoint.trimmingCharacters(in: .whitespaces)
        guard !base.isEmpty, let url = URL(string: base.hasSuffix("/") ? "\(base)api/chat" : "\(base)/api/chat")
        else { throw AIError.notConfigured }
        var headers: [String: String] = [:]
        if let key = ModelKeys.key(.ollama) { headers["Authorization"] = "Bearer \(key)" } // Ollama Cloud
        let body: [String: Any] = [
            "model": AIConfig.model(for: .ollama),
            "stream": false,
            "messages": [
                ["role": "system", "content": system],
                ["role": "user", "content": user],
            ],
        ]
        let data = try await post(url, headers: headers, body: body)
        // { "message": { "content": "..." } }
        let o = try json(data)
        guard let message = o["message"] as? [String: Any],
              let text = message["content"] as? String
        else { throw AIError.badResponse }
        return text
    }
}
