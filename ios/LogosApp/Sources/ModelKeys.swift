import Foundation
import Security

/// AI providers a user can bring their own key for. Privacy-ordered: on-device/your
/// own Ollama server keeps content private; cloud providers see what you send.
enum AIProvider: String, CaseIterable, Identifiable {
    case none, onDevice, ollama, anthropic, openai
    var id: String { rawValue }
    var label: String {
        switch self {
        case .none: return "Off"
        case .onDevice: return "On-device (Apple, private)"
        case .ollama: return "Ollama (your server)"
        case .anthropic: return "Anthropic (Claude)"
        case .openai: return "OpenAI"
        }
    }
    /// True if using this provider sends content off the device to a third party.
    var isCloud: Bool { self == .anthropic || self == .openai }
    var defaultModel: String {
        switch self {
        case .anthropic: return "claude-opus-4-8"
        case .openai: return "gpt-4o"
        case .ollama: return "llama3.1"
        case .none, .onDevice: return ""
        }
    }
    var needsKey: Bool { self == .anthropic || self == .openai }
}

/// Non-secret AI config (active provider, per-provider model, Ollama endpoint) in
/// UserDefaults. API keys themselves live in the Keychain (`ModelKeys`) — device-only,
/// never synced, and NEVER sent to the Logos relay.
enum AIConfig {
    private static let d = UserDefaults.standard

    static var provider: AIProvider {
        get { AIProvider(rawValue: d.string(forKey: "ai.provider") ?? "") ?? .none }
        set { d.set(newValue.rawValue, forKey: "ai.provider") }
    }
    static func model(for p: AIProvider) -> String {
        let m = d.string(forKey: "ai.model.\(p.rawValue)")?.trimmingCharacters(in: .whitespaces)
        return (m?.isEmpty == false) ? m! : p.defaultModel
    }
    static func setModel(_ m: String, for p: AIProvider) {
        d.set(m.trimmingCharacters(in: .whitespaces), forKey: "ai.model.\(p.rawValue)")
    }
    static var ollamaEndpoint: String {
        get { d.string(forKey: "ai.ollama.endpoint") ?? "" }
        set { d.set(newValue.trimmingCharacters(in: .whitespaces), forKey: "ai.ollama.endpoint") }
    }

    /// The provider actually used: if nothing is set up but the device has a free
    /// on-device model, fall back to it — that's the free, private default.
    static var effectiveProvider: AIProvider {
        if provider == .none, AppleOnDevice.isAvailable { return .onDevice }
        return provider
    }

    /// Whether the effective provider is usable (has the key/endpoint/model it needs).
    static var configured: Bool {
        switch effectiveProvider {
        case .none: return false
        case .onDevice: return AppleOnDevice.isAvailable
        case .ollama: return !ollamaEndpoint.isEmpty
        case .anthropic, .openai: return ModelKeys.key(effectiveProvider) != nil
        }
    }
}

/// Provider API keys in the iOS Keychain (`...ThisDeviceOnly` — device-only, not synced,
/// never transmitted to the relay). Mirrors `StoreKey`'s posture.
enum ModelKeys {
    private static let service = "com.colecantcode.logos.aikeys"

    static func key(_ p: AIProvider) -> String? { load(p.rawValue) }

    static func setKey(_ value: String?, for p: AIProvider) {
        let v = value?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let v, !v.isEmpty { save(p.rawValue, v) } else { delete(p.rawValue) }
    }

    static func hasKey(_ p: AIProvider) -> Bool { load(p.rawValue) != nil }

    private static func load(_ account: String) -> String? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data, let s = String(data: data, encoding: .utf8)
        else { return nil }
        return s
    }

    private static func save(_ account: String, _ value: String) {
        delete(account)
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: Data(value.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        SecItemAdd(add as CFDictionary, nil)
    }

    private static func delete(_ account: String) {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(q as CFDictionary)
    }
}
