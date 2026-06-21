import Foundation
import Security
import CryptoKit

/// Device-only at-rest key for the Logos identity store and chat history.
///
/// A random 32-byte key kept in the iOS Keychain — protected by the Secure Enclave,
/// gated on the device passcode, and **not** synced to iCloud
/// (`...AfterFirstUnlockThisDeviceOnly`, so background message polling keeps working
/// once the device has been unlocked since boot). The Rust store stretches this key
/// with Argon2id (`LogosClient.create/load/restore` `password:`); the Swift history
/// snapshot is sealed with it via ChaCha20-Poly1305. Get-or-create on first use.
///
/// This is the device copy's protection. The user-held backup is the recovery
/// phrase, which is independent (it carries the identity seed, not this key).
enum StoreKey {
    private static let service = "com.colecantcode.logos.storekey"
    private static let account = "store-key-v1"

    /// The raw 32-byte key, minting + persisting one on first use.
    private static func raw() -> Data {
        if let existing = load() { return existing }
        var bytes = [UInt8](repeating: 0, count: 32)
        // L4: a failed RNG must not yield a weak/zero key — fail closed.
        let rng = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        precondition(rng == errSecSuccess, "SecRandomCopyBytes failed (\(rng)) — refusing to mint a weak store key")
        let data = Data(bytes)
        // L4: if the key can't be persisted, the next launch would mint a different
        // key and the store would be unreadable — fail closed rather than continue.
        let status = save(data)
        precondition(status == errSecSuccess, "Keychain SecItemAdd failed (\(status)) — store key not persisted")
        return data
    }

    /// Symmetric key for sealing the history snapshot (CryptoKit).
    static func symmetric() -> SymmetricKey { SymmetricKey(data: raw()) }

    /// Base64 form, passed as the Rust store passphrase.
    static func password() -> String { raw().base64EncodedString() }

    /// Delete the device key so the next access mints a fresh one. Used when starting
    /// a new identity, so any ciphertext that survived deletion becomes undecryptable
    /// (red-team M2).
    static func rotate() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
    }

    private static func load() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    @discardableResult
    private static func save(_ data: Data) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary) // avoid errSecDuplicateItem
        var add = query
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return SecItemAdd(add as CFDictionary, nil)
    }
}
