import Foundation
#if canImport(FoundationModels)
import FoundationModels
#endif

/// Free, fully-private on-device generation via Apple's Foundation Models (iOS 26+,
/// Apple-Intelligence-capable devices). Nothing leaves the device; no key, no cost.
/// Wrapped in `canImport` so the app still builds where the SDK lacks the framework —
/// it just reports the model as unavailable there.
enum AppleOnDevice {
    /// Whether an on-device model can be used right now.
    static var isAvailable: Bool {
        #if canImport(FoundationModels)
        if #available(iOS 26.0, *) {
            if case .available = SystemLanguageModel.default.availability { return true }
        }
        #endif
        return false
    }

    /// Human-readable status for the settings screen.
    static var statusText: String {
        #if canImport(FoundationModels)
        if #available(iOS 26.0, *) {
            switch SystemLanguageModel.default.availability {
            case .available:
                return "Available on this device — free and fully private (nothing leaves your phone)."
            case .unavailable(let reason):
                return "Not available right now (\(reason)). On-device AI needs an Apple-Intelligence-capable device with the model downloaded."
            @unknown default:
                return "Not available on this device."
            }
        }
        return "Needs iOS 26 on an Apple-Intelligence-capable device."
        #else
        return "This build was compiled without on-device model support."
        #endif
    }

    static func complete(system: String, user: String) async throws -> String {
        #if canImport(FoundationModels)
        if #available(iOS 26.0, *), case .available = SystemLanguageModel.default.availability {
            let session = LanguageModelSession(instructions: system)
            let response = try await session.respond(to: user)
            return response.content
        }
        #endif
        throw AIError.onDeviceUnavailable
    }
}
