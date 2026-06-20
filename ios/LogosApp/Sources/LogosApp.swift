import SwiftUI

// EXPERIMENTAL — UNAUDITED. Do not use for real secrets.
@main
struct LogosApp: App {
    @StateObject private var session = Session()

    var body: some Scene {
        WindowGroup {
            Group {
                if session.username == nil {
                    OnboardingView()
                } else {
                    ConversationsView()
                }
            }
            .environmentObject(session)
            .tint(LColor.gold)
        }
    }
}
