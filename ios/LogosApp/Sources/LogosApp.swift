import SwiftUI

// EXPERIMENTAL — UNAUDITED. Do not use for real secrets.
@main
struct LogosApp: App {
    @StateObject private var session = Session()

    @State private var showSplash = true

    var body: some Scene {
        WindowGroup {
            ZStack {
                Group {
                    if session.username == nil {
                        OnboardingView()
                    } else {
                        ConversationsView()
                    }
                }
                .environmentObject(session)

                if showSplash {
                    SplashView().transition(.opacity).zIndex(1)
                }
            }
            .tint(LColor.gold)
            .task {
                try? await Task.sleep(nanoseconds: 950_000_000)
                withAnimation(.easeOut(duration: 0.45)) { showSplash = false }
            }
        }
    }
}

/// Brief branded launch flourish — the column emblem + wordmark on the app canvas,
/// shown on cold start and faded into the app. (A SwiftUI splash, not the OS launch
/// screen, so there's no storyboard to render wrong on a device.)
struct SplashView: View {
    @State private var appear = false
    var body: some View {
        ZStack {
            LColor.canvas.ignoresSafeArea()
            Image("Wordmark")
                .resizable()
                .scaledToFit()
                .frame(width: 248)
                .scaleEffect(appear ? 1 : 0.94)
            .opacity(appear ? 1 : 0)
        }
        .onAppear { withAnimation(.easeOut(duration: 0.5)) { appear = true } }
    }
}
