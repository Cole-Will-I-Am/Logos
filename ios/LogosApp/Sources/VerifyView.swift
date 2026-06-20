import SwiftUI

/// Identity / safety-number screen.
///
/// FFI TODO: a real safety number needs the *identity fingerprint* of both parties
/// (e.g. `client.safetyNumber(with: peer) -> String` + `markVerified(peer:)` /
/// `isVerified(peer:)`). Those don't exist yet, so this screen renders the intended
/// design and is honest that verification isn't wired up. It does NOT fabricate a
/// number — showing a fake "verified" state would be the exact trust failure we’re
/// trying to design out.
struct VerifyView: View {
    @EnvironmentObject var session: Session
    let peer: String

    private var security: SessionSecurity { session.security(for: peer) }
    private let wired = false   // flip to true once the fingerprint FFI lands

    var body: some View {
        ScrollView {
            VStack(spacing: Space.lg) {
                header

                if security == .identityChanged {
                    LBanner(tone: .caution, icon: "exclamationmark.shield.fill",
                            title: "This identity changed",
                            message: "Re-verify \(peer) before trusting this conversation again.")
                }

                safetyNumberCard
                explanation
            }
            .padding(Space.lg)
            .frame(maxWidth: 520).frame(maxWidth: .infinity)
        }
        .logosBackground()
        .navigationTitle("Verify \(peer)")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var header: some View {
        VStack(spacing: Space.sm) {
            LAvatar(name: peer, size: 72)
            Text(peer).font(LFont.title3).foregroundStyle(LColor.ink)
            switch security {
            case .verified:        SecurityChip(level: .verified)
            case .identityChanged: SecurityChip(level: .changed)
            case .encrypted:       SecurityChip(level: .encrypted)
            }
        }
    }

    private var safetyNumberCard: some View {
        VStack(spacing: Space.md) {
            Text("SAFETY NUMBER").font(LFont.caption).fontWeight(.semibold)
                .foregroundStyle(LColor.inkTertiary).tracking(0.6)

            if wired {
                // Real path: 12 grouped 5-digit blocks of the combined fingerprint.
                Text("00000 00000 00000 00000\n00000 00000 00000 00000\n00000 00000 00000 00000")
                    .font(LFont.mono).foregroundStyle(LColor.ink)
                    .multilineTextAlignment(.center).lineSpacing(6)
                HStack(spacing: Space.sm) {
                    Button { Haptic.tap() } label: {
                        Label("Scan QR", systemImage: "qrcode.viewfinder").frame(maxWidth: .infinity)
                    }.buttonStyle(.logosSecondary)
                    Button { Haptic.tap() } label: {
                        Label("Mark verified", systemImage: "checkmark.shield").frame(maxWidth: .infinity)
                    }.buttonStyle(.logosPrimary)
                }
            } else {
                VStack(spacing: Space.sm) {
                    Image(systemName: "number.square")
                        .font(.system(size: 30, weight: .light)).foregroundStyle(LColor.inkTertiary)
                    Text("Identity verification isn’t wired up in this build yet.")
                        .font(LFont.subhead).foregroundStyle(LColor.inkSecondary)
                        .multilineTextAlignment(.center)
                    Text("Messages are still end-to-end encrypted and pinned to the first identity Logos saw for \(peer) (trust-on-first-use).")
                        .font(LFont.footnote).foregroundStyle(LColor.inkTertiary)
                        .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                }
                .padding(.vertical, Space.sm)
            }
        }
        .cardStyle()
    }

    private var explanation: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            Text("Compare this number with \(peer) in person, or over another channel you already trust. If both numbers match, no one is intercepting your conversation.")
                .font(LFont.footnote).foregroundStyle(LColor.inkSecondary)
                .fixedSize(horizontal: false, vertical: true)
            Text("Logos never asks you to trust the relay — only the number.")
                .font(LFont.footnote).foregroundStyle(LColor.goldText)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
