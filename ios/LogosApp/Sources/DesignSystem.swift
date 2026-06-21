import SwiftUI
import UIKit

// Logos design system — tokens + reusable components.
//
// Direction: "quiet classical modernism." Warm paper-light / warm-charcoal-dark
// base, ONE restrained gold accent (from the column brand mark), a serif used only
// for display moments paired with the system sans for UI. Security states are
// always icon + text + color (never color alone) so they survive color-blindness,
// grayscale, and VoiceOver.
//
// Targets iOS 16 / Swift 5.9. iOS-17-only niceties are gated at the call site.

// MARK: - Color

extension Color {
    /// Adaptive color from two hex literals (light / dark).
    init(hex light: UInt, dark: UInt) {
        self.init(uiColor: UIColor { tc in
            UIColor(rgb: tc.userInterfaceStyle == .dark ? dark : light)
        })
    }
}

private extension UIColor {
    convenience init(rgb: UInt, alpha: CGFloat = 1) {
        self.init(
            red:   CGFloat((rgb >> 16) & 0xFF) / 255,
            green: CGFloat((rgb >> 8)  & 0xFF) / 255,
            blue:  CGFloat( rgb        & 0xFF) / 255,
            alpha: alpha
        )
    }
}

/// Logos palette. Warm neutrals + a single gold accent. Greens/ambers/reds are
/// reserved strictly for security semantics and used sparingly.
enum LColor {
    // Canvas & surfaces
    static let canvas      = Color(hex: 0xFAF7F1, dark: 0x15120D) // app background
    static let surface     = Color(hex: 0xFFFEFB, dark: 0x1C1813) // cards, rows, sheets
    static let surfaceAlt  = Color(hex: 0xF1ECE2, dark: 0x262019) // inbound bubble, chips
    static let hairline    = Color(hex: 0xE7E0D4, dark: 0x2E2820) // 1px separators

    // Text
    static let ink         = Color(hex: 0x1A1714, dark: 0xF4EFE6) // primary
    static let inkSecondary = Color(hex: 0x6B6357, dark: 0xA89C88) // secondary
    static let inkTertiary  = Color(hex: 0x9A9180, dark: 0x6F6557) // timestamps, hints

    // Accent (gold) — saturated for fills/icons; goldText is contrast-tuned for text.
    static let gold        = Color(hex: 0xB0894F, dark: 0xCBA468)
    static let goldText    = Color(hex: 0x8A6A38, dark: 0xD9B777)
    static let goldWash    = Color(hex: 0xF3E9D6, dark: 0x2C2415) // tonal fill behind gold icons
    static let onGold      = Color(hex: 0x231D12, dark: 0x1A140A) // text/glyphs ON a solid gold fill (dark in both modes)

    // Message bubbles — soft tints with ink/cream text (accessible; not solid-accent
    // "iMessage blue"). Mine is gold-tinted; theirs is neutral warm.
    static let bubbleMine     = Color(hex: 0xEFE2C7, dark: 0x322817)
    static let bubbleMineText = Color(hex: 0x231D12, dark: 0xF4EFE6)

    // Security semantics
    static let secure   = goldText                         // quiet "encrypted"
    static let verified = Color(hex: 0x3E7D55, dark: 0x6FBF8C) // only after safety-number compare
    static let caution  = Color(hex: 0xB2741A, dark: 0xE0A23E) // identity changed
    static let danger   = Color(hex: 0xC0392B, dark: 0xE3675B) // failed / can't decrypt
}

// MARK: - Type

/// Type ramp. Display/title use the serif (the Logos signature); body uses the
/// system sans. All scale with Dynamic Type.
enum LFont {
    static let display  = Font.system(.largeTitle, design: .serif).weight(.bold)
    static let title    = Font.system(.title2,     design: .serif).weight(.semibold)
    static let title3   = Font.system(.title3,     design: .serif).weight(.semibold)
    static let headline = Font.system(.headline)
    static let body     = Font.system(.body)
    static let callout  = Font.system(.callout)
    static let subhead  = Font.system(.subheadline)
    static let footnote = Font.system(.footnote)
    static let caption  = Font.system(.caption)
    static let mono     = Font.system(.body, design: .monospaced) // safety numbers, ids
}

// MARK: - Metrics

enum Space {
    static let xxs: CGFloat = 4
    static let xs:  CGFloat = 8
    static let sm:  CGFloat = 12
    static let md:  CGFloat = 16
    static let lg:  CGFloat = 24
    static let xl:  CGFloat = 32
    static let xxl: CGFloat = 48
}

enum Radius {
    static let bubble:  CGFloat = 18
    static let card:    CGFloat = 16
    static let control: CGFloat = 14
    static let pill:    CGFloat = 999
}

enum Motion {
    static let micro    = Animation.easeOut(duration: 0.12)
    static let standard = Animation.easeInOut(duration: 0.22)
    static let bubble   = Animation.spring(response: 0.34, dampingFraction: 0.82)
}

// MARK: - Haptics

enum Haptic {
    static func tap()   { UIImpactFeedbackGenerator(style: .light).impactOccurred() }
    static func send()  { UIImpactFeedbackGenerator(style: .soft).impactOccurred() }
    static func warn()  { UINotificationFeedbackGenerator().notificationOccurred(.warning) }
    static func error() { UINotificationFeedbackGenerator().notificationOccurred(.error) }
}

// MARK: - Modifiers

extension View {
    /// Canvas background, optionally with the faint λόγος wordmark watermark behind.
    func logosBackground(watermark: Bool = false) -> some View {
        background {
            ZStack {
                LColor.canvas
                if watermark { LogosWatermark() }
            }
            .ignoresSafeArea()
        }
    }

    /// Card surface: warm fill, hairline border, soft warm shadow.
    func cardStyle(padding: CGFloat = Space.md) -> some View {
        self.padding(padding)
            .background(LColor.surface)
            .clipShape(RoundedRectangle(cornerRadius: Radius.card, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: Radius.card, style: .continuous)
                    .strokeBorder(LColor.hairline, lineWidth: 1)
            )
            .shadow(color: Color.black.opacity(0.05), radius: 14, x: 0, y: 6)
    }
}

// MARK: - Watermark

/// Faint, centered λόγος wordmark for screen backgrounds. Uses the asset as a
/// template tinted to `ink` (adaptive: dark on light, cream on dark) at a low,
/// scheme-aware opacity so it never competes with content. Non-interactive.
struct LogosWatermark: View {
    @Environment(\.colorScheme) private var scheme
    var widthFraction: CGFloat = 0.72
    /// Vertical center as a fraction of height (0.5 = middle). Lower it on screens
    /// whose content is centered (e.g. an empty state) so the mark isn't obscured.
    var yFraction: CGFloat = 0.5

    var body: some View {
        GeometryReader { geo in
            Image("WordmarkGreek")
                .renderingMode(.template)
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(width: min(geo.size.width * widthFraction, 360))
                .foregroundStyle(LColor.ink)
                .opacity(scheme == .dark ? 0.07 : 0.055)
                .position(x: geo.size.width / 2, y: geo.size.height * yFraction)
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}

// MARK: - Buttons

struct LogosPrimaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(LFont.headline)
            .foregroundStyle(LColor.onGold)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 15)
            .background(enabled ? LColor.gold : LColor.gold.opacity(0.4))
            .clipShape(RoundedRectangle(cornerRadius: Radius.control, style: .continuous))
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
            .animation(Motion.micro, value: configuration.isPressed)
    }
}

struct LogosSecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(LFont.headline)
            .foregroundStyle(LColor.goldText)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 15)
            .background(LColor.goldWash)
            .clipShape(RoundedRectangle(cornerRadius: Radius.control, style: .continuous))
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
            .animation(Motion.micro, value: configuration.isPressed)
    }
}

extension ButtonStyle where Self == LogosPrimaryButtonStyle {
    static var logosPrimary: LogosPrimaryButtonStyle { .init() }
}
extension ButtonStyle where Self == LogosSecondaryButtonStyle {
    static var logosSecondary: LogosSecondaryButtonStyle { .init() }
}

// MARK: - Avatar

/// Deterministic monogram avatar with a thin gold ring. Restrained, warm tints.
struct LAvatar: View {
    let name: String
    var image: UIImage? = nil
    var size: CGFloat = 46

    private static let tints: [Color] = [
        Color(hex: 0xB0894F, dark: 0xCBA468), // gold
        Color(hex: 0x7C8B6B, dark: 0x9FB089), // sage
        Color(hex: 0x8A6E8F, dark: 0xB295B6), // mauve
        Color(hex: 0x6F8694, dark: 0x95AFBE), // slate-blue
        Color(hex: 0xA9714E, dark: 0xC79670), // terracotta
    ]
    private var tint: Color {
        let h = name.unicodeScalars.reduce(0) { $0 &+ Int($1.value) }
        return Self.tints[abs(h) % Self.tints.count]
    }
    private var initials: String {
        let parts = name.split(whereSeparator: { " ._-".contains($0) }).prefix(2)
        let s = parts.compactMap { $0.first }.map(String.init).joined()
        return (s.isEmpty ? String(name.prefix(1)) : s).uppercased()
    }

    var body: some View {
        Group {
            if let image {
                Image(uiImage: image).resizable().scaledToFill()
                    .frame(width: size, height: size)
                    .clipShape(Circle())
                    .overlay(Circle().strokeBorder(LColor.gold.opacity(0.5), lineWidth: 1))
            } else {
                Text(initials)
                    .font(.system(size: size * 0.4, weight: .semibold, design: .serif))
                    .foregroundStyle(tint)
                    .frame(width: size, height: size)
                    .background(tint.opacity(0.16))
                    .clipShape(Circle())
                    .overlay(Circle().strokeBorder(tint.opacity(0.45), lineWidth: 1))
            }
        }
        .accessibilityHidden(true)
    }
}

// MARK: - Security chip

/// Compact, contextual security indicator. Always icon + label + color.
struct SecurityChip: View {
    enum Level {
        case encrypted, verified, changed, failed, decryptFailed, experimental

        var icon: String {
            switch self {
            case .encrypted:     return "lock.fill"
            case .verified:      return "checkmark.shield.fill"
            case .changed:       return "exclamationmark.shield.fill"
            case .failed:        return "exclamationmark.circle.fill"
            case .decryptFailed: return "lock.trianglebadge.exclamationmark"
            case .experimental:  return "flask.fill"
            }
        }
        var label: String {
            switch self {
            case .encrypted:     return "Encrypted"
            case .verified:      return "Verified"
            case .changed:       return "Identity changed"
            case .failed:        return "Not delivered"
            case .decryptFailed: return "Can’t decrypt"
            case .experimental:  return "Experimental build"
            }
        }
        var tint: Color {
            switch self {
            case .encrypted:     return LColor.secure
            case .verified:      return LColor.verified
            case .changed:       return LColor.caution
            case .failed, .decryptFailed: return LColor.danger
            case .experimental:  return LColor.inkSecondary
            }
        }
    }

    let level: Level
    var compact = false

    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: level.icon).font(.system(size: compact ? 11 : 12, weight: .semibold))
            if !compact { Text(level.label).font(LFont.caption).fontWeight(.medium) }
        }
        .foregroundStyle(level.tint)
        .padding(.horizontal, compact ? 0 : 8)
        .padding(.vertical, compact ? 0 : 4)
        .background(compact ? Color.clear : level.tint.opacity(0.12), in: Capsule())
        .accessibilityElement()
        .accessibilityLabel(level.label)
    }
}

// MARK: - Banner

/// Full-width contextual banner (experimental notice, offline, identity changed).
struct LBanner: View {
    enum Tone { case neutral, caution, danger
        var tint: Color {
            switch self { case .neutral: return LColor.inkSecondary
                          case .caution: return LColor.caution
                          case .danger:  return LColor.danger }
        }
    }
    let tone: Tone
    let icon: String
    let title: String
    var message: String? = nil
    var actionTitle: String? = nil
    var action: (() -> Void)? = nil

    var body: some View {
        HStack(alignment: .top, spacing: Space.sm) {
            Image(systemName: icon)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(tone.tint)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(LFont.subhead).fontWeight(.semibold).foregroundStyle(LColor.ink)
                if let message {
                    Text(message).font(LFont.footnote).foregroundStyle(LColor.inkSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 0)
            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .font(LFont.footnote.weight(.semibold))
                    .foregroundStyle(tone.tint)
            }
        }
        .padding(Space.sm)
        .background(tone.tint.opacity(0.10))
        .overlay(alignment: .leading) { Rectangle().fill(tone.tint).frame(width: 3) }
        .clipShape(RoundedRectangle(cornerRadius: Radius.control, style: .continuous))
    }
}

// MARK: - Offline banner

/// Shown at the top of the chat list / a thread when the last relay sync failed.
/// Reassures (messages will retry) and offers a manual retry. Caution, not alarm.
struct OfflineBanner: View {
    let onRetry: () -> Void
    var body: some View {
        LBanner(tone: .caution, icon: "wifi.slash",
                title: "Offline",
                message: "Can’t reach the relay — messages will retry automatically.",
                actionTitle: "Retry", action: onRetry)
            .padding(.horizontal, Space.md)
            .padding(.vertical, Space.xs)
            .background(LColor.canvas)
            .transition(.move(edge: .top).combined(with: .opacity))
    }
}

// MARK: - Empty state

struct LEmptyState: View {
    var icon: String? = nil
    let title: String
    let message: String
    var actionTitle: String? = nil
    var action: (() -> Void)? = nil

    var body: some View {
        VStack(spacing: Space.md) {
            if let icon {
                Image(systemName: icon)
                    .font(.system(size: 40, weight: .light))
                    .foregroundStyle(LColor.goldText)
                    .frame(width: 84, height: 84)
                    .background(LColor.goldWash, in: Circle())
            }
            VStack(spacing: Space.xs) {
                Text(title).font(LFont.title3).foregroundStyle(LColor.ink)
                Text(message)
                    .font(LFont.subhead).foregroundStyle(LColor.inkSecondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .buttonStyle(.logosSecondary)
                    .fixedSize()
            }
        }
        .padding(Space.xl)
    }
}
