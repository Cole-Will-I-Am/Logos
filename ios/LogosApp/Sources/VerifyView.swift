import SwiftUI
import LogosKit

/// Identity verification — real safety numbers from the Rust core.
/// Compare the number out-of-band, mark verified, and recover from a legitimate
/// identity change (e.g. the peer reinstalled). No QR yet — that's the next step.
struct VerifyView: View {
    @EnvironmentObject var session: Session
    let peer: String

    @State private var info: ContactSecurity?
    @State private var loading = true
    @State private var working = false
    @State private var showQR = false
    @State private var showScan = false
    @State private var mismatch = false

    private var verified: Bool { info?.verified ?? false }
    private var changed: Bool { (info?.keyChanges ?? 0) > 0 }
    private var changeCountSuffix: String {
        let n = info?.keyChanges ?? 0
        return n > 1 ? " (\(n)×)" : ""
    }

    var body: some View {
        ScrollView {
            VStack(spacing: Space.lg) {
                header
                if changed && !verified { changeNotice }
                safetyNumberCard
                explanation
            }
            .padding(Space.lg)
            .frame(maxWidth: 520).frame(maxWidth: .infinity)
        }
        .logosBackground(watermark: true)
        .navigationTitle("Verify \(peer)")
        .navigationBarTitleDisplayMode(.inline)
        .task { await refresh() }
        .sheet(isPresented: $showQR) {
            if let sn = info?.safetyNumber { qrSheet(sn) }
        }
        .sheet(isPresented: $showScan) {
            QRScanSheet(title: "Scan \(peer)’s code") { handleScan($0) }
        }
        .alert("Numbers don’t match", isPresented: $mismatch) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("The scanned safety number doesn’t match — don’t trust this conversation; someone may be intercepting it.")
        }
    }

    private func refresh() async {
        info = await session.contactSecurity(peer)
        loading = false
    }

    private func handleScan(_ code: String) {
        guard let (host, q) = LogosQR.parse(code), host == "verify", let scanned = q["sn"] else {
            Haptic.warn(); mismatch = true; return
        }
        if scanned == info?.safetyNumber {
            Task { working = true; await session.markVerified(peer); await refresh(); working = false }
        } else {
            Haptic.warn(); mismatch = true
        }
    }

    private func qrSheet(_ sn: String) -> some View {
        NavigationStack {
            VStack(spacing: Space.lg) {
                QRCodeView(payload: LogosQR.verifyPayload(safetyNumber: sn))
                Text("Have \(peer) scan this from the **Scan** button on their Verify screen. If it matches, you’re both verified.")
                    .font(LFont.subhead).foregroundStyle(LColor.inkSecondary)
                    .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                Spacer()
            }
            .padding(Space.lg)
            .logosBackground()
            .navigationTitle("Your code for \(peer)")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .topBarTrailing) { Button("Done") { showQR = false } } }
        }
    }

    private var header: some View {
        VStack(spacing: Space.sm) {
            LAvatar(name: peer, size: 72)
            Text(peer).font(LFont.title3).foregroundStyle(LColor.ink)
            if verified {
                VStack(spacing: 4) {
                    SecurityChip(level: .verified)
                    if let at = info?.verifiedAt {
                        Text("Verified \(Date(timeIntervalSince1970: Double(at)).formatted(date: .abbreviated, time: .shortened))")
                            .font(LFont.caption).foregroundStyle(LColor.inkTertiary)
                    }
                }
            } else {
                SecurityChip(level: changed ? .changed : .encrypted)
            }
        }
    }

    private var changeNotice: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            Label("\(peer)’s identity changed\(changeCountSuffix)", systemImage: "exclamationmark.shield.fill")
                .font(LFont.headline).foregroundStyle(LColor.caution)
            Text("If \(peer) reinstalled Logos or switched devices, this is expected — reset and re-verify. If you didn’t expect it, don’t send anything sensitive until you’ve confirmed it’s really them.")
                .font(LFont.footnote).foregroundStyle(LColor.ink)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                Task { working = true; await session.resetPeerIdentity(peer); await refresh(); working = false }
            } label: {
                Text("They reinstalled — reset & re-verify").frame(maxWidth: .infinity)
            }
            .buttonStyle(.logosSecondary)
            .disabled(working)
        }
        .padding(Space.md)
        .background(LColor.caution.opacity(0.10))
        .overlay(RoundedRectangle(cornerRadius: Radius.card, style: .continuous)
            .strokeBorder(LColor.caution.opacity(0.4), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: Radius.card, style: .continuous))
    }

    private var safetyNumberCard: some View {
        VStack(spacing: Space.md) {
            Text("SAFETY NUMBER").font(LFont.caption).fontWeight(.semibold)
                .foregroundStyle(LColor.inkTertiary).tracking(0.6)

            if let sn = info?.safetyNumber {
                Text(twoRows(sn))
                    .font(LFont.mono).foregroundStyle(LColor.ink)
                    .multilineTextAlignment(.center).lineSpacing(6)
                    .textSelection(.enabled)
                HStack(spacing: Space.sm) {
                    Button { showQR = true } label: {
                        Label("Show QR", systemImage: "qrcode").frame(maxWidth: .infinity)
                    }.buttonStyle(.logosSecondary)
                    Button { showScan = true } label: {
                        Label("Scan", systemImage: "qrcode.viewfinder").frame(maxWidth: .infinity)
                    }.buttonStyle(.logosSecondary)
                }
                if verified {
                    Label("Verified", systemImage: "checkmark.shield.fill")
                        .font(LFont.headline).foregroundStyle(LColor.verified)
                } else {
                    Button {
                        Task { working = true; await session.markVerified(peer); await refresh(); working = false }
                    } label: {
                        Label("Mark as verified", systemImage: "checkmark.shield").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.logosPrimary)
                    .disabled(working)
                }
            } else if loading {
                ProgressView().padding(.vertical, Space.sm)
            } else {
                VStack(spacing: Space.xs) {
                    Image(systemName: "number.square")
                        .font(.system(size: 28, weight: .light)).foregroundStyle(LColor.inkTertiary)
                    Text("Send a message first").font(LFont.subhead).foregroundStyle(LColor.inkSecondary)
                    Text("The safety number appears once Logos has set up a secure session with \(peer).")
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

    /// "12345 12345 12345 12345 12345 12345" → two rows of three groups.
    private func twoRows(_ sn: String) -> String {
        let g = sn.split(separator: " ").map(String.init)
        guard g.count == 6 else { return sn }
        return g[0..<3].joined(separator: " ") + "\n" + g[3..<6].joined(separator: " ")
    }
}
