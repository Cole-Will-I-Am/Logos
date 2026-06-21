import SwiftUI
import LogosKit
import PhotosUI

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
    @State private var photoItem: PhotosPickerItem?
    @State private var nickname = ""

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
                if info?.safetyNumber != nil { reconnectCard }
                customizeCard
            }
            .padding(Space.lg)
            .frame(maxWidth: 520).frame(maxWidth: .infinity)
        }
        .logosBackground(watermark: true)
        .navigationTitle("Verify \(peer)")
        .navigationBarTitleDisplayMode(.inline)
        .task { await refresh(); nickname = session.nicknames[peer] ?? "" }
        .onChange(of: photoItem) { item in
            Task {
                if let data = try? await item?.loadTransferable(type: Data.self), let img = UIImage(data: data) {
                    session.setAvatar(img, for: peer)
                }
            }
        }
        .onDisappear { session.setNickname(nickname, for: peer) }
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
            LAvatar(name: peer, image: session.avatars[peer], size: 72)
            Text(session.displayName(for: peer)).font(LFont.title3).foregroundStyle(LColor.ink)
            if session.displayName(for: peer) != peer {
                Text("@\(peer)").font(LFont.footnote).foregroundStyle(LColor.inkTertiary)
            }
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

    private var reconnectCard: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            Label("Not receiving their messages?", systemImage: "arrow.triangle.2.circlepath")
                .font(LFont.subhead.weight(.medium)).foregroundStyle(LColor.ink)
            Text("If \(peer) restored their account from a recovery phrase (or reinstalled with the same identity), your secure session can go stale. Reset it to reconnect, then ask them to send a message. Your verification is kept.")
                .font(LFont.footnote).foregroundStyle(LColor.inkSecondary)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                Task { working = true; await session.resetSession(peer); await refresh(); working = false }
            } label: {
                Text("Reset secure session").frame(maxWidth: .infinity)
            }
            .buttonStyle(.logosSecondary)
            .disabled(working)
        }
        .cardStyle()
    }

    private var customizeCard: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            Text("THIS DEVICE ONLY").font(LFont.caption).fontWeight(.semibold)
                .foregroundStyle(LColor.inkTertiary).tracking(0.6)
            HStack(spacing: Space.sm) {
                PhotosPicker(selection: $photoItem, matching: .images) {
                    Label(session.avatars[peer] == nil ? "Set photo" : "Change photo", systemImage: "photo")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.logosSecondary)
                if session.avatars[peer] != nil {
                    Button(role: .destructive) { session.removeAvatar(for: peer) } label: {
                        Label("Remove", systemImage: "trash").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.logosSecondary)
                }
            }
            TextField("Nickname (optional)", text: $nickname)
                .textInputAutocapitalization(.words)
                .padding(.horizontal, Space.sm).padding(.vertical, 10)
                .background(LColor.surfaceAlt)
                .clipShape(RoundedRectangle(cornerRadius: Radius.control, style: .continuous))
                .submitLabel(.done)
                .onSubmit { session.setNickname(nickname, for: peer) }
            Text("A photo or name you set here is stored only on this device — never shared or uploaded.")
                .font(LFont.caption).foregroundStyle(LColor.inkTertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .cardStyle()
    }

    /// "12345 12345 12345 12345 12345 12345" → two rows of three groups.
    private func twoRows(_ sn: String) -> String {
        let g = sn.split(separator: " ").map(String.init)
        guard g.count == 6 else { return sn }
        return g[0..<3].joined(separator: " ") + "\n" + g[3..<6].joined(separator: " ")
    }
}
