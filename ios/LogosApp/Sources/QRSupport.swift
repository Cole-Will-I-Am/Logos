import SwiftUI
import AVFoundation
import CoreImage.CIFilterBuiltins

// QR payloads, generation, and a camera scanner — shared by verification (compare
// safety numbers) and contact add (scan a username to start a chat).

enum LogosQR {
    /// `logos://add?u=<username>&r=<relay>` — scan to start a chat.
    static func addPayload(username: String, relay: String) -> String {
        var c = URLComponents(); c.scheme = "logos"; c.host = "add"
        c.queryItems = [.init(name: "u", value: username), .init(name: "r", value: relay)]
        return c.string ?? "logos://add?u=\(username)"
    }

    /// `logos://verify?sn=<safety number>` — scan to compare safety numbers.
    static func verifyPayload(safetyNumber: String) -> String {
        var c = URLComponents(); c.scheme = "logos"; c.host = "verify"
        c.queryItems = [.init(name: "sn", value: safetyNumber)]
        return c.string ?? ""
    }

    static func parse(_ s: String) -> (host: String, query: [String: String])? {
        guard let c = URLComponents(string: s), c.scheme == "logos", let host = c.host else { return nil }
        var q: [String: String] = [:]
        for item in c.queryItems ?? [] where item.value != nil { q[item.name] = item.value }
        return (host, q)
    }

    /// Render a string to a crisp QR `UIImage` (CoreImage).
    static func image(_ string: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = "M"
        guard let out = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 10, y: 10)) else { return nil }
        let ctx = CIContext()
        guard let cg = ctx.createCGImage(out, from: out.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
}

/// Displays a QR code on a light card (QR needs high contrast to scan).
struct QRCodeView: View {
    let payload: String
    var size: CGFloat = 220
    var body: some View {
        Group {
            if let img = LogosQR.image(payload) {
                Image(uiImage: img).interpolation(.none).resizable().scaledToFit()
            } else {
                Image(systemName: "qrcode").resizable().scaledToFit().foregroundStyle(.gray)
            }
        }
        .frame(width: size, height: size)
        .padding(Space.md)
        .background(Color.white)
        .clipShape(RoundedRectangle(cornerRadius: Radius.card, style: .continuous))
        .accessibilityHidden(true)
    }
}

/// SwiftUI wrapper over an AVFoundation QR scanner. Calls `onScan` once.
struct QRScannerView: UIViewControllerRepresentable {
    let onScan: (String) -> Void
    func makeUIViewController(context: Context) -> ScannerVC {
        let vc = ScannerVC(); vc.onScan = onScan; return vc
    }
    func updateUIViewController(_ vc: ScannerVC, context: Context) {}
}

final class ScannerVC: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onScan: ((String) -> Void)?
    private let session = AVCaptureSession()
    private var preview: AVCaptureVideoPreviewLayer?
    private var handled = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized: configure()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { ok in
                DispatchQueue.main.async { ok ? self.configure() : self.showMessage("Camera access is needed to scan.") }
            }
        default: showMessage("Camera access is off — enable it in Settings to scan.")
        }
    }

    private func configure() {
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else { showMessage("No camera available."); return }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { showMessage("Can’t start the scanner."); return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        layer.frame = view.layer.bounds
        view.layer.addSublayer(layer)
        preview = layer
        DispatchQueue.global(qos: .userInitiated).async { self.session.startRunning() }
    }

    private func showMessage(_ text: String) {
        let label = UILabel()
        label.text = text; label.textColor = .white; label.numberOfLines = 0
        label.textAlignment = .center; label.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(label)
        NSLayoutConstraint.activate([
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            label.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 32),
            label.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -32),
        ])
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview?.frame = view.layer.bounds
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if session.isRunning { DispatchQueue.global(qos: .userInitiated).async { self.session.stopRunning() } }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput,
                        didOutput objects: [AVMetadataObject],
                        from connection: AVCaptureConnection) {
        guard !handled,
              let obj = objects.first as? AVMetadataMachineReadableCodeObject,
              let value = obj.stringValue else { return }
        handled = true
        Haptic.tap()
        onScan?(value)
    }
}

/// A presented scanner with a cancel button and a hint.
struct QRScanSheet: View {
    let title: String
    let onScan: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            QRScannerView { code in onScan(code); dismiss() }
                .ignoresSafeArea()
                .overlay(alignment: .bottom) {
                    Text("Point at a Logos QR code")
                        .font(LFont.subhead).foregroundStyle(.white)
                        .padding(.horizontal, Space.md).padding(.vertical, Space.xs)
                        .background(.black.opacity(0.55), in: Capsule())
                        .padding(.bottom, 48)
                }
                .navigationTitle(title)
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .topBarTrailing) { Button("Cancel") { dismiss() } }
                }
        }
    }
}
