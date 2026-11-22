import CoreImage
import PhotosUI
import SwiftUI
import VisionKit

/// Setting up a verification code as in Apple's Passwords: scan the site's
/// QR code with the camera, or pick a screenshot or photo of it. Hands back
/// the `otpauth://` link it holds (only one that makes codes).
struct CodeScannerView: View {
    let found: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var photo: PhotosPickerItem?
    @State private var error: String?
    @State private var done = false

    var body: some View {
        NavigationStack {
            Group {
                if DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
                    QRScanner { finish($0) }.ignoresSafeArea(edges: .bottom)
                } else {
                    ContentUnavailableView(
                        "Camera Unavailable", systemImage: "camera",
                        description: Text("Choose a screenshot of the QR code instead, or type the setup key in the editor."))
                }
            }
            .safeAreaInset(edge: .bottom) {
                VStack(spacing: 10) {
                    if let error {
                        Text(error).font(.footnote).foregroundStyle(.white).padding(8)
                            .background(.red.opacity(0.85), in: RoundedRectangle(cornerRadius: 8))
                    }
                    PhotosPicker(selection: $photo, matching: .images) {
                        Label("Choose Photo or Screenshot…", systemImage: "photo")
                    }
                    .buttonStyle(.borderedProminent)
                }
                .padding()
            }
            .navigationTitle("Scan QR Code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
            .onChange(of: photo) { _, item in
                Task { await read(item) }
            }
        }
    }

    private func finish(_ text: String) {
        guard !done else { return }
        guard isValidTotp(secret: text) else {
            error = "That QR code isn't for setting up a verification code."
            return
        }
        done = true
        found(text)
        dismiss()
    }

    /// The QR codes in a picked image.
    private func read(_ item: PhotosPickerItem?) async {
        guard let item else { return }
        guard let data = try? await item.loadTransferable(type: Data.self), let image = CIImage(data: data) else {
            error = "That image can't be opened."
            return
        }
        let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        let codes = (detector?.features(in: image) ?? []).compactMap { ($0 as? CIQRCodeFeature)?.messageString }
        if let code = codes.first(where: { isValidTotp(secret: $0) }) {
            finish(code)
        } else {
            error = codes.isEmpty ? "There's no QR code in that image." : "That QR code isn't for setting up a verification code."
        }
    }

    /// The site and account an `otpauth://totp/Site:account?issuer=Site`
    /// link names, to fill in a new login's name and user name.
    static func label(of uri: String) -> (issuer: String?, account: String?) {
        guard let c = URLComponents(string: uri), c.scheme?.lowercased() == "otpauth" else { return (nil, nil) }
        let path = String(c.path.drop { $0 == "/" })
        let parts = path.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
        let issuerParam = c.queryItems?.first { $0.name.lowercased() == "issuer" }?.value
        let issuer = issuerParam ?? (parts.count == 2 ? parts[0] : nil)
        let account = parts.last
        func clean(_ s: String?) -> String? { s.flatMap { $0.isEmpty ? nil : $0 } }
        return (clean(issuer), clean(account))
    }
}

/// VisionKit's live scanner, for QR codes.
private struct QRScanner: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let vc = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])], qualityLevel: .balanced,
            recognizesMultipleItems: false, isHighFrameRateTrackingEnabled: false, isHighlightingEnabled: true)
        vc.delegate = context.coordinator
        // Started once it's on screen.
        DispatchQueue.main.async { try? vc.startScanning() }
        return vc
    }

    func updateUIViewController(_ vc: DataScannerViewController, context: Context) {}

    static func dismantleUIViewController(_ vc: DataScannerViewController, coordinator: Coordinator) {
        vc.stopScanning()
    }

    func makeCoordinator() -> Coordinator { Coordinator(onCode: onCode) }

    @MainActor
    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let onCode: (String) -> Void
        init(onCode: @escaping (String) -> Void) { self.onCode = onCode }

        private func take(_ items: [RecognizedItem]) {
            for item in items {
                if case .barcode(let code) = item, let text = code.payloadStringValue {
                    onCode(text)
                    return
                }
            }
        }

        func dataScanner(_ dataScanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            take(addedItems)
        }

        func dataScanner(_ dataScanner: DataScannerViewController, didTapOn item: RecognizedItem) {
            take([item])
        }
    }
}
