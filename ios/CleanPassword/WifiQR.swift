import CoreImage.CIFilterBuiltins
import UIKit

/// The QR code another phone joins a Wi-Fi network from, as Apple's
/// Passwords shows for each network.
enum WifiQR {
    /// `WIFI:T:WPA;S:<network>;P:<password>;;`, with `\ ; , : "` escaped
    /// (an open network has no password).
    static func payload(network: String, password: String) -> String {
        func escaped(_ s: String) -> String {
            s.reduce(into: "") { out, c in
                if "\\;,:\"".contains(c) { out.append("\\") }
                out.append(c)
            }
        }
        return password.isEmpty
            ? "WIFI:T:nopass;S:\(escaped(network));;"
            : "WIFI:T:WPA;S:\(escaped(network));P:\(escaped(password));;"
    }

    static func image(network: String, password: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(payload(network: network, password: password).utf8)
        filter.correctionLevel = "M"
        guard let code = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 10, y: 10)),
              let cg = CIContext().createCGImage(code, from: code.extent)
        else { return nil }
        return UIImage(cgImage: cg)
    }
}
