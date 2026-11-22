import SwiftUI
import UIKit

/// An item's icon, as in Apple's Passwords: the website's own icon (its
/// apple-touch-icon, else its favicon), fetched from the site once and
/// kept in the app's cache. The letter monogram shows until then, for items
/// without a website or whose site has no icon, and with icons turned off
/// in Settings.
struct SiteIcon: View {
    let name: String
    let host: String?
    var size: CGFloat = 32
    @AppStorage(SiteIcons.settingKey) private var on = true
    @State private var image: UIImage?

    var body: some View {
        Group {
            if on, let image {
                Image(uiImage: image)
                    .resizable()
                    .interpolation(.high)
                    .scaledToFit()
                    .frame(width: size, height: size)
                    .background(Color.white)
                    .clipShape(RoundedRectangle(cornerRadius: size * 0.24, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: size * 0.24, style: .continuous).stroke(Color(.separator), lineWidth: 0.5))
            } else {
                Monogram(name: name, size: size)
            }
        }
        .task(id: on ? host : nil) {
            guard on, let host else {
                image = nil
                return
            }
            image = await SiteIcons.shared.icon(for: host)
        }
    }
}

/// Fetches and caches website icons. Requests go to the site itself, over
/// HTTPS, without cookies; a site without an icon isn't asked again for a
/// week.
actor SiteIcons {
    static let shared = SiteIcons()
    static let settingKey = "siteIcons"

    private var memory: [String: UIImage] = [:]
    private var missing: Set<String> = []
    private var inFlight: [String: Task<UIImage?, Never>] = [:]

    private static let session = URLSession(configuration: .ephemeral)

    static var directory: URL {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("SiteIcons", isDirectory: true)
    }

    /// Forgets every icon (icons turned off).
    static func clear() {
        try? FileManager.default.removeItem(at: directory)
    }

    func icon(for host: String) async -> UIImage? {
        let key = host.lowercased()
        // Only plain host names (they're file names here).
        guard !key.isEmpty, key.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" }), !key.hasPrefix(".") else { return nil }
        if let image = memory[key] { return image }
        if missing.contains(key) { return nil }
        if let task = inFlight[key] { return await task.value }
        let task = Task { await Self.load(key) }
        inFlight[key] = task
        let image = await task.value
        inFlight[key] = nil
        if let image { memory[key] = image } else { missing.insert(key) }
        return image
    }

    private static func load(_ host: String) async -> UIImage? {
        let dir = directory
        let file = dir.appendingPathComponent("\(host).png")
        let none = dir.appendingPathComponent("\(host).none")
        if let data = try? Data(contentsOf: file), let image = UIImage(data: data) { return image }
        if let date = (try? FileManager.default.attributesOfItem(atPath: none.path))?[.modificationDate] as? Date,
           Date().timeIntervalSince(date) < 7 * 86400 {
            return nil
        }
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        for path in ["/apple-touch-icon.png", "/apple-touch-icon-precomposed.png", "/favicon.ico"] {
            guard let url = URL(string: "https://\(host)\(path)") else { continue }
            let request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 8)
            guard let (data, response) = try? await session.data(for: request),
                  (response as? HTTPURLResponse)?.statusCode == 200,
                  data.count < 1_000_000,
                  let image = UIImage(data: data), image.size.width >= 16
            else { continue }
            try? image.pngData()?.write(to: file, options: .atomic)
            return image
        }
        FileManager.default.createFile(atPath: none.path, contents: nil)
        return nil
    }
}
