import Foundation

/// Which sites offer verification codes (TOTP), from 2fa.directory's
/// public list, to find logins that could have two-factor authentication
/// but don't (as Bitwarden's "inactive two-step login" report does). The
/// whole list is downloaded, about 250 KB, so nothing about the vault
/// leaves the iPhone; it's kept for a week.
actor TwoFactorDirectory {
    static let shared = TwoFactorDirectory()
    static let settingKey = "checkTwoFactor"

    private static let url = URL(string: "https://api.2fa.directory/v3/totp.json")!
    private static var file: URL {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("2fa-directory-totp.json")
    }

    /// Registrable domain → the site's instructions for turning it on.
    private var sites: [String: URL?]?

    /// The sites, by registrable domain (fetched, or from the cache).
    func load() async throws -> [String: URL?] {
        if let sites { return sites }
        let fresh = (try? FileManager.default.attributesOfItem(atPath: Self.file.path))?[.modificationDate] as? Date
        var data: Data?
        if let fresh, Date().timeIntervalSince(fresh) < 7 * 86400 {
            data = try? Data(contentsOf: Self.file)
        }
        if data == nil {
            let (fetched, response) = try await URLSession(configuration: .ephemeral).data(from: Self.url)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
            try? fetched.write(to: Self.file, options: .atomic)
            data = fetched
        }
        let parsed = Self.parse(data ?? Data())
        sites = parsed
        return parsed
    }

    /// `[[name, {domain, "additional-domains", documentation, …}], …]`.
    static func parse(_ data: Data) -> [String: URL?] {
        guard let entries = (try? JSONSerialization.jsonObject(with: data)) as? [[Any]] else { return [:] }
        var out: [String: URL?] = [:]
        for entry in entries {
            guard entry.count == 2, let info = entry[1] as? [String: Any], let domain = info["domain"] as? String else { continue }
            let docs = (info["documentation"] as? String).flatMap(URL.init(string:))
            let domains = [domain] + (info["additional-domains"] as? [String] ?? [])
            for d in domains {
                out[registrableDomain(host: d.lowercased())] = docs
            }
        }
        return out
    }
}
