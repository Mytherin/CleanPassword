import CryptoKit
import Foundation

/// Compromised passwords, as Apple's Passwords detects them: whether a
/// password appears in known data leaks, from Have I Been Pwned's
/// k-anonymity range API. Only the first five hex digits of the password's
/// SHA-1 leave the iPhone; the site answers with every leaked hash that
/// starts with them (padded, so the answer's size says nothing), and the
/// match is made here.
actor Breaches {
    static let shared = Breaches()
    static let settingKey = "detectCompromised"

    /// The leaked hash suffixes and counts for each prefix asked about.
    private var ranges: [String: [Substring: Int]] = [:]
    private static let session = URLSession(configuration: .ephemeral)

    /// How many times each password appears in leaks (0: not found), by
    /// password. Throws if the service can't be reached.
    func counts(for passwords: Set<String>) async throws -> [String: Int] {
        let hashes = Dictionary(uniqueKeysWithValues: passwords.map { ($0, Self.sha1(Data($0.utf8))) })
        let missing = Set(hashes.values.map { String($0.prefix(5)) }).filter { ranges[$0] == nil }
        let fetched = try await withThrowingTaskGroup(of: (String, [Substring: Int]).self) { group -> [(String, [Substring: Int])] in
            for prefix in missing {
                group.addTask { (prefix, try await Self.fetch(prefix)) }
            }
            var out: [(String, [Substring: Int])] = []
            for try await r in group { out.append(r) }
            return out
        }
        for (prefix, range) in fetched { ranges[prefix] = range }
        return hashes.mapValues { hash in ranges[String(hash.prefix(5))]?[hash.dropFirst(5)] ?? 0 }
    }

    private static func sha1(_ data: Data) -> String {
        Insecure.SHA1.hash(data: data).map { String(format: "%02X", $0) }.joined()
    }

    private static func fetch(_ prefix: String) async throws -> [Substring: Int] {
        var request = URLRequest(url: URL(string: "https://api.pwnedpasswords.com/range/\(prefix)")!, timeoutInterval: 15)
        request.setValue("true", forHTTPHeaderField: "Add-Padding")
        request.setValue("CleanPassword", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await session.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200, let text = String(data: data, encoding: .utf8) else {
            throw URLError(.badServerResponse)
        }
        var out: [Substring: Int] = [:]
        for line in text.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: ":")
            // Padding lines have a count of 0.
            guard parts.count == 2, let n = Int(parts[1].trimmingCharacters(in: .whitespaces)), n > 0 else { continue }
            out[Substring(parts[0].uppercased())] = n
        }
        return out
    }
}
