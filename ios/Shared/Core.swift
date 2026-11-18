import Foundation

/// The App Group the app and its AutoFill extension share: the saved vault
/// (sealed: see core/src/vault.rs) is a file in its container, and the
/// Face ID key is a keychain item in its access group.
enum AppGroup {
    static let id = "group.com.cleanpassword.app"

    static var container: URL {
        if let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: id) {
            return url
        }
        // Unsigned builds (tests, the simulator without a team) have no
        // group: fall back to the app's own folder.
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    }
}

/// The vault as this device keeps it: one string, in which everything but
/// the S3 settings is encrypted with the vault key.
enum SavedVault {
    static var url: URL { AppGroup.container.appendingPathComponent("vault.json") }

    static func load() -> String? {
        try? String(contentsOf: url, encoding: .utf8)
    }

    static func store(_ text: String) throws {
        try FileManager.default.createDirectory(at: AppGroup.container, withIntermediateDirectories: true)
        // Also encrypted by iOS until the phone is first unlocked after a
        // restart (the AutoFill extension needs it after that).
        try Data(text.utf8).write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    static func remove() {
        try? FileManager.default.removeItem(at: url)
    }
}

/// Runs the core's calls one at a time on a queue of their own: a sync
/// blocks on the network while holding the vault, and the UI mustn't wait
/// for that on the main thread.
final class Core: @unchecked Sendable {
    static let shared = Core()
    private let queue = DispatchQueue(label: "cleanpassword.core", qos: .userInitiated)
    private var session: VaultSession?

    var isUnlocked: Bool { queue.sync { session != nil } }

    func run<T>(_ body: @escaping (VaultSession) throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { cont in
            queue.async {
                guard let s = self.session else {
                    cont.resume(throwing: CoreError.Failed(message: "The vault is locked."))
                    return
                }
                cont.resume(with: Result { try body(s) })
            }
        }
    }

    /// Runs `body` on the core's queue without a session (setting up,
    /// unlocking, checking S3).
    func detached<T>(_ body: @escaping () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { cont in
            queue.async { cont.resume(with: Result { try body() }) }
        }
    }

    /// Runs a non-throwing body on the core's queue.
    func detachedValue<T>(_ body: @escaping () -> T) async -> T {
        await withCheckedContinuation { cont in
            queue.async { cont.resume(returning: body()) }
        }
    }

    func open(_ s: VaultSession) async {
        await withCheckedContinuation { cont in
            queue.async {
                self.session = s
                cont.resume()
            }
        }
    }

    func lock() {
        queue.async { self.session = nil }
    }

    /// Saves the vault to the shared container (call after every change).
    func persist() async throws {
        let text = try await run { $0.save() }
        try SavedVault.store(text)
    }
}

extension VaultItem: Identifiable {}
extension SuggestedLogin: Identifiable {}
extension AuditFinding: Identifiable {}

/// A message to show for an error from the core (or anything else).
func message(_ error: Error) -> String {
    switch error as? CoreError {
    case .WrongPassword: return "That's not the master password."
    case .DifferentVault: return "That S3 folder holds a different vault."
    case .Failed(let message): return message.prefix(1).uppercased() + message.dropFirst()
    case nil: return error.localizedDescription
    }
}

extension ItemFields {
    static func empty(kind: Kind = .login) -> ItemFields {
        ItemFields(kind: kind, name: "", username: "", password: "", websites: [], totp: "", notes: "", folder: "", favorite: false, fields: [])
    }
}

extension VaultItem {
    /// The first website's host, for display.
    var host: String? {
        guard let uri = fields.websites.first?.uri else { return nil }
        let full = uri.contains("://") ? uri : "https://\(uri)"
        return URL(string: full)?.host
    }
}
