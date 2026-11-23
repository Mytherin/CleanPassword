import Foundation
import Security

/// Unlocking with a PIN, as Bitwarden offers: the vault key sealed with a
/// key derived from the PIN (Argon2id, as the master password's), kept in
/// this device's keychain only (in the App Group's access group, so the
/// AutoFill extension can use it). After five wrong PINs it's deleted, and
/// the master password is needed again.
enum PinKey {
    private static let service = "com.cleanpassword.pin-key"
    static let maxAttempts = 5

    enum Outcome {
        case key(String)
        case wrong(attemptsLeft: Int)
        /// Too many wrong PINs: the PIN is gone.
        case forgotten
        case failed(String)
    }

    private static func query(vaultId: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: vaultId,
            kSecAttrAccessGroup as String: AppGroup.id,
        ]
    }

    private static var defaults: UserDefaults { UserDefaults(suiteName: AppGroup.id) ?? .standard }
    private static func attemptsKey(_ vaultId: String) -> String { "pinAttempts.\(vaultId)" }

    static func exists(vaultId: String) -> Bool {
        SecItemCopyMatching(query(vaultId: vaultId) as CFDictionary, nil) == errSecSuccess
    }

    /// Seals the vault key with the PIN (slow: run it off the main thread).
    static func store(key: String, pin: String, vaultId: String) throws {
        let sealed = try sealKeyWithPin(key: key, pin: pin)
        remove(vaultId: vaultId)
        var q = query(vaultId: vaultId)
        q[kSecValueData as String] = Data(sealed.utf8)
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
        defaults.removeObject(forKey: attemptsKey(vaultId))
    }

    static func remove(vaultId: String) {
        SecItemDelete(query(vaultId: vaultId) as CFDictionary)
        defaults.removeObject(forKey: attemptsKey(vaultId))
    }

    /// The vault key, if the PIN is right (slow: run it off the main thread).
    static func unlock(pin: String, vaultId: String) -> Outcome {
        var q = query(vaultId: vaultId)
        q[kSecReturnData as String] = true
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let data = out as? Data, let sealed = String(data: data, encoding: .utf8) else {
            return .forgotten
        }
        do {
            let key = try openKeyWithPin(sealed: sealed, pin: pin)
            defaults.removeObject(forKey: attemptsKey(vaultId))
            return .key(key)
        } catch CoreError.WrongPassword {
            let attempts = defaults.integer(forKey: attemptsKey(vaultId)) + 1
            if attempts >= maxAttempts {
                remove(vaultId: vaultId)
                return .forgotten
            }
            defaults.set(attempts, forKey: attemptsKey(vaultId))
            return .wrong(attemptsLeft: maxAttempts - attempts)
        } catch {
            return .failed(message(error))
        }
    }

    /// What to tell the user about a PIN that didn't unlock.
    static func explain(_ outcome: Outcome) -> String? {
        switch outcome {
        case .key: return nil
        case .wrong(let left): return left == 1 ? "Wrong PIN. One more wrong PIN turns PIN unlock off." : "Wrong PIN. \(left) tries left."
        case .forgotten: return "Too many wrong PINs: PIN unlock is off. Use your master password."
        case .failed(let m): return m
        }
    }
}
