import Foundation
import LocalAuthentication
import Security

/// The vault key kept in the keychain for Face ID (or Touch ID), when the
/// user turns that on: on this device only, readable only after biometric
/// authentication, and forgotten if the enrolled faces or fingers change.
/// It's in the App Group's access group so the AutoFill extension can use
/// it too.
enum BiometricKey {
    private static let service = "com.cleanpassword.vault-key"

    static var isAvailable: Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    static var biometryName: String {
        let ctx = LAContext()
        _ = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch ctx.biometryType {
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        default: return "Face ID"
        }
    }

    private static func baseQuery(vaultId: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: vaultId,
            kSecAttrAccessGroup as String: AppGroup.id,
        ]
    }

    static func store(key: String, vaultId: String) throws {
        remove(vaultId: vaultId)
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        var q = baseQuery(vaultId: vaultId)
        q[kSecValueData as String] = Data(key.utf8)
        q[kSecAttrAccessControl as String] = access
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
    }

    /// The key, after asking for Face ID; nil if cancelled or not set up.
    static func read(vaultId: String, reason: String) -> String? {
        try? readKey(vaultId: vaultId, reason: reason).get()
    }

    /// The same, with the keychain's status when there's no key.
    static func readKey(vaultId: String, reason: String) -> Result<String, NSError> {
        let ctx = LAContext()
        ctx.localizedReason = reason
        var q = baseQuery(vaultId: vaultId)
        q[kSecReturnData as String] = true
        q[kSecUseAuthenticationContext as String] = ctx
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        guard status == errSecSuccess, let data = out as? Data, let key = String(data: data, encoding: .utf8) else {
            return .failure(NSError(domain: NSOSStatusErrorDomain, code: Int(status)))
        }
        return .success(key)
    }

    /// Whether a key is stored, without asking for Face ID.
    static func exists(vaultId: String) -> Bool {
        let ctx = LAContext()
        ctx.interactionNotAllowed = true
        var q = baseQuery(vaultId: vaultId)
        q[kSecUseAuthenticationContext as String] = ctx
        let status = SecItemCopyMatching(q as CFDictionary, nil)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    static func remove(vaultId: String) {
        SecItemDelete(baseQuery(vaultId: vaultId) as CFDictionary)
    }
}
