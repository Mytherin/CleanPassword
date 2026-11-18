import AuthenticationServices
import Foundation

/// What iOS shows above the keyboard: the user names and websites of the
/// logins (never passwords), registered with the system so it can suggest
/// them without opening the extension; picking one asks the extension for
/// the password. Off in Settings, the list is cleared.
enum SuggestionStore {
    static let settingKey = "keyboardSuggestions"

    static var enabled: Bool {
        let d = UserDefaults(suiteName: AppGroup.id) ?? .standard
        return d.object(forKey: settingKey) as? Bool ?? true
    }

    static func setEnabled(_ on: Bool) {
        (UserDefaults(suiteName: AppGroup.id) ?? .standard).set(on, forKey: settingKey)
    }

    static func update(with items: [VaultItem]) {
        let store = ASCredentialIdentityStore.shared
        store.getState { state in
            guard state.isEnabled else { return }
            guard enabled else {
                store.removeAllCredentialIdentities(nil)
                return
            }
            var identities: [ASPasswordCredentialIdentity] = []
            for item in items where item.fields.kind == .login && !item.fields.password.isEmpty {
                for site in item.fields.websites where site.matching != .never {
                    let full = site.uri.contains("://") ? site.uri : "https://\(site.uri)"
                    guard let host = URL(string: full)?.host else { continue }
                    let service = ASCredentialServiceIdentifier(identifier: host, type: .domain)
                    identities.append(ASPasswordCredentialIdentity(serviceIdentifier: service, user: item.fields.username, recordIdentifier: item.id))
                }
            }
            store.replaceCredentialIdentities(with: identities, completion: nil)
        }
    }

    static func clear() {
        ASCredentialIdentityStore.shared.removeAllCredentialIdentities(nil)
    }
}
