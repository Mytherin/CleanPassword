import AuthenticationServices
import Foundation

/// What iOS shows above the keyboard and in Safari's sign-in sheets: the
/// user names and websites of the logins (never passwords), and the
/// passkeys (their site, user name and id, never their keys), registered
/// with the system so it can offer them without opening the extension;
/// picking one asks the extension for it. Off in Settings, the list is
/// cleared.
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
        var identities: [any ASCredentialIdentity] = []
        for item in items where item.fields.kind == .login {
            if !item.fields.password.isEmpty {
                for site in item.fields.websites where site.matching != .never {
                    let full = site.uri.contains("://") ? site.uri : "https://\(site.uri)"
                    guard let host = URL(string: full)?.host else { continue }
                    let service = ASCredentialServiceIdentifier(identifier: host, type: .domain)
                    identities.append(ASPasswordCredentialIdentity(serviceIdentifier: service, user: item.fields.username, recordIdentifier: item.id))
                }
            }
            for p in item.passkeys {
                identities.append(ASPasskeyCredentialIdentity(relyingPartyIdentifier: p.rpId, userName: p.userName, credentialID: p.credentialId, userHandle: p.userHandle, recordIdentifier: item.id))
            }
        }
        Task {
            let store = ASCredentialIdentityStore.shared
            let state = await store.state()
            guard state.isEnabled else { return }
            if enabled {
                try? await store.replaceCredentialIdentities(identities)
            } else {
                try? await store.removeAllCredentialIdentities()
            }
        }
    }

    static func clear() {
        Task { try? await ASCredentialIdentityStore.shared.removeAllCredentialIdentities() }
    }
}
