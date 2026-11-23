import AuthenticationServices
import Foundation

/// What iOS shows above the keyboard and in Safari's sign-in sheets: the
/// user names and websites of the logins (never passwords), and the
/// passkeys (their site, user name and id, never their keys), and the
/// logins with verification codes (never their secrets), registered
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
            // Only rules a host can stand for: iOS offers a suggestion for the
            // site's domain and hands over just that, so a login kept to one
            // exact address (or start, or pattern) would be offered beyond it.
            // Those stay in the extension's list, matched against the page.
            let hosts = item.fields.websites.filter { [Matching.default, .domain, .host].contains($0.matching) }.compactMap { site in
                URL(string: site.uri.contains("://") ? site.uri : "https://\(site.uri)")?.host
            }
            if !item.fields.password.isEmpty {
                for host in hosts {
                    let service = ASCredentialServiceIdentifier(identifier: host, type: .domain)
                    identities.append(ASPasswordCredentialIdentity(serviceIdentifier: service, user: item.fields.username, recordIdentifier: item.id))
                }
            }
            for p in item.passkeys {
                identities.append(ASPasskeyCredentialIdentity(relyingPartyIdentifier: p.rpId, userName: p.userName, credentialID: p.credentialId, userHandle: p.userHandle, recordIdentifier: item.id))
            }
            // Verification codes (iOS 18): offered above the keyboard in
            // one-time-code fields, labelled like the login (never the secret).
            if #available(iOS 18.0, *), !item.fields.totp.isEmpty {
                let label = item.fields.username.isEmpty ? item.fields.name : item.fields.username
                for host in hosts {
                    let service = ASCredentialServiceIdentifier(identifier: host, type: .domain)
                    identities.append(ASOneTimeCodeCredentialIdentity(serviceIdentifier: service, label: label, recordIdentifier: item.id))
                }
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
