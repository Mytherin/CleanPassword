import SwiftUI
import UniformTypeIdentifiers

/// Where the navigation stack can go.
enum Route: Hashable {
    /// A list of items, as from a tile or folder on the Passwords screen.
    case list(Category)
    /// An item.
    case item(id: String)
}

/// The groups on the Passwords screen, as in Apple's Passwords app.
enum Category: Hashable {
    case all
    /// Items with passkeys.
    case passkeys
    /// Items with a one-time code.
    case codes
    /// Weak and reused passwords.
    case security
    /// Recently Deleted.
    case deleted
    case folder(String)

    var title: String {
        switch self {
        case .all: return "All"
        case .passkeys: return "Passkeys"
        case .codes: return "Codes"
        case .security: return "Security"
        case .deleted: return "Deleted"
        case .folder(let name): return name
        }
    }

    var symbol: String {
        switch self {
        case .all: return "key.fill"
        case .passkeys: return "person.badge.key.fill"
        case .codes: return "lock.rotation"
        case .security: return "exclamationmark.shield.fill"
        case .deleted: return "trash.fill"
        case .folder: return "folder.fill"
        }
    }

    var color: Color {
        switch self {
        case .all: return .blue
        case .passkeys: return .green
        case .codes: return .indigo
        case .security: return .red
        case .deleted: return .orange
        case .folder: return .teal
        }
    }
}

/// An item's icon: its first letter on a colour of its own (Apple's shows
/// the site's icon; that would mean fetching it from the site).
struct Monogram: View {
    let name: String
    var size: CGFloat = 32

    var body: some View {
        let hash = name.unicodeScalars.reduce(UInt32(0)) { ($0 &* 31) &+ $1.value }
        let hue = Double(hash % 360) / 360
        Text(String(name.trimmingCharacters(in: .whitespaces).prefix(1)).uppercased())
            .font(.system(size: size * 0.47, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(Color(hue: hue, saturation: 0.55, brightness: 0.75), in: RoundedRectangle(cornerRadius: size * 0.24, style: .continuous))
    }
}

/// An item in a list: icon, name, and user name (or website).
struct ItemRow: View {
    let item: VaultItem

    var body: some View {
        HStack(spacing: 12) {
            Monogram(name: item.fields.name)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.fields.name).lineLimit(1)
                Text(subtitle).font(.subheadline).foregroundStyle(.secondary).lineLimit(1)
            }
        }
    }

    private var subtitle: String {
        if item.fields.kind == .note { return "Secure note" }
        return item.fields.username.isEmpty ? (item.host ?? "") : item.fields.username
    }
}

/// The copy actions of an item, for its context menu (as in Apple's app).
struct ItemMenu: View {
    @EnvironmentObject private var store: VaultStore
    let item: VaultItem

    var body: some View {
        if !item.fields.username.isEmpty {
            Button { copySecret(item.fields.username) } label: { Label("Copy User Name", systemImage: "person") }
        }
        if !item.fields.password.isEmpty {
            Button { copySecret(item.fields.password) } label: { Label("Copy Password", systemImage: "key") }
        }
        if !item.fields.totp.isEmpty {
            Button {
                if let code = try? oneTimeCode(secret: item.fields.totp) { copySecret(code.code) }
            } label: { Label("Copy Verification Code", systemImage: "lock.rotation") }
        }
        Divider()
        Button(role: .destructive) {
            Task { try? await store.change { try $0.delete(id: item.id) } }
        } label: { Label("Delete", systemImage: "trash") }
    }
}

/// Copies to the clipboard on this device only (not to other devices
/// through Universal Clipboard), cleared after 90 seconds.
func copySecret(_ text: String) {
    UIPasteboard.general.setItems([[UTType.plainText.identifier: text]], options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(90)])
}
