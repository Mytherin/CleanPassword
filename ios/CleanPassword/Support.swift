import SwiftUI
import LocalAuthentication
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
    /// Wi-Fi networks.
    case wifi
    /// Payment cards, identities and SSH keys.
    case cards
    case identities
    case sshKeys
    /// Weak and reused passwords.
    case security
    /// Recently Deleted.
    case deleted
    /// Items marked as favorites.
    case favorites
    case folder(String)

    var title: String {
        switch self {
        case .all: return "All"
        case .passkeys: return "Passkeys"
        case .codes: return "Codes"
        case .wifi: return "Wi-Fi"
        case .cards: return "Cards"
        case .identities: return "Identities"
        case .sshKeys: return "SSH Keys"
        case .security: return "Security"
        case .deleted: return "Deleted"
        case .favorites: return "Favorites"
        case .folder(let name): return name
        }
    }

    var symbol: String {
        switch self {
        case .all: return "key.fill"
        case .passkeys: return "person.badge.key.fill"
        case .codes: return "lock.rotation"
        case .wifi: return "wifi"
        case .cards: return "creditcard.fill"
        case .identities: return "person.text.rectangle.fill"
        case .sshKeys: return "terminal.fill"
        case .security: return "exclamationmark.shield.fill"
        case .deleted: return "trash.fill"
        case .favorites: return "star.fill"
        case .folder: return "folder.fill"
        }
    }

    var color: Color {
        switch self {
        case .all: return .blue
        case .passkeys: return .green
        case .codes: return .indigo
        case .wifi: return .cyan
        case .cards: return .purple
        case .identities: return .brown
        case .sshKeys: return .gray
        case .security: return .red
        case .deleted: return .orange
        case .favorites: return .yellow
        case .folder: return .teal
        }
    }
}

/// An item's first letter on a colour of its own: its icon until (or
/// unless) the site's own is loaded (`SiteIcon`).
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
            SiteIcon(name: item.fields.name, host: item.host)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.fields.name).lineLimit(1)
                Text(subtitle).font(.subheadline).foregroundStyle(.secondary).lineLimit(1)
            }
        }
    }

    var subtitle: String {
        if item.fields.kind == .note { return "Secure note" }
        if item.fields.kind == .wifi { return "Wi-Fi network" }
        if item.fields.kind == .card {
            let number = item.fields.fields.first { $0.name == "Number" }?.value.filter { $0.isNumber } ?? ""
            return number.count >= 4 ? "Card •••• \(number.suffix(4))" : "Card"
        }
        if item.fields.kind == .identity {
            let value = { (label: String) in item.fields.fields.first { $0.name == label }?.value ?? "" }
            let name = [value("First name"), value("Last name")].filter { !$0.isEmpty }.joined(separator: " ")
            return name.isEmpty ? (value("Email").isEmpty ? "Identity" : value("Email")) : name
        }
        if item.fields.kind == .sshKey {
            // The key's type: ssh-ed25519, ssh-rsa…
            let key = item.fields.fields.first { $0.name == "Public key" }?.value ?? ""
            return key.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? "SSH key"
        }
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
            Button { Reprompt.then(item) { copySecret(item.fields.password) } } label: { Label("Copy Password", systemImage: "key") }
        }
        if !item.fields.totp.isEmpty {
            Button {
                Reprompt.then(item) { if let code = try? oneTimeCode(secret: item.fields.totp) { copySecret(code.code) } }
            } label: { Label("Copy Verification Code", systemImage: "lock.rotation") }
        }
        Divider()
        Button {
            Task {
                try? await store.change { s in
                    guard var f = s.get(id: item.id)?.fields else { return }
                    f.favorite.toggle()
                    _ = try s.update(id: item.id, fields: f)
                }
            }
        } label: {
            Label(item.fields.favorite ? "Remove from Favorites" : "Add to Favorites", systemImage: item.fields.favorite ? "star.slash" : "star")
        }
        Button(role: .destructive) {
            Task { try? await store.change { try $0.delete(id: item.id) } }
        } label: { Label("Delete", systemImage: "trash") }
    }
}

extension VaultItem {
    /// Whether the item has every word of a search: in its name, user name,
    /// folder, notes, websites, or fields (the names of hidden ones only).
    func matches(search: String) -> Bool {
        let words = search.lowercased().split(separator: " ")
        guard !words.isEmpty else { return true }
        let f = fields
        let hay = ([f.name, f.username, f.folder, f.notes] + f.websites.map(\.uri) + f.fields.flatMap { $0.hidden ? [$0.name] : [$0.name, $0.value] })
            .joined(separator: "\n").lowercased()
        return words.allSatisfy { hay.contains($0) }
    }
}

/// How the lists of passwords are ordered, as in Apple's Passwords.
enum SortOrder: String, CaseIterable {
    case title, website, created, edited

    var label: String {
        switch self {
        case .title: return "Title"
        case .website: return "Website"
        case .created: return "Date Created"
        case .edited: return "Date Edited"
        }
    }

    func sorted(_ items: [VaultItem]) -> [VaultItem] {
        let byName: (VaultItem, VaultItem) -> Bool = { $0.fields.name.localizedCaseInsensitiveCompare($1.fields.name) == .orderedAscending }
        switch self {
        case .title: return items.sorted(by: byName)
        case .website:
            // By the site's domain; items without a website go last.
            let keyed = items.map { i in (i, i.host.map { registrableDomain(host: $0) } ?? "\u{10FFFF}") }
            return keyed.sorted { a, b in a.1 == b.1 ? byName(a.0, b.0) : a.1 < b.1 }.map(\.0)
        case .created: return items.sorted { $0.created > $1.created }
        case .edited: return items.sorted { $0.modified > $1.modified }
        }
    }
}


/// Items marked "Ask for Face ID to Show": their secrets are shown or
/// copied only after Face ID (or the passcode), even while the vault is
/// unlocked. One check covers the next half-minute.
@MainActor
enum Reprompt {
    private static var passedAt: Date?

    /// Whether the item's secrets may be used now (asking if needed).
    static func allow(_ item: VaultItem) async -> Bool {
        guard item.fields.reprompt else { return true }
        if let t = passedAt, Date().timeIntervalSince(t) < 30 { return true }
        let ctx = LAContext()
        let ok = (try? await ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Show “\(item.fields.name)”")) ?? false
        if ok { passedAt = Date() }
        return ok
    }

    /// Runs `action` once the item's secrets may be used.
    static func then(_ item: VaultItem, _ action: @escaping () -> Void) {
        Task { if await allow(item) { action() } }
    }
}
