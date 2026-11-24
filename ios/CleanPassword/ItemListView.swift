import SwiftUI

/// A tile's or folder's items, as in Apple's Passwords app: All and folders
/// by name in letter sections; Codes with their current codes; Security by
/// what's wrong; Deleted with Recover and Delete.
struct ItemListView: View {
    @EnvironmentObject private var store: VaultStore
    let category: Category
    @State private var search = ""
    @AppStorage("sortOrder") private var sort = SortOrder.title

    var body: some View {
        Group {
            switch category {
            case .all: sorted(store.items.filter { $0.fields.kind != .wifi })
            case .wifi: sorted(store.items.filter { $0.fields.kind == .wifi })
            case .cards: sorted(store.items.filter { $0.fields.kind == .card })
            case .identities: sorted(store.items.filter { $0.fields.kind == .identity })
            case .sshKeys: sorted(store.items.filter { $0.fields.kind == .sshKey })
            case .folder(let f): sorted(store.items.filter { $0.fields.folder == f })
            case .passkeys: sorted(store.items.filter { !$0.passkeys.isEmpty })
            case .favorites: sorted(store.items.filter(\.fields.favorite))
            case .codes: CodesList(search: search)
            case .security: SecurityList()
            case .deleted: DeletedList()
            }
        }
        .navigationTitle(category.title)
        .modifier(Searchable(on: category != .security && category != .deleted, text: $search))
        .toolbar {
            if category.sortable {
                Menu {
                    Picker("Sort By", selection: $sort) {
                        ForEach(SortOrder.allCases, id: \.self) { Text($0.label).tag($0) }
                    }
                } label: {
                    Image(systemName: "arrow.up.arrow.down")
                }
                .accessibilityLabel("Sort By")
            }
        }
    }

    /// The items found, in the chosen order: by title in letter sections,
    /// else in one list.
    @ViewBuilder
    private func sorted(_ all: [VaultItem]) -> some View {
        let items = sort.sorted(all.filter { $0.matches(search: search) })
        List {
            if sort == .title && search.isEmpty {
                let sections = Dictionary(grouping: items) { i -> String in
                    let first = i.fields.name.trimmingCharacters(in: .whitespaces).prefix(1).uppercased()
                    return first.first?.isLetter == true ? first : "#"
                }
                let keys = sections.keys.sorted { a, b in a == "#" ? false : b == "#" ? true : a < b }
                ForEach(keys, id: \.self) { k in
                    Section(k) {
                        ForEach(sections[k] ?? []) { row($0) }
                    }
                }
            } else {
                ForEach(items) { row($0) }
            }
        }
        .overlay {
            if items.isEmpty {
                if !search.isEmpty {
                    ContentUnavailableView.search(text: search)
                } else if category == .wifi {
                    ContentUnavailableView("No Wi-Fi Networks", systemImage: "wifi", description: Text("Add one with + on the Passwords screen, as a Wi-Fi Network."))
                } else if category == .favorites {
                    ContentUnavailableView("No Favorites", systemImage: "star", description: Text("Touch and hold a password and choose Add to Favorites."))
                } else {
                    ContentUnavailableView("No Passwords", systemImage: "key")
                }
            }
        }
    }

    private func row(_ i: VaultItem) -> some View {
        NavigationLink(value: Route.item(id: i.id)) { ItemRow(item: i) }
            .contextMenu { ItemMenu(item: i) }
    }
}

private extension Category {
    var sortable: Bool {
        switch self {
        case .all, .folder, .passkeys, .favorites, .wifi, .cards, .identities, .sshKeys: return true
        case .codes, .security, .deleted: return false
        }
    }
}

/// A search field, on lists that have one.
private struct Searchable: ViewModifier {
    let on: Bool
    @Binding var text: String

    func body(content: Content) -> some View {
        if on { content.searchable(text: $text) } else { content }
    }
}

/// Items with one-time codes, each showing its current code; tapping one
/// copies it.
private struct CodesList: View {
    @EnvironmentObject private var store: VaultStore
    let search: String
    @State private var copied: String?

    var body: some View {
        let items = SortOrder.title.sorted(store.items.filter { !$0.fields.totp.isEmpty && $0.matches(search: search) })
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            List(items) { i in
                let code = try? oneTimeCode(secret: i.fields.totp)
                Button {
                    guard code != nil else { return }
                    // Made when it's copied, after Face ID for items that ask.
                    Reprompt.then(i) {
                        guard let now = try? oneTimeCode(secret: i.fields.totp) else { return }
                        copySecret(now.code)
                        copied = i.id
                        Task {
                            try? await Task.sleep(for: .seconds(1.5))
                            if copied == i.id { copied = nil }
                        }
                    }
                } label: {
                    HStack(spacing: 12) {
                        SiteIcon(name: i.fields.name, host: i.host)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(i.fields.name).foregroundStyle(.primary)
                            Text(copied == i.id ? "Copied" : i.fields.username).font(.subheadline).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if let code, i.fields.reprompt {
                            // Shown only after Face ID: tap to copy.
                            Image(systemName: BiometricKey.symbol).foregroundStyle(.secondary)
                            CountdownRing(remaining: code.remaining, period: code.period)
                        } else if let code {
                            Text(spaced(code.code)).font(.title3.monospacedDigit()).foregroundStyle(.tint)
                            CountdownRing(remaining: code.remaining, period: code.period)
                        } else {
                            Text("Invalid").foregroundStyle(.red)
                        }
                    }
                }
                .contextMenu { ItemMenu(item: i) }
            }
        }
        .overlay {
            if items.isEmpty && !search.isEmpty {
                ContentUnavailableView.search(text: search)
            } else if items.isEmpty {
                ContentUnavailableView("No Codes", systemImage: "lock.rotation", description: Text("Open a password and tap Set Up Verification Code to scan the site's QR code."))
            }
        }
    }

    private func spaced(_ c: String) -> String {
        c.count == 6 ? "\(c.prefix(3)) \(c.suffix(3))" : c
    }
}

/// The seconds a code has left, as a closing ring.
struct CountdownRing: View {
    let remaining: UInt64
    let period: UInt64

    var body: some View {
        ZStack {
            Circle().stroke(Color(.systemFill), lineWidth: 3)
            Circle()
                .trim(from: 0, to: CGFloat(remaining) / CGFloat(max(period, 1)))
                .stroke(remaining <= 5 ? Color.red : Color.accentColor, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
        }
        .frame(width: 18, height: 18)
    }
}

/// Compromised passwords first (found in data leaks), then reused, then
/// weak ones.
private struct SecurityList: View {
    @EnvironmentObject private var store: VaultStore
    @AppStorage(Breaches.settingKey) private var detect = true
    /// Leak counts by item id, of the logins checked.
    @State private var leaked: [String: Int] = [:]
    @State private var checking = false
    @State private var checkError: String?
    @State private var hidden = HiddenRecommendations.all()

    private func isHidden(_ id: String) -> Bool {
        HiddenRecommendations.isHidden(store.items.first { $0.id == id }, in: hidden)
    }

    var body: some View {
        let reused = store.findings.filter { $0.reused > 0 && !isHidden($0.id) }
        let weak = store.findings.filter { $0.reused == 0 && $0.weak && !isHidden($0.id) }
        let compromised = SortOrder.title.sorted(store.items.filter { (leaked[$0.id] ?? 0) > 0 && !isHidden($0.id) })
        let hiddenItems = SortOrder.title.sorted(store.items.filter { i in
            HiddenRecommendations.isHidden(i, in: hidden) && hasRecommendation(i)
        })
        List {
            if detect && (!compromised.isEmpty || checking || checkError != nil) {
                Section {
                    ForEach(compromised) { i in
                        let n = leaked[i.id] ?? 0
                        NavigationLink(value: Route.item(id: i.id)) {
                            HStack(spacing: 12) {
                                SiteIcon(name: i.fields.name, host: i.host)
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(i.fields.name)
                                    Text(n == 1 ? "Appeared in a data leak" : "Appeared in data leaks \(n.formatted()) times").font(.subheadline).foregroundStyle(.red)
                                }
                            }
                        }
                        .swipeActions { hideButton(i.id) }
                    }
                    if checking { HStack { ProgressView(); Text("Checking for compromised passwords…").foregroundStyle(.secondary) } }
                    if let checkError { Text(checkError).font(.footnote).foregroundStyle(.secondary) }
                } header: {
                    Text("Compromised Passwords")
                } footer: {
                    if !compromised.isEmpty {
                        Text("These passwords are known to attackers, from leaks of some site's data. Change them now, everywhere you use them.")
                    }
                }
            }
            if store.duplicates > 0 {
                Section {
                    Button(store.duplicates == 1 ? "Merge 1 Duplicate" : "Merge \(store.duplicates) Duplicates") {
                        Task { try? await store.change { $0.mergeDuplicates() } }
                    }
                } header: {
                    Text("Duplicate Logins")
                } footer: {
                    Text("Logins saved more than once for the same site, user name and password, as browsers save one per host (example.com, www.example.com). Merging keeps every website; the copies go to Recently Deleted.")
                }
            }
            if !reused.isEmpty {
                Section {
                    ForEach(reused) { f in row(f, "Used on \(f.reused + 1) sites") }
                } header: {
                    Text("Reused Passwords")
                } footer: {
                    Text("If one of these sites leaks the password, the others are open too. Give each its own.")
                }
            }
            if !weak.isEmpty {
                Section {
                    ForEach(weak) { f in row(f, "Easily guessed") }
                } header: {
                    Text("Weak Passwords")
                } footer: {
                    Text("Change these to strong passwords: edit the item and tap the dice.")
                }
            }
            insecureSection
            twoFactorSection
            if !hiddenItems.isEmpty {
                Section {
                    DisclosureGroup("Hidden (\(hiddenItems.count))") {
                        ForEach(hiddenItems) { i in
                            NavigationLink(value: Route.item(id: i.id)) { ItemRow(item: i) }
                                .swipeActions {
                                    Button("Show") { setHidden(i.id, false) }.tint(.blue)
                                }
                        }
                    }
                } footer: {
                    Text("Recommendations you hid come back when the password is changed. Swipe to show one again.")
                }
            }
        }
        .overlay {
            if reused.isEmpty && weak.isEmpty && hiddenItems.isEmpty && store.duplicates == 0 && compromised.isEmpty && !checking && checkError == nil
                && insecure.isEmpty && withoutTwoFactor.isEmpty {
                ContentUnavailableView(
                    "No Security Recommendations", systemImage: "checkmark.shield",
                    description: Text(detect ? "No compromised, weak or reused passwords." : "No weak or reused passwords."))
            }
        }
        .refreshable { await check() }
        .task(id: store.items.map(\.fields.password).hashValue) { await check() }
        .task(id: checkTwoFactor) {
            twoFactorSites = checkTwoFactor ? ((try? await TwoFactorDirectory.shared.load()) ?? [:]) : [:]
        }
    }

    // MARK: Insecure websites and two-factor authentication

    @AppStorage(TwoFactorDirectory.settingKey) private var checkTwoFactor = true
    /// Sites that offer verification codes (registrable domain → how).
    @State private var twoFactorSites: [String: URL?] = [:]

    private func hasRecommendation(_ i: VaultItem) -> Bool {
        (leaked[i.id] ?? 0) > 0 || store.findings.contains { $0.id == i.id } || isInsecure(i) || twoFactorDomain(i) != nil
    }

    /// A login saved for an http:// address: its password is sent
    /// unencrypted there.
    private func isInsecure(_ i: VaultItem) -> Bool {
        i.fields.kind == .login && !i.fields.password.isEmpty && i.fields.websites.contains { $0.uri.lowercased().hasPrefix("http://") }
    }

    /// The domain of a login's site that offers verification codes, when
    /// the login has none (nor a passkey).
    private func twoFactorDomain(_ i: VaultItem) -> String? {
        guard !twoFactorSites.isEmpty, i.fields.kind == .login, i.fields.totp.isEmpty, i.passkeys.isEmpty, !i.fields.password.isEmpty else { return nil }
        return i.fields.websites.lazy.compactMap { ItemEditView.host($0.uri) }.map { registrableDomain(host: $0) }.first { twoFactorSites[$0] != nil }
    }

    private var insecure: [VaultItem] {
        SortOrder.title.sorted(store.items.filter { isInsecure($0) && !isHidden($0.id) })
    }

    private var withoutTwoFactor: [VaultItem] {
        SortOrder.title.sorted(store.items.filter { twoFactorDomain($0) != nil && !isHidden($0.id) })
    }

    @ViewBuilder
    private var insecureSection: some View {
        let items = insecure
        if !items.isEmpty {
            Section {
                ForEach(items) { i in itemRow(i, "Saved for an http:// address", color: .orange) }
            } header: {
                Text("Insecure Websites")
            } footer: {
                Text("These sites receive your password unencrypted. Change the address to https:// if the site supports it.")
            }
        }
    }

    @ViewBuilder
    private var twoFactorSection: some View {
        let items = withoutTwoFactor
        if !items.isEmpty {
            Section {
                ForEach(items) { i in
                    itemRow(i, "Offers verification codes", color: .blue)
                        .contextMenu {
                            if let domain = twoFactorDomain(i), let docs = twoFactorSites[domain] ?? nil {
                                Link(destination: docs) { Label("How to Turn It On", systemImage: "safari") }
                            }
                        }
                }
            } header: {
                Text("Two-Factor Authentication Available")
            } footer: {
                Text("These sites can ask for a verification code as well as your password. Turn it on at the site, then open the password and tap Set Up Verification Code. (From 2fa.directory's list.)")
            }
        }
    }

    private func itemRow(_ i: VaultItem, _ why: String, color: Color) -> some View {
        NavigationLink(value: Route.item(id: i.id)) {
            HStack(spacing: 12) {
                SiteIcon(name: i.fields.name, host: i.host)
                VStack(alignment: .leading, spacing: 1) {
                    Text(i.fields.name)
                    Text(why).font(.subheadline).foregroundStyle(color)
                }
            }
        }
        .swipeActions { hideButton(i.id) }
    }

    /// Looks up each login's password (by hash prefix only).
    private func check() async {
        guard detect else { return }
        let logins = store.items.filter { $0.fields.kind == .login && !$0.fields.password.isEmpty }
        guard !logins.isEmpty else { return }
        checking = true
        defer { checking = false }
        do {
            let counts = try await Breaches.shared.counts(for: Set(logins.map(\.fields.password)))
            leaked = Dictionary(uniqueKeysWithValues: logins.map { ($0.id, counts[$0.fields.password] ?? 0) })
            checkError = nil
        } catch {
            checkError = "Couldn't check for compromised passwords: \(error.localizedDescription)"
        }
    }

    private func row(_ f: AuditFinding, _ why: String) -> some View {
        NavigationLink(value: Route.item(id: f.id)) {
            HStack(spacing: 12) {
                SiteIcon(name: f.name, host: store.items.first { $0.id == f.id }?.host)
                VStack(alignment: .leading, spacing: 1) {
                    Text(f.name)
                    Text(why).font(.subheadline).foregroundStyle(.orange)
                }
            }
        }
        .swipeActions { hideButton(f.id) }
    }

    private func hideButton(_ id: String) -> some View {
        Button("Hide") { setHidden(id, true) }.tint(.gray)
    }

    private func setHidden(_ id: String, _ on: Bool) {
        guard let item = store.items.first(where: { $0.id == id }) else { return }
        HiddenRecommendations.set(item, hidden: on)
        hidden = HiddenRecommendations.all()
    }
}

/// Security recommendations hidden for an item, as Apple's Passwords lets
/// you: until the item next changes. Kept on this iPhone, as item ids and
/// modification times only.
enum HiddenRecommendations {
    private static let key = "hiddenRecommendations"

    static func all() -> [String: Int64] {
        (UserDefaults.standard.dictionary(forKey: key) ?? [:]).compactMapValues { ($0 as? NSNumber)?.int64Value }
    }

    static func isHidden(_ item: VaultItem?, in map: [String: Int64]) -> Bool {
        guard let item else { return false }
        return map[item.id] == item.modified
    }

    static func set(_ item: VaultItem, hidden: Bool) {
        var map = all()
        map[item.id] = hidden ? item.modified : nil
        UserDefaults.standard.set(map.mapValues { NSNumber(value: $0) }, forKey: key)
    }
}

/// Recently Deleted: swipe or touch and hold to recover or delete for good.
private struct DeletedList: View {
    @EnvironmentObject private var store: VaultStore
    @State private var purging: VaultItem?

    var body: some View {
        List {
            Section {
                ForEach(store.trash) { i in
                    ItemRow(item: i)
                        .swipeActions(edge: .leading) {
                            Button("Recover") { Task { try? await store.change { try $0.restore(id: i.id) } } }.tint(.blue)
                        }
                        .swipeActions(edge: .trailing) {
                            Button("Delete", role: .destructive) { purging = i }
                        }
                        .contextMenu {
                            Button { Task { try? await store.change { try $0.restore(id: i.id) } } } label: { Label("Recover", systemImage: "arrow.uturn.backward") }
                            Button(role: .destructive) { purging = i } label: { Label("Delete", systemImage: "trash") }
                        }
                }
            } footer: {
                if !store.trash.isEmpty { Text("Items are deleted for good after 30 days.") }
            }
        }
        .overlay {
            if store.trash.isEmpty { ContentUnavailableView("No Deleted Passwords", systemImage: "trash") }
        }
        .confirmationDialog("Delete “\(purging?.fields.name ?? "")” for good, on every device?", isPresented: Binding(get: { purging != nil }, set: { if !$0 { purging = nil } }), titleVisibility: .visible) {
            Button("Delete", role: .destructive) {
                if let id = purging?.id { Task { try? await store.change { try $0.purge(id: id) } } }
                purging = nil
            }
        }
        .toolbar {
            if !store.trash.isEmpty {
                Menu {
                    Button { recoverAll() } label: { Label("Recover All", systemImage: "arrow.uturn.backward") }
                    Button(role: .destructive) { confirmDeleteAll = true } label: { Label("Delete All", systemImage: "trash") }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
        .confirmationDialog("Delete all \(store.trash.count) items for good, on every device?", isPresented: $confirmDeleteAll, titleVisibility: .visible) {
            Button("Delete All", role: .destructive) {
                let ids = store.trash.map(\.id)
                Task { try? await store.change { s in for id in ids { try s.purge(id: id) } } }
            }
        } message: {
            Text("They can't be recovered.")
        }
    }

    @State private var confirmDeleteAll = false

    private func recoverAll() {
        let ids = store.trash.map(\.id)
        Task { try? await store.change { s in for id in ids { try s.restore(id: id) } } }
    }
}
