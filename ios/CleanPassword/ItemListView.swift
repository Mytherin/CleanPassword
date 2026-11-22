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
            case .all: sorted(store.items)
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
        case .all, .folder, .passkeys, .favorites: return true
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
                    guard let code else { return }
                    copySecret(code.code)
                    copied = i.id
                    Task {
                        try? await Task.sleep(for: .seconds(1.5))
                        if copied == i.id { copied = nil }
                    }
                } label: {
                    HStack(spacing: 12) {
                        SiteIcon(name: i.fields.name, host: i.host)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(i.fields.name).foregroundStyle(.primary)
                            Text(copied == i.id ? "Copied" : i.fields.username).font(.subheadline).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if let code {
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

/// Reused passwords first, then weak ones.
private struct SecurityList: View {
    @EnvironmentObject private var store: VaultStore

    var body: some View {
        let reused = store.findings.filter { $0.reused > 0 }
        let weak = store.findings.filter { $0.reused == 0 && $0.weak }
        List {
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
        }
        .overlay {
            if store.findings.isEmpty && store.duplicates == 0 {
                ContentUnavailableView("No Security Recommendations", systemImage: "checkmark.shield", description: Text("No weak or reused passwords."))
            }
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
