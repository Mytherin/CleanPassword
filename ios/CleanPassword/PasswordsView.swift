import SwiftUI

/// The Passwords screen, as in Apple's Passwords app: tiles for All,
/// Passkeys, Codes, Security and Deleted with their counts, then the folders; search across
/// every item; the "…" menu (Settings, Generator, Lock Now) on top and New
/// Password in the bottom toolbar.
struct PasswordsView: View {
    @EnvironmentObject private var store: VaultStore
    @Binding var path: [Route]

    @State private var search = ""
    @State private var newItem = false
    @State private var showSettings = false
    @State private var showGenerator = false

    var body: some View {
        Group {
            if search.trimmingCharacters(in: .whitespaces).isEmpty {
                overview
            } else {
                results
            }
        }
        .navigationTitle("Passwords")
        .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always), prompt: "Search")
        .refreshable { store.sync() }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button { showSettings = true } label: { Label("Settings", systemImage: "gear") }
                    Button { showGenerator = true } label: { Label("Password Generator", systemImage: "dice") }
                    Button { store.lock(manually: true) } label: { Label("Lock Now", systemImage: "lock") }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
            ToolbarItemGroup(placement: .bottomBar) {
                Spacer()
                SyncStatus()
                Spacer()
                Button { newItem = true } label: { Image(systemName: "plus") }
                    .accessibilityLabel("New Password")
            }
        }
        .sheet(isPresented: $newItem) {
            NavigationStack { ItemEditView(item: nil) }
        }
        .sheet(item: $store.codeLink) { c in
            NavigationStack { SetUpCodeView(link: c.link) }
        }
        // The editor that was open when the vault locked, with its work.
        .sheet(item: $store.reopenDraft) { d in
            NavigationStack { ItemEditView(item: store.items.first { $0.id == d.itemId }, draft: d) }
        }
        .sheet(isPresented: $showSettings) {
            NavigationStack { SettingsView() }
        }
        .sheet(isPresented: $showGenerator) {
            NavigationStack { GeneratorView() }
        }
    }

    private var overview: some View {
        List {
            Section {
                LazyVGrid(columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)], spacing: 12) {
                    tile(.all, count: store.items.count)
                    tile(.passkeys, count: store.items.filter { !$0.passkeys.isEmpty }.count)
                    tile(.codes, count: store.items.filter { !$0.fields.totp.isEmpty }.count)
                    tile(.security, count: store.findings.count)
                    tile(.deleted, count: store.trash.count)
                    tile(.favorites, count: store.items.filter { $0.fields.favorite }.count)
                }
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
            }
            let folders = Set(store.items.map(\.fields.folder)).filter { !$0.isEmpty }.sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
            if !folders.isEmpty {
                Section("Folders") {
                    ForEach(folders, id: \.self) { f in
                        NavigationLink(value: Route.list(.folder(f))) {
                            HStack {
                                Label(f, systemImage: "folder")
                                Spacer()
                                Text("\(store.items.filter { $0.fields.folder == f }.count)").foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            if store.items.isEmpty {
                Section {
                    Text("Add a password with +, or import from Bitwarden in Settings.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
        }
        .listStyle(.insetGrouped)
    }

    private func tile(_ c: Category, count: Int) -> some View {
        Button {
            path.append(.list(c))
        } label: {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Image(systemName: c.symbol)
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundStyle(.white)
                        .frame(width: 34, height: 34)
                        .background(c.color, in: Circle())
                    Spacer()
                    Text("\(count)").font(.title2.weight(.bold)).foregroundStyle(.primary)
                }
                Text(c.title).font(.headline).foregroundStyle(.secondary)
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        }
        .buttonStyle(.plain)
    }

    /// Search results: every item with all the words typed.
    private var results: some View {
        let found = SortOrder.title.sorted(store.items.filter { $0.matches(search: search) })
        return List(found) { i in
            NavigationLink(value: Route.item(id: i.id)) { ItemRow(item: i) }
                .contextMenu { ItemMenu(item: i) }
        }
        .overlay {
            if found.isEmpty { ContentUnavailableView.search(text: search) }
        }
    }
}

/// "Synced 2 minutes ago", in the bottom toolbar.
struct SyncStatus: View {
    @EnvironmentObject private var store: VaultStore

    var body: some View {
        Group {
            if store.syncing {
                Text("Syncing…")
            } else if let m = store.syncMessage {
                Label(m, systemImage: "exclamationmark.triangle").lineLimit(1)
            } else if let t = store.lastSync {
                Text("Synced \(t.formatted(.relative(presentation: .named)))")
            } else {
                Text("\(store.items.count) passwords")
            }
        }
        .font(.caption)
        .foregroundStyle(.secondary)
    }
}
