import SwiftUI
import UniformTypeIdentifiers

struct VaultListView: View {
    @EnvironmentObject var model: AppModel
    @State private var query = ""
    @State private var editing: EditTarget?
    @State private var showGenerator = false
    @State private var showSettings = false

    struct EditTarget: Identifiable {
        let id = UUID()
        let item: VaultItem?
    }

    private var shown: [VaultItem] {
        let words = query.lowercased().split(separator: " ")
        guard !words.isEmpty else { return model.items }
        return model.items.filter { i in
            let hay = ([i.fields.name, i.fields.username, i.fields.folder, i.fields.notes] + i.fields.websites.map(\.uri)).joined(separator: "\n").lowercased()
            return words.allSatisfy { hay.contains($0) }
        }
    }

    var body: some View {
        NavigationStack {
            List {
                let favorites = shown.filter(\.fields.favorite)
                if !favorites.isEmpty && query.isEmpty {
                    Section("Favorites") { ForEach(favorites) { row($0) } }
                }
                let folders = Dictionary(grouping: shown, by: \.fields.folder)
                ForEach(folders.keys.sorted { a, b in a.isEmpty ? false : b.isEmpty ? true : a.localizedCaseInsensitiveCompare(b) == .orderedAscending }, id: \.self) { folder in
                    Section(folder.isEmpty ? (folders.count > 1 ? "No Folder" : "All Items") : folder) {
                        ForEach(folders[folder] ?? []) { row($0) }
                    }
                }
                if model.items.isEmpty {
                    ContentUnavailableView("No Items Yet", systemImage: "key", description: Text("Add one with +, or import from Bitwarden in Settings."))
                }
            }
            .searchable(text: $query)
            .refreshable { model.sync() }
            .navigationTitle("Passwords")
            .navigationDestination(for: String.self) { id in ItemDetailView(id: id) }
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button { showSettings = true } label: { Image(systemName: "gearshape") }
                }
                ToolbarItemGroup(placement: .topBarTrailing) {
                    Button { showGenerator = true } label: { Image(systemName: "dice") }
                    Button { editing = EditTarget(item: nil) } label: { Image(systemName: "plus") }
                }
                ToolbarItem(placement: .bottomBar) { status }
                ToolbarItem(placement: .bottomBar) {
                    Button { model.lock() } label: { Image(systemName: "lock") }
                }
            }
            .sheet(item: $editing) { t in
                NavigationStack { ItemEditView(item: t.item) }
            }
            .sheet(isPresented: $showGenerator) {
                NavigationStack { GeneratorView() }
            }
            .sheet(isPresented: $showSettings) {
                NavigationStack { SettingsView() }
            }
        }
    }

    private var status: some View {
        Group {
            if model.syncing {
                Text("Syncing…")
            } else if let m = model.syncMessage {
                Label(m, systemImage: "exclamationmark.triangle").lineLimit(1)
            } else if let t = model.lastSync {
                Text("Synced \(t.formatted(.relative(presentation: .named)))")
            } else {
                Text("\(model.items.count) items")
            }
        }
        .font(.caption)
        .foregroundStyle(.secondary)
    }

    private func row(_ i: VaultItem) -> some View {
        NavigationLink(value: i.id) {
            HStack(spacing: 12) {
                Monogram(name: i.fields.name)
                VStack(alignment: .leading) {
                    Text(i.fields.name).font(.body.weight(.medium)).lineLimit(1)
                    Text(i.fields.kind == .note ? "Secure note" : (i.fields.username.isEmpty ? (i.host ?? "") : i.fields.username))
                        .font(.subheadline).foregroundStyle(.secondary).lineLimit(1)
                }
            }
        }
    }
}

struct Monogram: View {
    let name: String

    var body: some View {
        let hash = name.unicodeScalars.reduce(UInt32(0)) { ($0 &* 31) &+ $1.value }
        let hue = Double(hash % 360) / 360
        Text(String(name.trimmingCharacters(in: .whitespaces).prefix(1)).uppercased())
            .font(.system(size: 15, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: 32, height: 32)
            .background(Color(hue: hue, saturation: 0.55, brightness: 0.75), in: Circle())
    }
}

/// Copies to the clipboard on this device only (not to other devices
/// through Universal Clipboard), cleared after 90 seconds.
func copySecret(_ text: String) {
    UIPasteboard.general.setItems([[UTType.plainText.identifier: text]], options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(90)])
}
