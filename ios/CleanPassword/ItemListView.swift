import SwiftUI

/// A tile's or folder's items, as in Apple's Passwords app: All and folders
/// by name in letter sections; Codes with their current codes; Security by
/// what's wrong; Deleted with Recover and Delete.
struct ItemListView: View {
    @EnvironmentObject private var store: VaultStore
    let category: Category

    var body: some View {
        Group {
            switch category {
            case .all: lettered(store.items)
            case .folder(let f): lettered(store.items.filter { $0.fields.folder == f })
            case .passkeys: lettered(store.items.filter { !$0.passkeys.isEmpty })
            case .codes: CodesList()
            case .security: SecurityList()
            case .deleted: DeletedList()
            }
        }
        .navigationTitle(category.title)
    }

    /// Items in sections by their first letter.
    private func lettered(_ items: [VaultItem]) -> some View {
        let sections = Dictionary(grouping: items) { i -> String in
            let first = i.fields.name.trimmingCharacters(in: .whitespaces).prefix(1).uppercased()
            return first.first?.isLetter == true ? first : "#"
        }
        let keys = sections.keys.sorted { a, b in a == "#" ? false : b == "#" ? true : a < b }
        return List {
            ForEach(keys, id: \.self) { k in
                Section(k) {
                    ForEach(sections[k] ?? []) { i in
                        NavigationLink(value: Route.item(id: i.id)) { ItemRow(item: i) }
                            .contextMenu { ItemMenu(item: i) }
                    }
                }
            }
        }
        .overlay {
            if items.isEmpty { ContentUnavailableView("No Passwords", systemImage: "key") }
        }
    }
}

/// Items with one-time codes, each showing its current code; tapping one
/// copies it.
private struct CodesList: View {
    @EnvironmentObject private var store: VaultStore
    @State private var copied: String?

    var body: some View {
        let items = store.items.filter { !$0.fields.totp.isEmpty }
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            List(items) { i in
                let code = try? oneTimeCode(secret: i.fields.totp)
                Button {
                    if let code { copySecret(code.code); copied = i.id }
                } label: {
                    HStack(spacing: 12) {
                        Monogram(name: i.fields.name)
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
            if items.isEmpty {
                ContentUnavailableView("No Codes", systemImage: "lock.rotation", description: Text("Add a setup key to a password to keep its verification codes here."))
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
            if store.findings.isEmpty {
                ContentUnavailableView("No Security Recommendations", systemImage: "checkmark.shield", description: Text("No weak or reused passwords."))
            }
        }
    }

    private func row(_ f: AuditFinding, _ why: String) -> some View {
        NavigationLink(value: Route.item(id: f.id)) {
            HStack(spacing: 12) {
                Monogram(name: f.name)
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
    }
}
