import SwiftUI

struct ItemDetailView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    let id: String
    @State private var revealed = false
    @State private var editing = false
    @State private var confirmDelete = false

    private var item: VaultItem? { model.items.first { $0.id == id } }

    var body: some View {
        if let item {
            List {
                let f = item.fields
                if f.kind == .login {
                    Section {
                        if !f.username.isEmpty { copyRow("User name", f.username) }
                        if !f.password.isEmpty {
                            HStack {
                                VStack(alignment: .leading) {
                                    Text("Password").font(.caption).foregroundStyle(.secondary)
                                    Text(revealed ? f.password : String(repeating: "•", count: 10)).font(.body.monospaced())
                                }
                                Spacer()
                                Button { revealed.toggle() } label: { Image(systemName: revealed ? "eye.slash" : "eye") }.buttonStyle(.borderless)
                                Button { copySecret(f.password) } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless)
                            }
                        }
                        if !f.totp.isEmpty { TotpRow(id: item.id) }
                    }
                    if !f.websites.isEmpty {
                        Section("Websites") {
                            ForEach(f.websites, id: \.uri) { w in
                                Button(w.uri) {
                                    if let url = URL(string: w.uri.contains("://") ? w.uri : "https://\(w.uri)") { openURL(url) }
                                }
                            }
                        }
                    }
                }
                if !f.fields.isEmpty {
                    Section("Fields") {
                        ForEach(Array(f.fields.enumerated()), id: \.offset) { _, c in
                            copyRow(c.name, c.hidden && !revealed ? String(repeating: "•", count: 8) : c.value, copy: c.value)
                        }
                    }
                }
                if !f.notes.isEmpty {
                    Section("Notes") { Text(f.notes).textSelection(.enabled) }
                }
                if !item.history.isEmpty {
                    Section("Password History") {
                        DisclosureGroup("\(item.history.count) earlier password(s)") {
                            ForEach(Array(item.history.enumerated()), id: \.offset) { _, h in
                                copyRow(Date(timeIntervalSince1970: TimeInterval(h.retired)).formatted(), h.password)
                            }
                        }
                    }
                }
                Section {
                    Text("Modified \(Date(timeIntervalSince1970: TimeInterval(item.modified)).formatted())").font(.footnote).foregroundStyle(.secondary)
                    Button("Delete", role: .destructive) { confirmDelete = true }
                }
            }
            .navigationTitle(f.name)
            .toolbar {
                Button("Edit") { editing = true }
            }
            .sheet(isPresented: $editing) {
                NavigationStack { ItemEditView(item: item) }
            }
            .confirmationDialog("Move “\(f.name)” to Recently Deleted?", isPresented: $confirmDelete, titleVisibility: .visible) {
                Button("Delete", role: .destructive) {
                    Task {
                        try? await model.change { try $0.delete(id: item.id) }
                        dismiss()
                    }
                }
            }
        } else {
            ContentUnavailableView("Item Not Found", systemImage: "questionmark")
        }
    }

    private var f: ItemFields { item?.fields ?? .empty() }

    private func copyRow(_ label: String, _ value: String, copy: String? = nil) -> some View {
        HStack {
            VStack(alignment: .leading) {
                Text(label).font(.caption).foregroundStyle(.secondary)
                Text(value).textSelection(.enabled)
            }
            Spacer()
            Button { copySecret(copy ?? value) } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless)
        }
    }
}

/// The current one-time code, ticking.
struct TotpRow: View {
    let id: String
    @State private var code: OneTimeCode?

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { ctx in
            HStack {
                VStack(alignment: .leading) {
                    Text("One-time code").font(.caption).foregroundStyle(.secondary)
                    Text(formatted).font(.title3.monospaced())
                }
                Spacer()
                if let c = code {
                    Text("\(c.remaining)s").font(.caption.monospacedDigit()).foregroundStyle(c.remaining <= 5 ? .red : .secondary)
                }
                Button { if let c = code { copySecret(c.code) } } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless)
            }
            .task(id: ctx.date) {
                code = try? await Core.shared.run { $0.totp(id: id) }
            }
        }
    }

    private var formatted: String {
        guard let c = code?.code else { return "——" }
        return c.count == 6 ? "\(c.prefix(3)) \(c.suffix(3))" : c
    }
}
