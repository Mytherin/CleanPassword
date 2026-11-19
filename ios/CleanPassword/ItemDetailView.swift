import SwiftUI

/// A password, as in Apple's Passwords app: its icon, name and when it was
/// modified on top; then user name, password (dots until tapped) and
/// verification code, each copied from its menu or button; websites,
/// fields, notes and earlier passwords below. Edit opens the editor.
struct ItemDetailView: View {
    @EnvironmentObject private var store: VaultStore
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    let id: String

    @State private var revealed = false
    @State private var editing = false
    @State private var confirmDelete = false
    @State private var copied: String?
    @State private var deletingPasskey: PasskeyInfo?

    private var item: VaultItem? { store.items.first { $0.id == id } }

    var body: some View {
        if let item {
            content(item)
        } else {
            ContentUnavailableView("Password Not Found", systemImage: "key")
        }
    }

    private func content(_ item: VaultItem) -> some View {
        let f = item.fields
        return List {
            Section {
                VStack(spacing: 8) {
                    Monogram(name: f.name, size: 64)
                    Text(f.name).font(.title2.bold()).multilineTextAlignment(.center)
                    Text("Modified \(Date(timeIntervalSince1970: TimeInterval(item.modified)).formatted(date: .abbreviated, time: .shortened))")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .listRowBackground(Color.clear)
            }
            if f.kind == .login {
                Section {
                    if !f.username.isEmpty { copyRow("User Name", f.username, key: "user") }
                    if !f.password.isEmpty { passwordRow(f.password) }
                    if !f.totp.isEmpty { TotpRow(secret: f.totp) }
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
            if !item.passkeys.isEmpty {
                Section {
                    ForEach(item.passkeys, id: \.id) { p in
                        HStack(spacing: 12) {
                            Image(systemName: "person.badge.key.fill").foregroundStyle(.tint)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(p.userName.isEmpty ? p.rpId : p.userName)
                                Text("\(p.rpId) · created \(Date(timeIntervalSince1970: TimeInterval(p.created)).formatted(date: .abbreviated, time: .omitted))")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        .swipeActions {
                            Button("Delete", role: .destructive) { deletingPasskey = p }
                        }
                        .contextMenu {
                            Button(role: .destructive) { deletingPasskey = p } label: { Label("Delete Passkey", systemImage: "trash") }
                        }
                    }
                } header: {
                    Text("Passkeys")
                } footer: {
                    Text("Signs you in to \(item.passkeys[0].rpId) with Face ID instead of a password.")
                }
            }
            if !f.fields.isEmpty {
                Section("Fields") {
                    ForEach(Array(f.fields.enumerated()), id: \.offset) { n, c in
                        copyRow(c.name, c.hidden && !revealed ? String(repeating: "•", count: 8) : c.value, key: "field\(n)", copy: c.value)
                    }
                }
            }
            if !f.notes.isEmpty {
                Section("Notes") { Text(f.notes).textSelection(.enabled) }
            }
            if !item.history.isEmpty {
                Section {
                    DisclosureGroup("Earlier Passwords (\(item.history.count))") {
                        ForEach(Array(item.history.enumerated()), id: \.offset) { n, h in
                            copyRow(Date(timeIntervalSince1970: TimeInterval(h.retired)).formatted(date: .abbreviated, time: .omitted), h.password, key: "old\(n)", mono: true)
                        }
                    }
                }
            }
            Section {
                Button(f.kind == .note ? "Delete Note" : "Delete Password", role: .destructive) { confirmDelete = true }
            }
        }
        .listStyle(.insetGrouped)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            Button("Edit") { editing = true }
        }
        .sheet(isPresented: $editing) {
            NavigationStack { ItemEditView(item: item) }
        }
        .confirmationDialog("Delete this passkey?", isPresented: Binding(get: { deletingPasskey != nil }, set: { if !$0 { deletingPasskey = nil } }), titleVisibility: .visible) {
            Button("Delete Passkey", role: .destructive) {
                if let p = deletingPasskey {
                    Task { try? await store.change { try $0.deletePasskey(itemId: item.id, id: p.id) } }
                }
                deletingPasskey = nil
            }
        } message: {
            Text("You won't be able to sign in to \(deletingPasskey?.rpId ?? "the site") with it any more. Remove it on the site too.")
        }
        .confirmationDialog("Move “\(f.name)” to Deleted?", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("Delete", role: .destructive) {
                Task {
                    try? await store.change { try $0.delete(id: item.id) }
                    dismiss()
                }
            }
        } message: {
            Text("You can recover it from Deleted for 30 days.")
        }
    }

    private func passwordRow(_ password: String) -> some View {
        Button {
            revealed.toggle()
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Password").font(.caption).foregroundStyle(.secondary)
                    Text(revealed ? password : String(repeating: "•", count: 12))
                        .font(.body.monospaced()).foregroundStyle(.primary)
                }
                Spacer()
                copyButton(password, key: "password")
            }
        }
        .contextMenu {
            Button { copySecret(password) } label: { Label("Copy Password", systemImage: "doc.on.doc") }
            Button { revealed.toggle() } label: { Label(revealed ? "Hide Password" : "Show Password", systemImage: revealed ? "eye.slash" : "eye") }
        }
    }

    private func copyRow(_ label: String, _ value: String, key: String, copy: String? = nil, mono: Bool = false) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(label).font(.caption).foregroundStyle(.secondary)
                Text(value).font(mono ? .body.monospaced() : .body).textSelection(.enabled)
            }
            Spacer()
            copyButton(copy ?? value, key: key)
        }
        .contextMenu {
            Button { copySecret(copy ?? value) } label: { Label("Copy \(label)", systemImage: "doc.on.doc") }
        }
    }

    private func copyButton(_ value: String, key: String) -> some View {
        Button {
            copySecret(value)
            copied = key
            Task {
                try? await Task.sleep(for: .seconds(1.5))
                if copied == key { copied = nil }
            }
        } label: {
            Image(systemName: copied == key ? "checkmark" : "doc.on.doc")
        }
        .buttonStyle(.borderless)
    }
}

/// The current verification code, ticking down.
struct TotpRow: View {
    let secret: String

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            let code = try? oneTimeCode(secret: secret)
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Verification Code").font(.caption).foregroundStyle(.secondary)
                    Text(code.map { $0.code.count == 6 ? "\($0.code.prefix(3)) \($0.code.suffix(3))" : $0.code } ?? "Invalid setup key")
                        .font(.title3.monospacedDigit())
                }
                Spacer()
                if let code {
                    CountdownRing(remaining: code.remaining, period: code.period)
                    Button { copySecret(code.code) } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless)
                }
            }
        }
    }
}
