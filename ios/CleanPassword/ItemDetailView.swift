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
    /// Hidden fields and earlier passwords shown, each on its own.
    @State private var revealedFields: Set<Int> = []
    @State private var revealedOld: Set<Int> = []
    @State private var failure: String?
    @State private var editing = false
    @State private var scanning = false
    @State private var confirmDelete = false
    @State private var copied: String?
    @State private var deletingPasskey: PasskeyInfo?

    /// Face ID passed for an item that asks for it (on this screen).
    @State private var verified = false

    private var item: VaultItem? { store.items.first { $0.id == id } }

    var body: some View {
        if let item {
            if item.fields.reprompt && !verified {
                locked(item)
            } else {
                content(item)
            }
        } else {
            ContentUnavailableView("Password Not Found", systemImage: "key")
        }
    }

    /// An item that asks for Face ID before showing anything of it.
    private func locked(_ item: VaultItem) -> some View {
        ContentUnavailableView {
            Label(item.fields.name, systemImage: "lock.fill")
        } description: {
            Text("This item asks for \(BiometricKey.biometryName) before it's shown.")
        } actions: {
            Button("Show") { Task { await verify(item) } }.buttonStyle(.borderedProminent)
        }
        .task { await verify(item) }
    }

    private func verify(_ item: VaultItem) async {
        if await Reprompt.allow(item) { verified = true }
    }

    private func content(_ item: VaultItem) -> some View {
        let f = item.fields
        return List {
            Section {
                VStack(spacing: 8) {
                    SiteIcon(name: f.name, host: item.host, size: 64)
                    Text(f.name).font(.title2.bold()).multilineTextAlignment(.center)
                    Text("Modified \(Date(timeIntervalSince1970: TimeInterval(item.modified)).formatted(date: .abbreviated, time: .shortened))")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .listRowBackground(Color.clear)
            }
            if f.kind == .wifi {
                Section {
                    copyRow("Network", f.name, key: "network")
                    if !f.password.isEmpty { passwordRow(f.password) }
                }
                Section {
                    if let qr = WifiQR.image(network: f.name, password: f.password) {
                        Image(uiImage: qr)
                            .interpolation(.none)
                            .resizable()
                            .scaledToFit()
                            .frame(maxWidth: 220)
                            .padding(12)
                            .background(Color.white, in: RoundedRectangle(cornerRadius: 12))
                            .frame(maxWidth: .infinity)
                            .accessibilityLabel("QR code to join \(f.name)")
                    }
                } header: {
                    Text("Join This Network")
                } footer: {
                    Text("Point another phone's camera at this code to join \(f.name).")
                }
            }
            if f.kind == .login {
                Section {
                    if !f.username.isEmpty { copyRow("User Name", f.username, key: "user") }
                    if !f.password.isEmpty { passwordRow(f.password) }
                    if !f.totp.isEmpty { TotpRow(secret: f.totp) }
                }
                if f.totp.isEmpty {
                    Section {
                        Button { scanning = true } label: { Label("Set Up Verification Code…", systemImage: "qrcode.viewfinder") }
                    } footer: {
                        Text("Scan the QR code the site shows when you turn on two-factor authentication, and CleanPassword fills in its codes.")
                    }
                }
                if !f.websites.isEmpty {
                    Section("Websites") {
                        ForEach(Array(f.websites.enumerated()), id: \.offset) { _, w in
                            let url = URL(string: w.uri.contains("://") ? w.uri : "https://\(w.uri)")
                            Button(w.uri) {
                                if let url { openURL(url) }
                            }
                            .contextMenu {
                                if let url {
                                    Button { openURL(url) } label: { Label("Open Website", systemImage: "safari") }
                                }
                                Button { UIPasteboard.general.string = w.uri } label: { Label("Copy Website", systemImage: "doc.on.doc") }
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
                    Text("Signs you in to \(item.passkeys[0].rpId) with \(BiometricKey.biometryName) instead of a password.")
                }
            }
            if !f.fields.isEmpty {
                Section(Self.detailsTitle(f.kind) ?? "Fields") {
                    ForEach(Array(f.fields.enumerated()), id: \.offset) { n, c in
                        if c.hidden {
                            secretRow(c.name, c.value, shown: revealedFields.contains(n), key: "field\(n)", mono: false) { revealedFields.formSymmetricDifference([n]) }
                        } else {
                            copyRow(c.name, c.value, key: "field\(n)")
                        }
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
                            secretRow(Date(timeIntervalSince1970: TimeInterval(h.retired)).formatted(date: .abbreviated, time: .omitted), h.password,
                                      shown: revealedOld.contains(n), key: "old\(n)", mono: true) { revealedOld.formSymmetricDifference([n]) }
                        }
                    }
                }
            }
            Section {
                Button(Self.deleteTitle(f.kind), role: .destructive) { confirmDelete = true }
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
        .sheet(isPresented: $scanning) {
            CodeScannerView { code in
                Task {
                    do {
                        try await store.change { s in
                            guard var fields = s.get(id: item.id)?.fields else { return }
                            fields.totp = code
                            _ = try s.update(id: item.id, fields: fields)
                        }
                    } catch {
                        failure = message(error)
                    }
                }
            }
        }
        .confirmationDialog("Delete this passkey?", isPresented: Binding(get: { deletingPasskey != nil }, set: { if !$0 { deletingPasskey = nil } }), titleVisibility: .visible) {
            Button("Delete Passkey", role: .destructive) {
                if let p = deletingPasskey {
                    Task {
                        do { try await store.change { try $0.deletePasskey(itemId: item.id, id: p.id) } } catch { failure = message(error) }
                    }
                }
                deletingPasskey = nil
            }
        } message: {
            Text("You won't be able to sign in to \(deletingPasskey?.rpId ?? "the site") with it any more. Remove it on the site too.")
        }
        .confirmationDialog("Move “\(f.name)” to Deleted?", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("Delete", role: .destructive) {
                Task {
                    do {
                        try await store.change { try $0.delete(id: item.id) }
                        dismiss()
                    } catch {
                        failure = message(error)
                    }
                }
            }
        } message: {
            Text("You can recover it from Deleted for 30 days.")
        }
        .alert("CleanPassword", isPresented: Binding(get: { failure != nil }, set: { if !$0 { failure = nil } })) {
            Button("OK") { failure = nil }
        } message: {
            Text(failure ?? "")
        }
    }

    /// A secret shown as dots until tapped (a hidden field, an earlier
    /// password), with its copy button.
    private func secretRow(_ label: String, _ value: String, shown: Bool, key: String, mono: Bool, toggle: @escaping () -> Void) -> some View {
        Button(action: toggle) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(label).font(.caption).foregroundStyle(.secondary)
                    Text(shown ? value : String(repeating: "•", count: 8))
                        .font(mono ? .body.monospaced() : .body).foregroundStyle(.primary)
                }
                Spacer()
                copyButton(value, key: key)
            }
        }
        .contextMenu {
            Button { copySecret(value) } label: { Label("Copy \(label)", systemImage: "doc.on.doc") }
            Button(action: toggle) { Label(shown ? "Hide" : "Show", systemImage: shown ? "eye.slash" : "eye") }
        }
    }

    static func deleteTitle(_ kind: Kind) -> String {
        switch kind {
        case .login: return "Delete Password"
        case .note: return "Delete Note"
        case .wifi: return "Delete Network"
        case .card: return "Delete Card"
        case .identity: return "Delete Identity"
        case .sshKey: return "Delete SSH Key"
        }
    }

    /// The heading of a kind's details (and its fields); `nil` for kinds
    /// without details.
    static func detailsTitle(_ kind: Kind) -> String? {
        switch kind {
        case .card: return "Card"
        case .identity: return "Identity"
        case .sshKey: return "SSH Key"
        case .login, .note, .wifi: return nil
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
                Text(value).font(mono ? .body.monospaced() : .body)
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
