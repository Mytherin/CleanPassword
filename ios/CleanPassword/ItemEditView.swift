import SwiftUI

/// Editing an item, or making a new one.
///
/// - What's typed is kept in `store.editing` as it changes: if the vault
///   locks meanwhile (switching apps to copy a setup key, with Lock After
///   set to Immediately), the editor opens again with it after unlocking.
/// - Saving applies only the fields changed here to the item as it is now,
///   so a change synced from another device while the editor was open isn't
///   undone.
struct ItemEditView: View {
    @EnvironmentObject private var store: VaultStore
    @Environment(\.dismiss) private var dismiss
    // State, set once: the view is made again whenever the store publishes
    // (the item synced from another device), and these must stay as they
    // were when editing began.
    @State private var itemId: String?
    /// The fields as they were when editing began.
    @State private var original: ItemFields
    @State private var f: ItemFields
    @State private var websites: [Site]
    @State private var custom: [Field]
    /// A card's or identity's details, by label (the item fields they're
    /// kept in).
    @State private var details: [String: String]

    struct Site: Identifiable {
        let id = UUID()
        var uri: String
        var matching: Matching = .default
    }

    struct Field: Identifiable {
        let id = UUID()
        var name: String
        var value: String
        var hidden: Bool
    }

    @State private var showPassword = false
    @State private var scanning = false
    @State private var error: String?
    @State private var busy = false
    @AppStorage("recipe") private var recipeData = Data()

    init(item: VaultItem?, draft: VaultStore.Draft? = nil) {
        _itemId = State(initialValue: draft?.itemId ?? item?.id)
        _original = State(initialValue: draft?.original ?? item?.fields ?? .empty())
        let fields = draft?.edited ?? item?.fields ?? .empty()
        _f = State(initialValue: fields)
        _websites = State(initialValue: fields.websites.isEmpty ? [Site(uri: "")] : fields.websites.map { Site(uri: $0.uri, matching: $0.matching) })
        let labels = Set(itemDetails(kind: fields.kind).map(\.label))
        _custom = State(initialValue: fields.fields.filter { !labels.contains($0.name) }.map { Field(name: $0.name, value: $0.value, hidden: $0.hidden) })
        _details = State(initialValue: Dictionary(fields.fields.filter { labels.contains($0.name) }.map { ($0.name, $0.value) }, uniquingKeysWith: { a, _ in a }))
    }

    private static let numeric: Set<String> = ["Number", "Expiry month", "Expiry year", "Security code"]

    private var kindName: String {
        switch f.kind {
        case .login: return "login"
        case .note: return "note"
        case .wifi: return "Wi-Fi network"
        case .card: return "card"
        case .identity: return "identity"
        }
    }

    var body: some View {
        Form {
            Section {
                Picker("Kind", selection: $f.kind) {
                    Text("Login").tag(Kind.login)
                    Text("Secure Note").tag(Kind.note)
                    Text("Wi-Fi Network").tag(Kind.wifi)
                    Text("Card").tag(Kind.card)
                    Text("Identity").tag(Kind.identity)
                }
                TextField(f.kind == .wifi ? "Network name" : "Name", text: $f.name)
                    .autocorrectionDisabled(f.kind == .wifi)
            } footer: {
                if f.kind != .login && original.kind == .login && hasLoginFields {
                    Text(f.kind == .wifi
                        ? "The user name, websites and verification code are removed when you save it as a Wi-Fi network."
                        : "The user name, password, websites and verification code are removed when you save it as a \(kindName).")
                }
            }
            if f.kind == .card || f.kind == .identity {
                Section(f.kind == .card ? "Card" : "Identity") {
                    ForEach(itemDetails(kind: f.kind), id: \.label) { spec in
                        TextField(spec.label, text: Binding(get: { details[spec.label] ?? "" }, set: { details[spec.label] = $0 }))
                            .keyboardType(Self.numeric.contains(spec.label) ? .numberPad : spec.label == "Email" ? .emailAddress : spec.label == "Phone" ? .phonePad : .default)
                            .textInputAutocapitalization(spec.label == "Email" ? .never : .words)
                            .autocorrectionDisabled()
                            .font(spec.hidden ? .body.monospaced() : .body)
                    }
                }
            }
            if f.kind == .login || f.kind == .wifi {
                Section {
                    if f.kind == .login {
                        HStack {
                            TextField("User name or email", text: $f.username).textContentType(.username).textInputAutocapitalization(.never).autocorrectionDisabled()
                            UsernameMenu(username: $f.username)
                        }
                    }
                    HStack {
                        Group {
                            if showPassword { TextField("Password", text: $f.password) } else { SecureField("Password", text: $f.password) }
                        }
                        .textInputAutocapitalization(.never).autocorrectionDisabled().font(.body.monospaced())
                        Button { showPassword.toggle() } label: { Image(systemName: showPassword ? "eye.slash" : "eye") }.buttonStyle(.borderless)
                            .accessibilityLabel(showPassword ? "Hide Password" : "Show Password")
                        Button {
                            f.password = generated() ?? f.password
                            showPassword = true
                        } label: { Image(systemName: "dice") }.buttonStyle(.borderless)
                            .accessibilityLabel("Generate Password")
                    }
                    if !f.password.isEmpty { StrengthMeter(password: f.password) }
                }
            }
            if f.kind == .login {
                Section {
                    ForEach($websites) { $site in
                        HStack {
                            TextField("https://example.com", text: $site.uri).keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                            Menu {
                                Picker("Match", selection: $site.matching) {
                                    ForEach(Self.matchings, id: \.0) { m in Text(m.1).tag(m.0) }
                                }
                            } label: {
                                Image(systemName: site.matching == .default ? "link" : site.matching == .never ? "link.badge.minus" : "link.badge.plus")
                            }
                            .accessibilityLabel("Matching")
                        }
                    }
                    .onDelete { websites.remove(atOffsets: $0) }
                    Button("Add Website") { websites.append(Site(uri: "")) }
                } header: {
                    Text("Websites")
                } footer: {
                    if let m = websites.first(where: { $0.matching != .default })?.matching, let name = Self.matchings.first(where: { $0.0 == m })?.1 {
                        Text("A website marked with a badge matches by “\(name)” instead of the site's domain.")
                    }
                }
                Section {
                    HStack {
                        TextField("otpauth://… or the setup key", text: $f.totp).textInputAutocapitalization(.never).autocorrectionDisabled()
                        Button { scanning = true } label: { Image(systemName: "qrcode.viewfinder") }.buttonStyle(.borderless)
                            .accessibilityLabel("Scan QR Code")
                    }
                } header: {
                    Text("Verification Code")
                } footer: {
                    if totpInvalid { Text("That isn't a valid setup key.").foregroundStyle(.red) }
                }
            }
            Section {
                ForEach($custom) { $field in
                    VStack(alignment: .leading, spacing: 6) {
                        TextField("Label", text: $field.name).font(.subheadline)
                        HStack {
                            Group {
                                if field.hidden { SecureField("Value", text: $field.value) } else { TextField("Value", text: $field.value) }
                            }
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            Button { field.hidden.toggle() } label: { Image(systemName: field.hidden ? "eye.slash" : "eye") }.buttonStyle(.borderless)
                                .accessibilityLabel(field.hidden ? "Hidden Field" : "Visible Field")
                        }
                    }
                }
                .onDelete { custom.remove(atOffsets: $0) }
                Button("Add Field") { custom.append(Field(name: "", value: "", hidden: false)) }
            } header: {
                Text("Fields")
            } footer: {
                if !custom.isEmpty { Text("Tap the eye to hide a field's value, as for a password.") }
            }
            Section {
                TextField("Folder", text: $f.folder)
                Toggle("Favorite", isOn: $f.favorite)
            }
            Section("Notes") {
                TextEditor(text: $f.notes).frame(minHeight: 90)
            }
            if let error {
                Section { Text(error).foregroundStyle(.red) }
            }
        }
        .navigationTitle(itemId == nil ? "New Item" : "Edit")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") { Task { await save() } }.disabled(busy || !canSave)
            }
        }
        .sheet(isPresented: $scanning) {
            CodeScannerView { useCode($0) }
        }
        // A code QR scanned with the Camera app while this was open.
        .onChange(of: store.editorCodeLink) { _, link in
            guard let link else { return }
            store.editorCodeLink = nil
            useCode(link)
        }
        .onAppear { keepDraft() }
        .onChange(of: f) { _, _ in keepDraft() }
        .onChange(of: websites.map(\.uri)) { _, _ in keepDraft() }
        .onChange(of: websites.map(\.matching)) { _, _ in keepDraft() }
        .onChange(of: custom.map { [$0.name, $0.value, $0.hidden ? "1" : ""] }) { _, _ in keepDraft() }
        .onChange(of: details) { _, _ in keepDraft() }
        .onDisappear {
            // Cancelled or saved: forget the draft. Locked: keep it.
            if store.phase == .unlocked { store.editing = nil }
        }
    }

    static let matchings: [(Matching, String)] = [
        (.default, "Default"), (.domain, "Base domain"), (.host, "Host"), (.startsWith, "Starts with"),
        (.exact, "Exact"), (.regex, "Regular expression"), (.never, "Never"),
    ]

    private var totpInvalid: Bool {
        let t = f.totp.trimmingCharacters(in: .whitespaces)
        return f.kind == .login && !t.isEmpty && !isValidTotp(secret: t)
    }

    private var hasLoginFields: Bool {
        !f.username.isEmpty || !f.password.isEmpty || !f.totp.isEmpty || websites.contains { !$0.uri.trimmingCharacters(in: .whitespaces).isEmpty }
    }

    private var canSave: Bool {
        let fields = composed()
        let empty = fields.name.trimmingCharacters(in: .whitespaces).isEmpty && fields.username.isEmpty && fields.password.isEmpty
            && fields.websites.isEmpty && fields.notes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && fields.fields.isEmpty
        // A network needs its name (it's what the phone joins).
        if fields.kind == .wifi && fields.name.trimmingCharacters(in: .whitespaces).isEmpty { return false }
        return !empty && !totpInvalid
    }

    /// A strong password: for the item's site, following its known rules,
    /// when the generator is on Apple's style; else in the saved style.
    private func generated() -> String? {
        let recipe = GeneratorView.savedRecipe(recipeData)
        if case .apple = recipe, let host = composed().websites.lazy.compactMap({ Self.host($0.uri) }).first {
            return generateForSite(host: host)
        }
        return try? generatePassword(recipe: recipe)
    }

    static func host(_ uri: String) -> String? {
        URL(string: uri.contains("://") ? uri : "https://\(uri)")?.host
    }

    /// The fields as typed, ready to save.
    private func composed() -> ItemFields {
        var fields = f
        fields.websites = websites.compactMap { site in
            let uri = site.uri.trimmingCharacters(in: .whitespaces)
            return uri.isEmpty ? nil : Website(uri: uri, matching: site.matching)
        }
        // A card's or identity's details first, in their order, then the
        // custom fields.
        let detailFields = itemDetails(kind: f.kind).compactMap { spec -> CustomField? in
            let value = (details[spec.label] ?? "").trimmingCharacters(in: .whitespaces)
            return value.isEmpty ? nil : CustomField(name: spec.label, value: value, hidden: spec.hidden)
        }
        fields.fields = detailFields + custom.filter { !$0.name.isEmpty || !$0.value.isEmpty }.map { CustomField(name: $0.name, value: $0.value, hidden: $0.hidden) }
        fields.totp = fields.totp.trimmingCharacters(in: .whitespaces)
        return Self.stripped(fields)
    }

    /// Without the fields the kind doesn't have: only logins have user
    /// names, websites and codes; only they and networks have passwords.
    static func stripped(_ f: ItemFields) -> ItemFields {
        var fields = f
        if fields.kind != .login {
            fields.username = ""
            fields.websites = []
            fields.totp = ""
        }
        if fields.kind != .login && fields.kind != .wifi { fields.password = "" }
        return fields
    }

    /// Sets up a scanned code; a new login takes its name and user name from
    /// it.
    private func useCode(_ code: String) {
        f.totp = code
        let label = CodeScannerView.label(of: code)
        if f.name.trimmingCharacters(in: .whitespaces).isEmpty, let issuer = label.issuer { f.name = issuer }
        if f.username.isEmpty, let account = label.account { f.username = account }
    }

    private func keepDraft() {
        store.editing = VaultStore.Draft(itemId: itemId, original: original, edited: composed())
    }

    /// Each field changed here, on top of the item as it is now.
    static func rebase(edited e: ItemFields, original o: ItemFields, onto c: ItemFields) -> ItemFields {
        func pick<T: Equatable>(_ k: KeyPath<ItemFields, T>) -> T { e[keyPath: k] != o[keyPath: k] ? e[keyPath: k] : c[keyPath: k] }
        return ItemFields(
            kind: pick(\.kind), name: pick(\.name), username: pick(\.username), password: pick(\.password),
            websites: pick(\.websites), totp: pick(\.totp), notes: pick(\.notes), folder: pick(\.folder),
            favorite: pick(\.favorite), fields: pick(\.fields))
    }

    private func save() async {
        busy = true
        defer { busy = false }
        var fields = composed()
        if let id = itemId, let current = store.items.first(where: { $0.id == id })?.fields {
            fields = Self.rebase(edited: fields, original: original, onto: current)
            // Nor fields its kind doesn't have that were synced in.
            fields = Self.stripped(fields)
        }
        do {
            _ = try await store.save(id: itemId, fields: fields)
            store.editing = nil
            dismiss()
        } catch {
            self.error = message(error)
        }
    }
}
