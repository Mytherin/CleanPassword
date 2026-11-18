import SwiftUI

struct ItemEditView: View {
    @EnvironmentObject private var store: VaultStore
    @Environment(\.dismiss) private var dismiss
    let item: VaultItem?
    @State private var f: ItemFields
    @State private var websites: [Site]

    struct Site: Identifiable {
        let id = UUID()
        var uri: String
    }
    @State private var showPassword = false
    @State private var error: String?
    @State private var busy = false
    @AppStorage("recipe") private var recipeData = Data()

    init(item: VaultItem?) {
        self.item = item
        let fields = item?.fields ?? .empty()
        _f = State(initialValue: fields)
        _websites = State(initialValue: fields.websites.isEmpty ? [Site(uri: "")] : fields.websites.map { Site(uri: $0.uri) })
    }

    var body: some View {
        Form {
            Section {
                Picker("Kind", selection: $f.kind) {
                    Text("Login").tag(Kind.login)
                    Text("Secure Note").tag(Kind.note)
                }
                TextField("Name", text: $f.name)
            }
            if f.kind == .login {
                Section {
                    TextField("User name or email", text: $f.username).textContentType(.username).textInputAutocapitalization(.never).autocorrectionDisabled()
                    HStack {
                        Group {
                            if showPassword { TextField("Password", text: $f.password) } else { SecureField("Password", text: $f.password) }
                        }
                        .textInputAutocapitalization(.never).autocorrectionDisabled().font(.body.monospaced())
                        Button { showPassword.toggle() } label: { Image(systemName: showPassword ? "eye.slash" : "eye") }.buttonStyle(.borderless)
                        Button {
                            f.password = (try? generatePassword(recipe: GeneratorView.savedRecipe(recipeData))) ?? f.password
                            showPassword = true
                        } label: { Image(systemName: "dice") }.buttonStyle(.borderless)
                    }
                    if !f.password.isEmpty { StrengthMeter(password: f.password) }
                }
                Section("Websites") {
                    ForEach($websites) { $site in
                        TextField("https://example.com", text: $site.uri).keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                    }
                    .onDelete { websites.remove(atOffsets: $0) }
                    Button("Add Website") { websites.append(Site(uri: "")) }
                }
                Section {
                    TextField("otpauth://… or the secret", text: $f.totp).textInputAutocapitalization(.never).autocorrectionDisabled()
                } header: {
                    Text("One-time code (TOTP)")
                } footer: {
                    if !f.totp.isEmpty && !isValidTotp(secret: f.totp) { Text("That isn't a valid TOTP secret.").foregroundStyle(.red) }
                }
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
        .navigationTitle(item == nil ? "New Item" : "Edit")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") { Task { await save() } }.disabled(busy)
            }
        }
    }

    private func save() async {
        busy = true
        defer { busy = false }
        var fields = f
        let previous = Dictionary(f.websites.map { ($0.uri, $0.matching) }, uniquingKeysWith: { a, _ in a })
        fields.websites = websites.map { $0.uri.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }.map { Website(uri: $0, matching: previous[$0] ?? .default) }
        do {
            _ = try await store.save(id: item?.id, fields: fields)
            dismiss()
        } catch {
            self.error = message(error)
        }
    }
}
