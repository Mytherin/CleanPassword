import AuthenticationServices
import SwiftUI
import UniformTypeIdentifiers

struct SettingsView: View {
    @EnvironmentObject private var store: VaultStore
    @Environment(\.dismiss) private var dismiss
    @State private var settings: S3Settings?
    @State private var accessKeyId = ""
    @State private var biometrics = false
    @State private var suggestions = SuggestionStore.enabled
    @State private var importing = false
    @State private var importText: String?
    @State private var importPassword = ""
    @State private var importResult: String?
    @State private var exportDoc: JSONDoc?
    @State private var confirmForget = false
    @State private var error: String?

    var body: some View {
        Form {
            Section("Vault") {
                if let s = settings {
                    LabeledContent("Bucket", value: s.bucket)
                    LabeledContent("Folder", value: s.prefix)
                    LabeledContent("Region", value: s.region)
                    if let e = s.endpoint { LabeledContent("Endpoint", value: e) }
                }
                NavigationLink("Access Key") { KeysView(accessKeyId: accessKeyId) }
                Button("Sync Now") { store.sync() }
            }
            Section {
                if BiometricKey.isAvailable {
                    Toggle("Unlock with \(BiometricKey.biometryName)", isOn: $biometrics)
                        .onChange(of: biometrics) { _, on in
                            // Also called when the screen sets the toggle to
                            // what's already so: then there's nothing to do
                            // (storing the key again would re-arm it without
                            // Face ID, even after the enrolled faces changed).
                            guard on != store.biometricsOn else { return }
                            Task {
                                do { try await store.setBiometrics(on) } catch { self.error = message(error); biometrics = store.biometricsOn }
                            }
                        }
                }
                Picker("Lock After", selection: $store.autoLockSeconds) {
                    Text("Immediately").tag(0)
                    Text("1 minute").tag(60)
                    Text("5 minutes").tag(300)
                    Text("15 minutes").tag(900)
                    Text("1 hour").tag(3600)
                }
                NavigationLink("Change Master Password") { ChangePasswordView() }
            } header: {
                Text("Security")
            }
            Section {
                Button("Turn On AutoFill…") {
                    Task { try? await ASSettingsHelper.openCredentialProviderAppSettings() }
                }
                Toggle("Suggestions Above the Keyboard", isOn: $suggestions)
                    .onChange(of: suggestions) { _, on in
                        SuggestionStore.setEnabled(on)
                        if on { SuggestionStore.update(with: store.items) } else { SuggestionStore.clear() }
                    }
            } header: {
                Text("AutoFill")
            } footer: {
                Text("In Settings → General → AutoFill & Passwords, turn on CleanPassword. Suggestions show user names and websites (never passwords) to iOS so it can offer them above the keyboard.")
            }
            Section("Data") {
                Button("Import…") { importing = true }
                Button("Export…") { Task { await export() } }
            }
            if let importResult {
                Section { Text(importResult).font(.footnote) }
            }
            if let error {
                Section { Text(error).foregroundStyle(.red) }
            }
            Section {
                Button("Remove Vault from This iPhone…", role: .destructive) { confirmForget = true }
            }
        }
        .navigationTitle("Settings")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { Button("Done") { dismiss() } }
        .task {
            settings = try? await Core.shared.run { $0.settings() }
            accessKeyId = (try? await Core.shared.run { $0.accessKeyId() }) ?? ""
            biometrics = store.biometricsOn
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.json, .commaSeparatedText, .plainText]) { result in
            guard case let .success(url) = result else { return }
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { error = "Couldn't read that file."; return }
            if importNeedsPassword(text: text) {
                importText = text
            } else {
                Task { await runImport(text, password: nil) }
            }
        }
        .alert("Password-protected export", isPresented: Binding(get: { importText != nil }, set: { if !$0 { importText = nil } })) {
            SecureField("Export password", text: $importPassword)
            Button("Import") {
                let text = importText ?? ""
                importText = nil
                Task { await runImport(text, password: importPassword) }
            }
            Button("Cancel", role: .cancel) { importText = nil }
        } message: {
            Text("Enter the password the export was protected with.")
        }
        .fileExporter(isPresented: Binding(get: { exportDoc != nil }, set: { if !$0 { exportDoc = nil } }), document: exportDoc, contentType: .json, defaultFilename: "cleanpassword-export.json") { _ in
            exportDoc = nil
        }
        .confirmationDialog("Remove the vault from this iPhone?", isPresented: $confirmForget, titleVisibility: .visible) {
            Button("Remove", role: .destructive) {
                dismiss()
                store.forget()
            }
        } message: {
            Text("It stays in S3. Changes made here that haven't synced yet are lost.")
        }
    }

    private func runImport(_ text: String, password: String?) async {
        do {
            let r = try await store.change { try $0.importFile(text: text, password: password) }
            importPassword = ""
            importResult = (["Imported \(r.added) item(s)" + (r.merged > 0 ? "; \(r.merged) merged into a login for the same site" : "") + (r.skipped > 0 ? "; \(r.skipped) were already here." : ".") + (r.passkeys > 0 ? " \(r.passkeys) passkey(s) added." : "")] + r.warnings).joined(separator: "\n\n")
        } catch {
            self.error = message(error)
        }
    }

    private func export() async {
        guard let json = try? await Core.shared.run({ $0.exportJson() }) else { return }
        exportDoc = JSONDoc(text: json)
    }
}

/// An export file (unencrypted: the user is warned).
struct JSONDoc: FileDocument {
    static var readableContentTypes: [UTType] { [.json] }
    var text: String

    init(text: String) { self.text = text }

    init(configuration: ReadConfiguration) throws {
        text = String(data: configuration.file.regularFileContents ?? Data(), encoding: .utf8) ?? ""
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: Data(text.utf8))
    }
}

struct KeysView: View {
    @EnvironmentObject private var store: VaultStore
    @Environment(\.dismiss) private var dismiss
    let accessKeyId: String
    @State private var keyId = ""
    @State private var secret = ""
    @State private var error: String?

    var body: some View {
        Form {
            Section {
                LabeledContent("Current", value: accessKeyId)
            }
            Section("New access key") {
                TextField("Access key ID", text: $keyId).textInputAutocapitalization(.characters).autocorrectionDisabled()
                SecureField("Secret access key", text: $secret)
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
            Button("Save") {
                Task {
                    do {
                        let keys = AwsKeys(accessKeyId: keyId.trimmingCharacters(in: .whitespaces), secretAccessKey: secret.trimmingCharacters(in: .whitespaces), sessionToken: nil)
                        try await store.change { try $0.setKeys(keys: keys) }
                        dismiss()
                    } catch {
                        self.error = message(error)
                    }
                }
            }
            .disabled(keyId.isEmpty || secret.isEmpty)
        }
        .navigationTitle("Access Key")
    }
}

struct ChangePasswordView: View {
    @EnvironmentObject private var store: VaultStore
    @Environment(\.dismiss) private var dismiss
    @State private var current = ""
    @State private var new = ""
    @State private var again = ""
    @State private var error: String?

    var body: some View {
        Form {
            Section {
                SecureField("Current master password", text: $current).textContentType(.password)
            }
            Section {
                SecureField("New master password", text: $new).textContentType(.newPassword)
                SecureField("Confirm", text: $again).textContentType(.newPassword)
                StrengthMeter(password: new)
            } footer: {
                Text("Other devices need the new password from their next sync on.")
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
            Button("Change") {
                Task {
                    guard new == again else { error = "The new passwords don't match."; return }
                    do {
                        let (c, n) = (current, new)
                        try await store.change { try $0.changeMasterPassword(current: c, newPassword: n) }
                        dismiss()
                    } catch {
                        self.error = message(error)
                    }
                }
            }
            .disabled(current.isEmpty || new.isEmpty)
        }
        .navigationTitle("Master Password")
    }
}
