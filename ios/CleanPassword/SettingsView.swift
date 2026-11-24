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
    @AppStorage(SiteIcons.settingKey) private var siteIcons = true
    @AppStorage(Clipboard.copyCodeKey, store: Clipboard.defaults) private var copyCode = true
    @AppStorage(Clipboard.clearKey, store: Clipboard.defaults) private var clearAfter = 90
    @AppStorage(Breaches.settingKey) private var detectCompromised = true
    @AppStorage(TwoFactorDirectory.settingKey) private var checkTwoFactor = true
    @State private var importing = false
    @State private var importText: String?
    @State private var importPassword = ""
    @State private var importResult: String?
    @State private var exportDoc: JSONDoc?
    @State private var askingExport = false
    @State private var exportPassword = ""
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
                if store.pinOn {
                    Button("Turn Off PIN Unlock", role: .destructive) { Task { try? await store.setPin(nil) } }
                } else {
                    NavigationLink("Set Up PIN Unlock") { PinSetupView() }
                }
                Toggle("Detect Compromised Passwords", isOn: $detectCompromised)
                Toggle("Find Sites That Offer Two-Factor", isOn: $checkTwoFactor)
            } header: {
                Text("Security")
            } footer: {
                Text("Compromised passwords are found by checking the start of each password's hash (never the password) against Have I Been Pwned's list of leaked passwords. Sites that offer verification codes come from 2fa.directory's public list, downloaded whole.")
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
                Toggle("Copy Verification Code After Filling", isOn: $copyCode)
                Picker("Clear Clipboard After", selection: $clearAfter) {
                    Text("30 seconds").tag(30)
                    Text("90 seconds").tag(90)
                    Text("5 minutes").tag(300)
                    Text("Never").tag(0)
                }
            } header: {
                Text("AutoFill")
            } footer: {
                Text("In Settings → General → AutoFill & Passwords, turn on CleanPassword. Suggestions show user names and websites (never passwords) to iOS so it can offer them above the keyboard. Filling a login with a verification code copies its code, ready for the site's next step.")
            }
            Section {
                Label("Turn on CleanPassword in Settings → Apps → Safari → Extensions, and allow it on all websites.", systemImage: "safari")
                    .font(.footnote)
            } header: {
                Text("Safari Extension")
            } footer: {
                Text("In Safari, CleanPassword can also offer to save a login after you sign up or sign in, and fill cards and identities, from the puzzle-piece menu. It keeps its own copy of the vault: set it up there with the same S3 folder and master password.")
            }
            Section {
                Toggle("Show Website Icons", isOn: $siteIcons)
                    .onChange(of: siteIcons) { _, on in if !on { SiteIcons.clear() } }
            } footer: {
                Text("Icons are fetched from each website itself (never with your passwords) and kept on this \(ThisDevice.name).")
            }
            Section("Data") {
                Button("Import…") { importing = true }
                Button("Export…") {
                    exportPassword = ""
                    askingExport = true
                }
            }
            if let importResult {
                Section { Text(importResult).font(.footnote) }
            }
            if let error {
                Section { Text(error).foregroundStyle(.red) }
            }
            Section {
                Button("Remove Vault from This \(ThisDevice.name)…", role: .destructive) { confirmForget = true }
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
        // Every password, unencrypted: warned, and only with the master
        // password (an unlocked iPhone alone isn't enough).
        .alert("Export every password?", isPresented: $askingExport) {
            SecureField("Master password", text: $exportPassword)
            Button("Export") { Task { await export() } }
            Button("Cancel", role: .cancel) { exportPassword = "" }
        } message: {
            Text("The export holds every password unencrypted. Keep it safe, and delete it when you're done.")
        }
        .fileExporter(isPresented: Binding(get: { exportDoc != nil }, set: { if !$0 { exportDoc = nil } }), document: exportDoc, contentType: .json, defaultFilename: "cleanpassword-export.json") { _ in
            exportDoc = nil
        }
        .confirmationDialog("Remove the vault from this \(ThisDevice.name)?", isPresented: $confirmForget, titleVisibility: .visible) {
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
        let password = exportPassword
        exportPassword = ""
        do {
            let json = try await Core.shared.run { try $0.exportJson(masterPassword: password) }
            exportDoc = JSONDoc(text: json)
        } catch {
            self.error = message(error)
        }
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
                        // A new vault key comes with it.
                        await store.keyChanged()
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

/// Choosing a PIN to unlock with on this device (and in AutoFill), as
/// Bitwarden offers: quicker than the master password where Face ID isn't
/// wanted. Five wrong PINs turn it off.
struct PinSetupView: View {
    @EnvironmentObject private var store: VaultStore
    @Environment(\.dismiss) private var dismiss
    @State private var pin = ""
    @State private var again = ""
    @State private var busy = false
    @State private var error: String?

    private var valid: Bool { pin.count >= 6 && pin.allSatisfy(\.isNumber) && pin == again }

    var body: some View {
        Form {
            Section {
                SecureField("PIN", text: $pin).keyboardType(.numberPad).textContentType(.oneTimeCode)
                SecureField("PIN again", text: $again).keyboardType(.numberPad).textContentType(.oneTimeCode)
            } footer: {
                Text("At least 6 digits. The PIN unlocks CleanPassword on this \(ThisDevice.name) only; after \(PinKey.maxAttempts) wrong PINs it's turned off and your master password is needed. Someone with your unlocked phone and enough time could guess a short PIN: prefer \(BiometricKey.biometryName) where you can.")
            }
            if !again.isEmpty && pin != again {
                Section { Text("The PINs don't match.").foregroundStyle(.red) }
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
            Section {
                Button {
                    Task {
                        busy = true
                        defer { busy = false }
                        do {
                            try await store.setPin(pin)
                            dismiss()
                        } catch {
                            self.error = message(error)
                        }
                    }
                } label: {
                    HStack { Text("Turn On PIN Unlock"); Spacer(); if busy { ProgressView() } }
                }
                .disabled(!valid || busy)
            }
        }
        .navigationTitle("PIN Unlock")
        .navigationBarTitleDisplayMode(.inline)
    }
}
