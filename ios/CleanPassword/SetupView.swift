import SwiftUI

/// Connecting to an S3 bucket: a new vault, or the one already there.
struct SetupView: View {
    @EnvironmentObject private var store: VaultStore
    @State private var bucket = ""
    @State private var region = "us-east-1"
    @State private var prefix = "CleanPassword"
    @State private var endpoint = ""
    @State private var keyId = ""
    @State private var secret = ""
    @State private var busy = false
    @State private var error: String?
    @State private var found: Found?

    struct Found: Hashable {
        var settings: S3Settings
        var keys: AwsKeys
        var remote: RemoteVault?
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Your passwords live in an S3 bucket of your own, encrypted on this \(ThisDevice.name) with your master password before they leave it.")
                        .font(.callout).foregroundStyle(.secondary)
                }
                Section("Bucket") {
                    TextField("Bucket name", text: $bucket).textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("Region", text: $region).textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("Folder", text: $prefix).textInputAutocapitalization(.never).autocorrectionDisabled()
                }
                Section {
                    TextField("Access key ID", text: $keyId).textInputAutocapitalization(.characters).autocorrectionDisabled()
                    SecureField("Secret access key", text: $secret)
                } header: {
                    Text("IAM access key")
                } footer: {
                    Text("Use an IAM user that can only list, read and write this bucket (see the README).")
                }
                Section {
                    TextField("https://… (R2, MinIO, …)", text: $endpoint).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                } header: {
                    Text("S3-compatible service")
                } footer: {
                    Text("Leave empty for Amazon S3.")
                }
                if let error {
                    Section { Text(error).foregroundStyle(.red) }
                }
                Section {
                    Button {
                        Task { await go() }
                    } label: {
                        HStack { Text("Continue"); Spacer(); if busy { ProgressView() } }
                    }
                    .disabled(busy || bucket.isEmpty || keyId.isEmpty || secret.isEmpty)
                }
            }
            .navigationTitle("CleanPassword")
            .navigationDestination(item: $found) { f in
                MasterPasswordView(found: f)
            }
        }
    }

    private func go() async {
        busy = true
        error = nil
        defer { busy = false }
        let settings = S3Settings(bucket: bucket.trimmingCharacters(in: .whitespaces), region: region.trimmingCharacters(in: .whitespaces), prefix: prefix.trimmingCharacters(in: .whitespaces), endpoint: endpoint.isEmpty ? nil : endpoint)
        let keys = AwsKeys(accessKeyId: keyId.trimmingCharacters(in: .whitespaces), secretAccessKey: secret.trimmingCharacters(in: .whitespaces), sessionToken: nil)
        do {
            let remote = try await store.probe(settings: settings, keys: keys)
            found = Found(settings: settings, keys: keys, remote: remote)
        } catch {
            self.error = message(error)
        }
    }
}

/// A new master password, or the existing vault's.
struct MasterPasswordView: View {
    @EnvironmentObject private var store: VaultStore
    let found: SetupView.Found
    @State private var password = ""
    @State private var again = ""
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        Form {
            Section {
                if found.remote != nil {
                    Text("There's a vault in \(found.settings.bucket)/\(found.settings.prefix). Enter its master password.")
                } else {
                    Text("Choose a master password: at least 10 characters, ideally a few unrelated words. It can't be recovered if you forget it.")
                }
            }
            .font(.callout).foregroundStyle(.secondary)
            Section {
                SecureField("Master password", text: $password).textContentType(found.remote == nil ? .newPassword : .password)
                if found.remote == nil {
                    SecureField("Confirm", text: $again).textContentType(.newPassword)
                    StrengthMeter(password: password)
                }
            }
            if let error {
                Section { Text(error).foregroundStyle(.red) }
            }
            Section {
                Button {
                    Task { await go() }
                } label: {
                    HStack { Text(found.remote == nil ? "Create Vault" : "Unlock"); Spacer(); if busy { ProgressView() } }
                }
                .disabled(busy || password.isEmpty)
            }
        }
        .navigationTitle(found.remote == nil ? "New Vault" : "Unlock Vault")
    }

    private func go() async {
        busy = true
        error = nil
        defer { busy = false }
        do {
            if let remote = found.remote {
                try await store.join(settings: found.settings, keys: found.keys, remote: remote, password: password)
            } else {
                guard password == again else { error = "The passwords don't match."; return }
                try await store.create(settings: found.settings, keys: found.keys, password: password)
            }
        } catch {
            self.error = message(error)
        }
    }
}

struct StrengthMeter: View {
    let password: String

    var body: some View {
        let s = passwordStrength(password: password)
        let colors: [Color] = [.red, .orange, .yellow, .green, .green]
        let words = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
        VStack(alignment: .leading, spacing: 4) {
            GeometryReader { g in
                ZStack(alignment: .leading) {
                    Capsule().fill(Color(.systemFill))
                    Capsule().fill(colors[Int(s.score)]).frame(width: g.size.width * CGFloat(Int(s.score) + 1) / 5)
                }
            }
            .frame(height: 4)
            if !password.isEmpty {
                Text(words[Int(s.score)]).font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}
