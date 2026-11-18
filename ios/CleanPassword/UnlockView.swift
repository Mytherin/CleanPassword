import SwiftUI

struct UnlockView: View {
    @EnvironmentObject private var store: VaultStore
    let info: LockedVault
    @State private var password = ""
    @State private var busy = false
    @State private var error: String?
    @State private var confirmForget = false
    @FocusState private var focused: Bool

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "lock.fill").font(.system(size: 44)).foregroundStyle(.tint)
            Text("CleanPassword").font(.title2.bold())
            Text("\(info.settings.bucket)/\(info.settings.prefix)").font(.footnote).foregroundStyle(.secondary)
            SecureField("Master password", text: $password)
                .textContentType(.password)
                .padding(12)
                .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 10))
                .focused($focused)
                .onSubmit { Task { await unlock() } }
            if let error {
                Text(error).foregroundStyle(.red).font(.footnote)
            }
            Button {
                Task { await unlock() }
            } label: {
                Group { if busy { ProgressView() } else { Text("Unlock") } }.frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(busy || password.isEmpty)
            if store.biometricsOn {
                Button {
                    Task { _ = await store.unlockWithBiometrics() }
                } label: {
                    Label("Use \(BiometricKey.biometryName)", systemImage: "faceid")
                }
            }
            Spacer()
            Button("Remove Vault from This iPhone…", role: .destructive) { confirmForget = true }
                .font(.footnote)
        }
        .padding(24)
        .task {
            if store.biometricsOn, await store.unlockWithBiometrics() { return }
            focused = true
        }
        .confirmationDialog("Remove the vault from this iPhone?", isPresented: $confirmForget, titleVisibility: .visible) {
            Button("Remove", role: .destructive) { store.forget() }
        } message: {
            Text("It stays in S3. Changes made here that haven't synced yet are lost.")
        }
    }

    private func unlock() async {
        busy = true
        error = nil
        defer { busy = false }
        do {
            try await store.unlock(password: password)
            password = ""
        } catch {
            self.error = message(error)
        }
    }
}
