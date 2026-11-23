import SwiftUI

struct UnlockView: View {
    @EnvironmentObject private var store: VaultStore
    let info: LockedVault
    @State private var password = ""
    @State private var busy = false
    @State private var error: String?
    @State private var confirmForget = false
    @FocusState private var focused: Bool
    @Environment(\.scenePhase) private var scenePhase
    @State private var wasInBackground = false
    /// Unlocking with the PIN (when it's set up) rather than the master
    /// password.
    @State private var usePin = false

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "lock.fill").font(.system(size: 44)).foregroundStyle(.tint)
            Text("CleanPassword").font(.title2.bold())
            Text("\(info.settings.bucket)/\(info.settings.prefix)").font(.footnote).foregroundStyle(.secondary)
            if info.passwordChangedElsewhere {
                Text("The master password was changed on another device: unlock with the new one.")
                    .font(.footnote).multilineTextAlignment(.center).foregroundStyle(.orange)
            }
            SecureField(usePin ? "PIN" : "Master password", text: $password)
                .textContentType(usePin ? .oneTimeCode : .password)
                .keyboardType(usePin ? .numberPad : .default)
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
            if store.pinOn || usePin {
                Button(usePin ? "Use Master Password" : "Use PIN") {
                    usePin.toggle()
                    password = ""
                    error = nil
                    focused = true
                }
            }
            Spacer()
            Button("Remove Vault from This iPhone…", role: .destructive) { confirmForget = true }
                .font(.footnote)
        }
        .padding(24)
        .task { await offerBiometrics() }
        // Locked on leaving the app (Lock After: Immediately), this screen
        // appears while the app is in the background, where Face ID can't
        // run: offer it on coming back. Only after the background, not
        // after Face ID's own prompt (which makes the app inactive too).
        .onChange(of: scenePhase) { _, p in
            if p == .background { wasInBackground = true }
            if p == .active && wasInBackground {
                wasInBackground = false
                Task { await offerBiometrics() }
            }
        }
        .confirmationDialog("Remove the vault from this iPhone?", isPresented: $confirmForget, titleVisibility: .visible) {
            Button("Remove", role: .destructive) { store.forget() }
        } message: {
            Text("It stays in S3. Changes made here that haven't synced yet are lost.")
        }
    }

    private func offerBiometrics() async {
        guard scenePhase == .active else {
            wasInBackground = true
            return
        }
        guard !busy else { return }
        if store.offerBiometrics, store.biometricsOn {
            busy = true
            let unlocked = await store.unlockWithBiometrics()
            busy = false
            if unlocked { return }
        }
        focused = true
    }

    private func unlock() async {
        busy = true
        error = nil
        defer { busy = false }
        if usePin {
            error = await store.unlockWithPin(password)
            password = ""
            // Too many wrong PINs: back to the master password.
            if error != nil && !store.pinOn { usePin = false }
            return
        }
        do {
            try await store.unlock(password: password)
            password = ""
        } catch {
            self.error = message(error)
        }
    }
}
