import SwiftUI

/// The app's state: set up, locked or unlocked, the items, and syncing.
/// Everything the vault does happens in the Rust core (`Core`).
@MainActor
final class VaultStore: ObservableObject {
    enum Phase: Equatable {
        case setup
        case locked(LockedVault)
        case unlocked
    }

    @Published var phase: Phase = .setup
    @Published var items: [VaultItem] = []
    /// Recently Deleted.
    @Published var trash: [VaultItem] = []
    /// Weak and reused passwords (the Security tile).
    @Published var findings: [AuditFinding] = []
    @Published var syncing = false
    @Published var syncMessage: String?
    @Published var lastSync: Date?
    @Published var notice: String?

    /// Lock after this many seconds in the background (0: at once).
    @AppStorage("autoLockSeconds") var autoLockSeconds = 300
    private var backgroundedAt: Date?

    init() {
        refreshPhase()
    }

    var vaultId: String? {
        SavedVault.load().flatMap { lockedVault(saved: $0) }?.vaultId
    }

    func refreshPhase() {
        if let saved = SavedVault.load(), let info = lockedVault(saved: saved) {
            phase = Core.shared.isUnlocked ? .unlocked : .locked(info)
            lastSync = info.lastSync.map { Date(timeIntervalSince1970: TimeInterval($0)) }
        } else {
            phase = .setup
        }
    }

    // MARK: Setting up and unlocking

    func probe(settings: S3Settings, keys: AwsKeys) async throws -> RemoteVault? {
        try await Core.shared.detached { try fetchRemoteVault(settings: settings, keys: keys) }
    }

    func create(settings: S3Settings, keys: AwsKeys, password: String) async throws {
        let s = try await Core.shared.detached { try VaultSession.create(settings: settings, keys: keys, password: password) }
        await opened(s)
    }

    func join(settings: S3Settings, keys: AwsKeys, remote: RemoteVault, password: String) async throws {
        let s = try await Core.shared.detached { try VaultSession.join(settings: settings, keys: keys, remote: remote, password: password) }
        await opened(s)
    }

    func unlock(password: String) async throws {
        guard let saved = SavedVault.load() else { return refreshPhase() }
        let s = try await Core.shared.detached { try VaultSession.unlock(saved: saved, password: password) }
        await opened(s)
    }

    /// Unlocks with the key in the keychain, after Face ID. False if that
    /// isn't set up, or was cancelled.
    func unlockWithBiometrics() async -> Bool {
        guard let saved = SavedVault.load(), let id = vaultId else { return false }
        let key = await Core.shared.detachedValue { BiometricKey.read(vaultId: id, reason: "Unlock CleanPassword") }
        guard let key, let s = try? await Core.shared.detached({ try VaultSession.unlockWithKey(saved: saved, key: key) }) else { return false }
        await opened(s)
        return true
    }

    private func opened(_ s: VaultSession) async {
        await Core.shared.open(s)
        try? await Core.shared.persist()
        phase = .unlocked
        await reload()
        sync()
    }

    func lock() {
        Core.shared.lock()
        items = []
        refreshPhase()
    }

    /// Removes the vault from this iPhone (not from S3).
    func forget() {
        if let id = vaultId { BiometricKey.remove(vaultId: id) }
        Core.shared.lock()
        SavedVault.remove()
        SuggestionStore.clear()
        items = []
        refreshPhase()
    }

    // MARK: Items

    func reload() async {
        let all = try? await Core.shared.run { s in (s.items(), s.trash(), s.audit()) }
        items = all?.0 ?? []
        trash = all?.1 ?? []
        findings = all?.2 ?? []
        SuggestionStore.update(with: items)
    }

    /// Runs a change, saves, reloads and syncs.
    @discardableResult
    func change<T>(_ body: @escaping (VaultSession) throws -> T) async throws -> T {
        let r = try await Core.shared.run(body)
        try await Core.shared.persist()
        await reload()
        sync()
        return r
    }

    func save(id: String?, fields: ItemFields) async throws -> String {
        if let id {
            try await change { try $0.update(id: id, fields: fields) }
            return id
        }
        return try await change { try $0.add(fields: fields) }
    }

    // MARK: Syncing

    func sync() {
        guard !syncing, Core.shared.isUnlocked else { return }
        syncing = true
        Task {
            defer { syncing = false }
            do {
                let r = try await Core.shared.run { try $0.sync() }
                try await Core.shared.persist()
                lastSync = Date()
                syncMessage = r.unreadable > 0 ? "\(r.unreadable) item(s) in S3 couldn't be decrypted." : nil
                if r.passwordChangedElsewhere {
                    notice = "The master password was changed on another device. Use the new one from now on."
                }
                await reload()
            } catch {
                syncMessage = message(error)
            }
        }
    }

    // MARK: Face ID

    var biometricsOn: Bool {
        vaultId.map { BiometricKey.exists(vaultId: $0) } ?? false
    }

    func setBiometrics(_ on: Bool) async throws {
        guard let id = vaultId else { return }
        if on {
            let key = try await Core.shared.run { $0.key() }
            try BiometricKey.store(key: key, vaultId: id)
        } else {
            BiometricKey.remove(vaultId: id)
        }
        objectWillChange.send()
    }

    // MARK: Background

    func enteredBackground() {
        backgroundedAt = Date()
        if autoLockSeconds == 0 { lock() }
    }

    func enteredForeground() {
        if let t = backgroundedAt, Date().timeIntervalSince(t) >= TimeInterval(autoLockSeconds), phase == .unlocked {
            lock()
        } else if phase == .unlocked {
            sync()
        }
        backgroundedAt = nil
    }
}
