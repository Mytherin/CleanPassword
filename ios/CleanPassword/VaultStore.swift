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
    /// Logins that are copies of another for the same site (saved once per
    /// host by a browser), to merge.
    @Published var duplicates: UInt64 = 0
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
        if let d = lockedDraft {
            lockedDraft = nil
            reopenDraft = d
        }
        sync()
    }

    // MARK: Drafts

    /// An editor's unsaved work.
    struct Draft: Identifiable {
        let id = UUID()
        var itemId: String?
        var original: ItemFields
        var edited: ItemFields
    }

    /// What the open editor holds, as it's typed (not published: it changes
    /// with every key).
    var editing: Draft?
    /// The editor that was open when the vault locked, until it's unlocked.
    private var lockedDraft: Draft?
    /// That editor, to open again now that the vault is unlocked.
    @Published var reopenDraft: Draft?

    /// An `otpauth://` link opened in the app, to set up on a login (once
    /// unlocked).
    struct CodeLink: Identifiable {
        let id = UUID()
        let link: String
    }
    @Published var codeLink: CodeLink?

    func open(url: URL) {
        let text = url.absoluteString
        guard url.scheme?.lowercased() == "otpauth" else { return }
        guard isValidTotp(secret: text) else {
            notice = "That verification code link isn't valid."
            return
        }
        codeLink = CodeLink(link: text)
    }

    /// Whether the unlock screen starts Face ID by itself. Not right after
    /// Lock Now: the user is looking at the phone, so it would unlock again.
    private(set) var offerBiometrics = true

    /// Locks, and forgets what was shown (passwords included); an open
    /// editor's work is kept to reopen after unlocking.
    func lock(manually: Bool = false) {
        offerBiometrics = !manually
        if let d = editing { lockedDraft = d }
        editing = nil
        Core.shared.lock()
        items = []
        trash = []
        findings = []
        refreshPhase()
    }

    /// Removes the vault from this iPhone (not from S3).
    func forget() {
        editing = nil
        lockedDraft = nil
        reopenDraft = nil
        if let id = vaultId { BiometricKey.remove(vaultId: id) }
        Core.shared.lock()
        SavedVault.remove()
        SuggestionStore.clear()
        items = []
        trash = []
        findings = []
        refreshPhase()
    }

    // MARK: Items

    func reload() async {
        // Locked meanwhile (lock() already cleared what was shown): leave
        // the suggestions above the keyboard as they are.
        guard let all = try? await Core.shared.run({ s in (s.items(), s.trash(), s.audit(), s.duplicates()) }) else { return }
        (items, trash, findings, duplicates) = all
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

    /// A change made while a sync was running, to upload when it's done.
    private var syncAgain = false

    func sync() {
        guard Core.shared.isUnlocked else { return }
        guard !syncing else {
            syncAgain = true
            return
        }
        syncing = true
        syncAgain = false
        Task {
            defer {
                syncing = false
                if syncAgain { sync() }
            }
            do {
                let r = try await Core.shared.run { try $0.sync() }
                try await Core.shared.persist()
                lastSync = Date()
                syncMessage = nil
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
            Task {
                // The AutoFill extension may have saved a passkey meanwhile.
                if await Core.shared.reloadIfChangedOnDisk() { await reload() }
                sync()
            }
        }
        backgroundedAt = nil
    }
}
